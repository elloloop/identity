// Package conformance is a driver-agnostic test suite for
// service.Repository implementations.
//
// The aim is to give every Repository driver — entdb, postgres,
// memory — a single source of truth for "does this driver honour the
// contract the service layer relies on?". A new driver runs:
//
//	conformance.RunConformance(t, conformance.Driver{
//	    Name:    "mydriver",
//	    NewRepo: func(t *testing.T) service.Repository { return mydriver.New(...) },
//	})
//
// and either passes the suite or fails loudly with the precise
// semantic that broke. Same test bodies, same assertions — only the
// backend varies. The driver name is included in every subtest path
// so a failure like `TestConformance/postgres/UserCRUD` is
// immediately attributable.
//
// Subtests are intentionally narrow: each one exercises ONE
// Repository semantic, named after the methods it covers, so a
// failure points at one method (or one method pair). The goal is
// breadth of coverage, not exhaustive concurrency edge-cases — those
// belong in driver-specific unit tests.
//
// The suite is backend-agnostic: every subtest that touches a
// user-scoped row creates its User via CreateUser first. Drivers that
// enforce foreign-key constraints (Postgres) pass without any test-
// seam shim, and drivers that don't enforce FKs (memory, EntDB) still
// exercise the same code path.
//
// Sweeper subtests (DeleteExpired*) accept either a real deletion or
// service.ErrSweepNotImplemented. Every backend currently in tree
// (memory, postgres, entdb) implements the real sweep; the exemption
// is retained so a new backend can land its CRUD methods first and
// the sweep in a follow-up PR without failing the conformance suite
// (Rule 6 — split along feature boundaries). A driver that returns a
// different error still fails the suite.
//
// Beyond the per-method CRUD subtests, RunConformance also runs the
// extended suites in consistency.go (read-your-writes through every
// secondary index), queryedge.go (pagination past the server row cap;
// query-before-first-write on a fresh tenant), roundtrip.go (value
// fidelity for adversarial strings and the full int64 range), and
// concurrency.go (no-lost-writes and read-your-writes under a writer
// fan-out). These target cross-backend bug classes the happy-path CRUD
// subtests don't reach.
//
// As of this writing the entdb driver FAILS three extended groups and
// the failures are INTENTIONAL — each is the isolated repro of a
// tenant-shard-db bug being fixed upstream, kept red as the tracking
// signal (do not skip them):
//   - RoundTrip/Int64_Fidelity: payloads marshal through structpb, so
//     int64 values above 2^53 lose precision (float64 coercion).
//   - Pagination/*: QueryNodes caps at ~100 rows with no cursor, so
//     un-paginated List* reads truncate.
//   - FreshTenant/*: a query before the tenant's first write returns a
//     sanitized Internal error instead of an empty result.
//   - Concurrency/ConcurrentDuplicate_OAuthIdentity_SingleRow: entdb has
//     no composite unique constraint, so the non-atomic query-then-
//     create guard lets concurrent (provider,sub) creates all win.
//   - Concurrency/ConcurrentIncrement_NoLostUpdates: read-modify-write
//     IncrementFailedLoginCount plus a value-specific visibility wait
//     errors out / loses updates under concurrent increments.
//   - UpdateToZeroValue/Bool_TotpVerified_TrueThenFalse: the typed
//     update patch omits proto3 zero values, so "set false/0/”" no-ops
//     (an identity-side gap — the raw field-id update path used by
//     UpdateUser does not have it).
//
// Memory and postgres pass every group; they are the differential
// reference for "correct".
package conformance

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// Driver names the backend implementation under test and provides a
// factory the suite calls at the top of every subtest.
type Driver struct {
	// Name appears in every subtest path emitted by the suite, e.g.
	// `TestConformance/postgres/UserCRUD`. Use the same names CI
	// surfaces as check names — `memory`, `postgres`, `entdb`.
	Name string

	// NewRepo returns a freshly-constructed Repository with empty
	// state. Drivers that need per-test cleanup hooks should register
	// them with t.Cleanup inside NewRepo so a subtest never leaks
	// state into the next.
	NewRepo func(t *testing.T) service.Repository

	// BindProject returns base rebound to projectID (ADR-0002 — the Project
	// is the storage shard). It exists so the cross-project isolation suite
	// can exercise the real per-request WithProject scoping on ONE backing
	// store rather than two independently-constructed repos. Drivers whose
	// data-plane FK requires the project row to exist first (postgres) seed
	// it here before returning base.WithProject(projectID); drivers without a
	// control plane (memory, entdb) just return base.WithProject(projectID).
	// When nil, the cross-project isolation subtest skips for this driver.
	BindProject func(t *testing.T, base service.Repository, projectID string) service.Repository
}

// runSweepCase exercises one DeleteExpired* method. The caller
// supplies seedExpired (creates a row with ExpiresAt < 10_000) and
// seedUnexpired (creates a row with ExpiresAt > 10_000), plus an
// unexpiredStillPresent probe that must return true after the sweep
// for the suite to pass.
//
// tenant-shard-db v1.14.0's OpDeleteWhere (#540) does not return a
// deleted-row count, so the Repository contract returns only error
// and the suite probes the surviving rows (via the "still present"
// callback) instead of asserting on a count. The sweep call is still
// invoked at the boundary thresholds (below cutoff → nothing
// deleted; at cutoff with a tight limit → at least one drained per
// call) so a backend that ignores the limit or the cutoff still
// fails the deletion check on the unexpired row, or the idempotent
// re-sweep that follows.
//
// Drivers that return service.ErrSweepNotImplemented on the first
// sweep call are exempt from the data assertions but must still
// return that exact sentinel. As of v0.7.x every shipping backend
// implements the real sweep, so this branch is unused in practice;
// see the package doc for the rationale on keeping it.
func runSweepCase(t *testing.T, label string, sweep func(ctx context.Context, beforeMs int64, limit int) error, seedExpired, seedUnexpired func(t *testing.T), unexpiredStillPresent func(t *testing.T) bool) {
	t.Helper()
	ctx := context.Background()

	seedExpired(t)
	seedExpired(t)
	seedUnexpired(t)

	// First sweep at a time strictly less than the expired rows'
	// ExpiresAt: nothing to delete. We can't assert "rows deleted ==
	// 0" any more, but the unexpired-row probe below catches a buggy
	// backend that deletes everything regardless of cutoff.
	err := sweep(ctx, 100, 10)
	if errors.Is(err, service.ErrSweepNotImplemented) {
		t.Logf("%s: backend does not implement sweep — skipping data assertions", label)
		return
	}
	if err != nil {
		t.Fatalf("%s: first sweep: %v", label, err)
	}
	if !unexpiredStillPresent(t) {
		t.Fatalf("%s: unexpired row was deleted by a below-cutoff sweep", label)
	}

	// Second sweep beyond the expired rows but capped at 1: drains
	// at least one row per call. The 10-tick loop below is the
	// "drain to empty" pattern callers must use when they need to
	// guarantee a clean run; assert that two calls are sufficient
	// for the two-row backlog.
	if err := sweep(ctx, 10_000, 1); err != nil {
		t.Fatalf("%s: limit-1 sweep: %v", label, err)
	}
	if err := sweep(ctx, 10_000, 1); err != nil {
		t.Fatalf("%s: second limit-1 sweep: %v", label, err)
	}
	// Final sweep with a generous limit removes anything left over;
	// the unexpired row must still be present.
	if err := sweep(ctx, 10_000, 10); err != nil {
		t.Fatalf("%s: final sweep: %v", label, err)
	}
	if !unexpiredStillPresent(t) {
		t.Fatalf("%s: unexpired row was deleted by the sweeper", label)
	}

	// One more sweep with the same threshold: idempotent on an empty
	// backlog.
	if err := sweep(ctx, 10_000, 10); err != nil {
		t.Fatalf("%s: idempotent re-sweep: %v", label, err)
	}
	if !unexpiredStillPresent(t) {
		t.Fatalf("%s: unexpired row was deleted by the idempotent re-sweep", label)
	}
}

// RunConformance exercises every method on the service.Repository
// contract against driver.NewRepo. Subtests run under a t.Run group
// named after driver.Name so test logs and CI output show the driver
// for every assertion.
func RunConformance(t *testing.T, driver Driver) {
	t.Helper()

	if driver.Name == "" {
		t.Fatal("conformance: driver.Name is required")
	}
	if driver.NewRepo == nil {
		t.Fatal("conformance: driver.NewRepo is required")
	}

	t.Run(driver.Name, func(t *testing.T) {
		t.Run("UserCRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			got, err := r.FindUserByEmail(ctx, "alice@example.com")
			if err != nil {
				t.Fatalf("FindUserByEmail empty: %v", err)
			}
			if got != nil {
				t.Fatalf("FindUserByEmail empty: want nil, got %#v", got)
			}

			now := time.UnixMilli(1_700_000_000_000)
			id, err := r.CreateUser(ctx, &service.User{
				Email:           "alice@example.com",
				Name:            "Alice",
				Status:          "active",
				Role:            "member",
				PasswordHash:    "h-1",
				PhoneNumber:     "+14155550100",
				PhoneVerified:   true,
				PhoneVerifiedAt: 99,
				CreatedAt:       now,
				UpdatedAt:       now,
			})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if id == "" {
				t.Fatal("CreateUser: empty id")
			}

			got, err = r.FindUserByEmail(ctx, "alice@example.com")
			if err != nil {
				t.Fatalf("FindUserByEmail: %v", err)
			}
			if got == nil {
				t.Fatal("FindUserByEmail: nil after create")
			}
			if got.ID != id {
				t.Fatalf("FindUserByEmail id = %q, want %q", got.ID, id)
			}
			if got.Email != "alice@example.com" {
				t.Fatalf("FindUserByEmail email = %q", got.Email)
			}
			if got.PasswordHash != "h-1" {
				t.Fatalf("FindUserByEmail password_hash = %q, want %q",
					got.PasswordHash, "h-1")
			}
			if got.PhoneNumber != "+14155550100" || !got.PhoneVerified || got.PhoneVerifiedAt != 99 {
				t.Fatalf("FindUserByEmail phone round-trip: number=%q verified=%v at=%d",
					got.PhoneNumber, got.PhoneVerified, got.PhoneVerifiedAt)
			}

			byID, err := r.GetUser(ctx, id)
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}
			if byID == nil || byID.ID != id {
				t.Fatalf("GetUser: %#v", byID)
			}
			if byID.PasswordHash != "h-1" {
				t.Fatalf("GetUser password_hash = %q", byID.PasswordHash)
			}
		})

		t.Run("UserDuplicate_Email_Rejected", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			_, err := r.CreateUser(ctx, &service.User{Email: "dup@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("first CreateUser: %v", err)
			}
			_, err = r.CreateUser(ctx, &service.User{Email: "dup@example.com", Status: "active"})
			if err == nil {
				t.Fatal("CreateUser duplicate: want error, got nil")
			}
		})

		t.Run("UserUpdate_FieldRoundTrip", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "u@example.com", Status: "active", Name: "Old"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := r.UpdateUser(ctx, id, map[string]any{
				"name":              "New",
				"avatar_url":        "https://x/a.png",
				"password_hash":     "h-2",
				"status":            "active",
				"recovery_email":    "r@example.com",
				"email_verified":    true,
				"email_verified_at": int64(123),
				"phone_number":      "+14155550123",
				"phone_verified":    true,
				"phone_verified_at": int64(456),
			}); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			got, err := r.GetUser(ctx, id)
			if err != nil || got == nil {
				t.Fatalf("GetUser: %v, %#v", err, got)
			}
			if got.Name != "New" || got.AvatarURL != "https://x/a.png" || got.PasswordHash != "h-2" {
				t.Fatalf("UpdateUser round-trip: %+v", got)
			}
			if !got.EmailVerified || got.EmailVerifiedAt != 123 {
				t.Fatalf("UpdateUser email_verified round-trip: verified=%v at=%d", got.EmailVerified, got.EmailVerifiedAt)
			}
			if got.PhoneNumber != "+14155550123" || !got.PhoneVerified || got.PhoneVerifiedAt != 456 {
				t.Fatalf("UpdateUser phone round-trip: number=%q verified=%v at=%d", got.PhoneNumber, got.PhoneVerified, got.PhoneVerifiedAt)
			}
		})

		t.Run("UserLockout_FailedLoginCount", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "lock@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			n, err := r.IncrementFailedLoginCount(ctx, id)
			if err != nil || n != 1 {
				t.Fatalf("Increment#1: n=%d err=%v", n, err)
			}
			n, err = r.IncrementFailedLoginCount(ctx, id)
			if err != nil || n != 2 {
				t.Fatalf("Increment#2: n=%d err=%v", n, err)
			}
			if err := r.SetUserLockedUntil(ctx, id, 1234); err != nil {
				t.Fatalf("SetUserLockedUntil: %v", err)
			}
			got, _ := r.GetUser(ctx, id)
			if got == nil || got.FailedLoginCount != 2 || got.LockedUntil != 1234 {
				t.Fatalf("locked state: %+v", got)
			}
			if err := r.ResetFailedLoginCount(ctx, id); err != nil {
				t.Fatalf("ResetFailedLoginCount: %v", err)
			}
			got, _ = r.GetUser(ctx, id)
			if got == nil || got.FailedLoginCount != 0 || got.LockedUntil != 0 {
				t.Fatalf("after reset: %+v", got)
			}
		})

		t.Run("RefreshToken_CreateFindConsume", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "rt-cfc@example.com")
			id, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash:  "rh-1",
				UserID:     userID,
				ExpiresAt:  9_000_000_000_000,
				CreatedAt:  100,
				LastUsedAt: 100,
			})
			if err != nil || id == "" {
				t.Fatalf("CreateRefreshToken: id=%q err=%v", id, err)
			}
			got, err := r.FindRefreshTokenByHash(ctx, "rh-1")
			if err != nil || got == nil {
				t.Fatalf("FindRefreshTokenByHash: %v, %#v", err, got)
			}
			if got.UserID != userID {
				t.Fatalf("UserID = %q, want %q", got.UserID, userID)
			}
			if err := r.ConsumeRefreshTokenByHash(ctx, "rh-1", 200); err != nil {
				t.Fatalf("Consume: %v", err)
			}
			live, err := r.FindRefreshTokenByHash(ctx, "rh-1")
			if err != nil {
				t.Fatalf("FindRefreshTokenByHash post-consume: %v", err)
			}
			if live != nil {
				t.Fatalf("FindRefreshTokenByHash post-consume: got %#v, want nil", live)
			}
			all, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, "rh-1")
			if err != nil || all == nil || all.ConsumedAtMs != 200 {
				t.Fatalf("FindRefreshTokenByHashIncludingConsumed: %#v err=%v", all, err)
			}
			if err := r.ConsumeRefreshTokenByHash(ctx, "rh-1", 300); !errors.Is(err, service.ErrUnauthenticated) {
				t.Fatalf("second Consume: want ErrUnauthenticated, got %v", err)
			}
		})

		t.Run("RefreshToken_ConsumeCAS_RaceSingleWinner", func(t *testing.T) {
			// Drives ConsumeRefreshTokenByHash from N goroutines against
			// the same unconsumed token. Exactly one goroutine must win;
			// all others must observe ErrUnauthenticated. The repository
			// is the serialization point — this is the cross-driver
			// equivalent of the multi-replica refresh-rotation race
			// issue #24 fixes.
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "rt-race@example.com")
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash:  "rt-race-1",
				UserID:     userID,
				ExpiresAt:  9_000_000_000_000,
				CreatedAt:  100,
				LastUsedAt: 100,
			}); err != nil {
				t.Fatalf("CreateRefreshToken: %v", err)
			}

			const N = 8
			results := make(chan error, N)
			start := make(chan struct{})
			for i := 0; i < N; i++ {
				go func() {
					<-start
					results <- r.ConsumeRefreshTokenByHash(ctx, "rt-race-1", 200)
				}()
			}
			close(start)

			winners := 0
			losers := 0
			for i := 0; i < N; i++ {
				err := <-results
				switch {
				case err == nil:
					winners++
				case errors.Is(err, service.ErrUnauthenticated):
					losers++
				default:
					t.Errorf("loser got unexpected error: %v", err)
				}
			}
			if winners != 1 {
				t.Fatalf("ConsumeRefreshTokenByHash winners = %d, want 1 (losers=%d)", winners, losers)
			}
			if losers != N-1 {
				t.Fatalf("ConsumeRefreshTokenByHash losers = %d, want %d", losers, N-1)
			}
			got, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-race-1")
			if err != nil || got == nil {
				t.Fatalf("Find post-race: err=%v got=%#v", err, got)
			}
			if got.ConsumedAtMs == 0 {
				t.Fatalf("final consumed_at_ms = 0, want non-zero (post-race row should be consumed)")
			}
		})

		t.Run("RefreshToken_DeleteForUser", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userA := createTestUser(t, r, "rt-dfu-a@example.com")
			userB := createTestUser(t, r, "rt-dfu-b@example.com")
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "a", UserID: userA}); err != nil {
				t.Fatalf("CreateRefreshToken a: %v", err)
			}
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "b", UserID: userA}); err != nil {
				t.Fatalf("CreateRefreshToken b: %v", err)
			}
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "c", UserID: userB}); err != nil {
				t.Fatalf("CreateRefreshToken c: %v", err)
			}
			if err := r.DeleteRefreshTokensForUser(ctx, userA); err != nil {
				t.Fatalf("DeleteForUser: %v", err)
			}
			got, _ := r.FindRefreshTokenByHashIncludingConsumed(ctx, "a")
			if got != nil {
				t.Fatalf("userA token still present after DeleteForUser")
			}
			got, _ = r.FindRefreshTokenByHashIncludingConsumed(ctx, "c")
			if got == nil {
				t.Fatal("userB token removed by DeleteForUser scope leak")
			}
		})

		t.Run("RefreshToken_DeleteOne", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "rt-del-one@example.com")
			id, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "delete-one", UserID: userID})
			if err != nil {
				t.Fatalf("CreateRefreshToken: %v", err)
			}
			_, err = r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "keep-one", UserID: userID})
			if err != nil {
				t.Fatalf("CreateRefreshToken keep: %v", err)
			}
			if err := r.DeleteRefreshToken(ctx, id); err != nil {
				t.Fatalf("DeleteRefreshToken: %v", err)
			}
			deleted, _ := r.FindRefreshTokenByHashIncludingConsumed(ctx, "delete-one")
			if deleted != nil {
				t.Fatalf("deleted token still present: %#v", deleted)
			}
			kept, _ := r.FindRefreshTokenByHashIncludingConsumed(ctx, "keep-one")
			if kept == nil {
				t.Fatal("DeleteRefreshToken removed a different token")
			}
		})

		t.Run("PasswordResetToken_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "prt@example.com")
			tok := &service.PasswordResetToken{TokenHash: "p-1", UserID: userID, ExpiresAt: 1_000, CreatedAt: 100}
			if err := r.CreatePasswordResetToken(ctx, tok); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if tok.NodeID == "" {
				t.Fatal("CreatePasswordResetToken did not set NodeID")
			}
			got, err := r.FindPasswordResetTokenByHash(ctx, "p-1")
			if err != nil || got == nil {
				t.Fatalf("Find: %v %#v", err, got)
			}
			if err := r.MarkPasswordResetTokenConsumed(ctx, got.NodeID, 200); err != nil {
				t.Fatalf("MarkConsumed: %v", err)
			}
			got, _ = r.FindPasswordResetTokenByHash(ctx, "p-1")
			if got == nil || got.ConsumedAt != 200 {
				t.Fatalf("after MarkConsumed: %#v", got)
			}
		})

		t.Run("EmailVerificationToken_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "evt@example.com")
			tok := &service.EmailVerificationToken{TokenHash: "ev-1", UserID: userID, Email: "x@y.com", ExpiresAt: 1_000, CreatedAt: 100}
			if err := r.CreateEmailVerificationToken(ctx, tok); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.FindEmailVerificationTokenByHash(ctx, "ev-1")
			if got == nil {
				t.Fatal("Find missing")
			}
			if err := r.MarkEmailVerificationTokenConsumed(ctx, got.NodeID, 222); err != nil {
				t.Fatalf("MarkConsumed: %v", err)
			}
		})

		t.Run("EmailChangeToken_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid, err := r.CreateUser(ctx, &service.User{Email: "old@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			tok := &service.EmailChangeToken{TokenHash: "ec-1", UserID: uid, OldEmail: "old@example.com", NewEmail: "new@example.com", ExpiresAt: 1_000, CreatedAt: 100}
			if err := r.CreateEmailChangeToken(ctx, tok); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.FindEmailChangeTokenByHash(ctx, "ec-1")
			if got == nil {
				t.Fatal("Find missing")
			}
			if err := r.MarkEmailChangeTokenConsumed(ctx, got.NodeID, 333); err != nil {
				t.Fatalf("MarkConsumed: %v", err)
			}
			if err := r.UpdateUserEmail(ctx, uid, "new@example.com", 444); err != nil {
				t.Fatalf("UpdateUserEmail: %v", err)
			}
			u, _ := r.GetUser(ctx, uid)
			if u == nil || u.Email != "new@example.com" || !u.EmailVerified {
				t.Fatalf("after UpdateUserEmail: %+v", u)
			}
			oldEmail, err := r.FindUserByEmail(ctx, "old@example.com")
			if err != nil {
				t.Fatalf("FindUserByEmail old: %v", err)
			}
			if oldEmail != nil {
				t.Fatalf("old email still resolves after UpdateUserEmail: %+v", oldEmail)
			}
			newEmail, err := r.FindUserByEmail(ctx, "new@example.com")
			if err != nil {
				t.Fatalf("FindUserByEmail new: %v", err)
			}
			if newEmail == nil || newEmail.ID != uid {
				t.Fatalf("new email lookup = %+v, want user %q", newEmail, uid)
			}
		})

		t.Run("PasskeyCredential_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "pk@example.com")
			id, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
				CredentialID: "cred-1", UserID: userID, PublicKey: "pk", SignCount: 5,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.GetPasskeyCredentialByCredID(ctx, "cred-1")
			if got == nil || got.NodeID != id {
				t.Fatalf("GetByCred: %#v", got)
			}
			list, err := r.ListPasskeyCredentials(ctx, userID)
			if err != nil || len(list) != 1 {
				t.Fatalf("List: len=%d err=%v", len(list), err)
			}
			if err := r.UpdatePasskeyCredential(ctx, id, map[string]any{"sign_count": int64(99)}); err != nil {
				t.Fatalf("Update: %v", err)
			}
		})

		t.Run("PasskeyChallenge_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "pkc@example.com")
			id, err := r.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
				Challenge:     "c-1",
				UserID:        userID,
				ChallengeType: "registration",
				ExpiresAt:     1_000,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := r.GetPasskeyChallenge(ctx, id)
			if err != nil || got == nil || got.Challenge != "c-1" {
				t.Fatalf("Get: %v, %#v", err, got)
			}
			if err := r.DeletePasskeyChallenge(ctx, id); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		})

		t.Run("QrLoginSession_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "qr@example.com")
			id, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: "qr-1", Status: "pending", NewDeviceInfo: "Chrome",
				ExpiresAt: 1_000, CreatedAt: 100, UpdatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.FindQrLoginSession(ctx, "qr-1")
			if got == nil || got.NodeID != id {
				t.Fatalf("Find: %#v", got)
			}
			if err := r.UpdateQrLoginSession(ctx, id, map[string]any{
				"status":  "approved",
				"user_id": userID,
			}); err != nil {
				t.Fatalf("Update: %v", err)
			}
			got, _ = r.FindQrLoginSession(ctx, "qr-1")
			if got == nil || got.Status != "approved" || got.UserID != userID {
				t.Fatalf("after Update: %#v", got)
			}
		})

		t.Run("QrLoginSession_ConsumeCAS_HappyPathAndReplay", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "qr-consume@example.com")
			id, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: "qr-consume-1", Status: "approved", UserID: userID,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, UpdatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := r.ConsumeQrLoginSession(ctx, id, 200); err != nil {
				t.Fatalf("first Consume: want nil, got %v", err)
			}
			got, err := r.FindQrLoginSession(ctx, "qr-consume-1")
			if err != nil || got == nil {
				t.Fatalf("Find post-consume: err=%v got=%#v", err, got)
			}
			if got.Status != "consumed" {
				t.Fatalf("Status post-consume = %q, want consumed", got.Status)
			}
			if got.UpdatedAt != 200 {
				t.Fatalf("UpdatedAt post-consume = %d, want 200", got.UpdatedAt)
			}
			if err := r.ConsumeQrLoginSession(ctx, id, 300); !errors.Is(err, service.ErrQrLoginNotPending) {
				t.Fatalf("replay Consume: want ErrQrLoginNotPending, got %v", err)
			}
		})

		t.Run("QrLoginSession_ConsumeCAS_RejectsNonApproved", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			// Pending session — Consume must refuse without changing state.
			pid, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: "qr-pending", Status: "pending",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, UpdatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create pending: %v", err)
			}
			if err := r.ConsumeQrLoginSession(ctx, pid, 200); !errors.Is(err, service.ErrQrLoginNotPending) {
				t.Fatalf("Consume pending: want ErrQrLoginNotPending, got %v", err)
			}
			pgot, _ := r.FindQrLoginSession(ctx, "qr-pending")
			if pgot == nil || pgot.Status != "pending" {
				t.Fatalf("pending session state changed: %#v", pgot)
			}

			// Rejected session — same: refuse, no state change.
			userID := createTestUser(t, r, "qr-rej@example.com")
			rid, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: "qr-rejected", Status: "rejected", UserID: userID,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, UpdatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create rejected: %v", err)
			}
			if err := r.ConsumeQrLoginSession(ctx, rid, 200); !errors.Is(err, service.ErrQrLoginNotPending) {
				t.Fatalf("Consume rejected: want ErrQrLoginNotPending, got %v", err)
			}

			// Missing session — same.
			if err := r.ConsumeQrLoginSession(ctx, "missing-node", 200); !errors.Is(err, service.ErrQrLoginNotPending) {
				t.Fatalf("Consume missing: want ErrQrLoginNotPending, got %v", err)
			}
		})

		t.Run("QrLoginSession_ConsumeCAS_RaceSingleWinner", func(t *testing.T) {
			// Drives ConsumeQrLoginSession from N goroutines against the
			// same approved session row. Exactly one goroutine must win;
			// all others must see ErrQrLoginNotPending. The repository is
			// the serialization point — this test is the cross-driver
			// equivalent of the multi-replica race the production server
			// faces in #14.
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "qr-race@example.com")
			id, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: "qr-race-1", Status: "approved", UserID: userID,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, UpdatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			const N = 8
			results := make(chan error, N)
			start := make(chan struct{})
			for i := 0; i < N; i++ {
				go func() {
					<-start
					results <- r.ConsumeQrLoginSession(ctx, id, 200)
				}()
			}
			close(start)

			winners := 0
			losers := 0
			for i := 0; i < N; i++ {
				err := <-results
				switch {
				case err == nil:
					winners++
				case errors.Is(err, service.ErrQrLoginNotPending):
					losers++
				default:
					t.Errorf("loser got unexpected error: %v", err)
				}
			}
			if winners != 1 {
				t.Fatalf("ConsumeQrLoginSession winners = %d, want 1 (losers=%d)", winners, losers)
			}
			if losers != N-1 {
				t.Fatalf("ConsumeQrLoginSession losers = %d, want %d", losers, N-1)
			}
			got, err := r.FindQrLoginSession(ctx, "qr-race-1")
			if err != nil || got == nil {
				t.Fatalf("Find post-race: err=%v got=%#v", err, got)
			}
			if got.Status != "consumed" {
				t.Fatalf("final status = %q, want consumed", got.Status)
			}
		})

		t.Run("OAuthOneTimeCode_ConsumeCAS_HappyPathAndReplay", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "otc-consume@example.com")
			id, err := r.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{
				CodeHash: "otc-hash-1", UserID: userID,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if id == "" {
				t.Fatal("CreateOAuthOneTimeCode did not return a node id")
			}
			rec, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-hash-1", 200)
			if err != nil {
				t.Fatalf("first Consume: want nil, got %v", err)
			}
			if rec == nil || rec.UserID != userID {
				t.Fatalf("Consume returned wrong record: %#v", rec)
			}
			if rec.ConsumedAt != 200 {
				t.Fatalf("ConsumedAt = %d, want 200", rec.ConsumedAt)
			}
			// Replay must fail with ErrOAuthCodeInvalid.
			if _, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-hash-1", 300); !errors.Is(err, service.ErrOAuthCodeInvalid) {
				t.Fatalf("replay Consume: want ErrOAuthCodeInvalid, got %v", err)
			}
		})

		t.Run("OAuthOneTimeCode_ConsumeCAS_RejectsExpiredAndMissing", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "otc-expired@example.com")
			// Expired code: expires_at <= atMs must be refused.
			if _, err := r.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{
				CodeHash: "otc-expired", UserID: userID,
				ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create expired: %v", err)
			}
			if _, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-expired", 2_000); !errors.Is(err, service.ErrOAuthCodeInvalid) {
				t.Fatalf("Consume expired: want ErrOAuthCodeInvalid, got %v", err)
			}
			// Unknown code: same shape.
			if _, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-missing", 2_000); !errors.Is(err, service.ErrOAuthCodeInvalid) {
				t.Fatalf("Consume missing: want ErrOAuthCodeInvalid, got %v", err)
			}
		})

		t.Run("OAuthOneTimeCode_ConsumeCAS_RaceSingleWinner", func(t *testing.T) {
			// Drives ConsumeOAuthOneTimeCode from N goroutines against the
			// same code. Exactly one goroutine wins (and gets the record);
			// all others see ErrOAuthCodeInvalid. The repository is the
			// serialization point — the cross-driver equivalent of the
			// multi-replica redeem race.
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "otc-race@example.com")
			if _, err := r.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{
				CodeHash: "otc-race-1", UserID: userID,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create: %v", err)
			}

			const N = 8
			type outcome struct {
				rec *service.OAuthOneTimeCodeRecord
				err error
			}
			results := make(chan outcome, N)
			start := make(chan struct{})
			for i := 0; i < N; i++ {
				go func() {
					<-start
					rec, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-race-1", 200)
					results <- outcome{rec, err}
				}()
			}
			close(start)

			winners := 0
			losers := 0
			for i := 0; i < N; i++ {
				o := <-results
				switch {
				case o.err == nil:
					winners++
					if o.rec == nil || o.rec.UserID != userID {
						t.Errorf("winner got wrong record: %#v", o.rec)
					}
				case errors.Is(o.err, service.ErrOAuthCodeInvalid):
					losers++
				default:
					t.Errorf("loser got unexpected error: %v", o.err)
				}
			}
			if winners != 1 {
				t.Fatalf("ConsumeOAuthOneTimeCode winners = %d, want 1 (losers=%d)", winners, losers)
			}
			if losers != N-1 {
				t.Fatalf("ConsumeOAuthOneTimeCode losers = %d, want %d", losers, N-1)
			}
		})

		t.Run("OAuthOneTimeCode_DeleteExpired", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "otc-sweep@example.com")
			if _, err := r.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{
				CodeHash: "otc-old", UserID: userID, ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create old: %v", err)
			}
			if _, err := r.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{
				CodeHash: "otc-fresh", UserID: userID, ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create fresh: %v", err)
			}
			if err := r.DeleteExpiredOAuthOneTimeCodes(ctx, 5_000, 100); err != nil {
				t.Fatalf("DeleteExpired: %v", err)
			}
			// The expired code is gone (consume now fails); the fresh one
			// survives (consume succeeds).
			if _, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-old", 6_000); !errors.Is(err, service.ErrOAuthCodeInvalid) {
				t.Fatalf("Consume swept code: want ErrOAuthCodeInvalid, got %v", err)
			}
			if _, err := r.ConsumeOAuthOneTimeCode(ctx, "otc-fresh", 6_000); err != nil {
				t.Fatalf("Consume surviving code: want nil, got %v", err)
			}
			if err := r.DeleteExpiredOAuthOneTimeCodes(ctx, 5_000, 0); err == nil {
				t.Fatal("DeleteExpired with limit 0: want error, got nil")
			}
		})

		t.Run("EmailLoginCode_UpsertFindConsume", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp@example.com", CodeHash: "hash-1",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			})
			if err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			if id == "" {
				t.Fatal("UpsertEmailLoginCode did not return a node id")
			}
			got, err := r.FindEmailLoginCodeByEmail(ctx, "otp@example.com")
			if err != nil || got == nil {
				t.Fatalf("Find: err=%v got=%#v", err, got)
			}
			if got.CodeHash != "hash-1" || got.MaxAttempts != 5 {
				t.Fatalf("Find returned wrong record: %#v", got)
			}
			// Consume succeeds once.
			rec, err := r.ConsumeEmailLoginCode(ctx, "otp@example.com", 200)
			if err != nil {
				t.Fatalf("first Consume: want nil, got %v", err)
			}
			if rec == nil || rec.ConsumedAt != 200 {
				t.Fatalf("Consume returned wrong record: %#v", rec)
			}
			// Replay must fail.
			if _, err := r.ConsumeEmailLoginCode(ctx, "otp@example.com", 300); !errors.Is(err, service.ErrEmailLoginCodeInvalid) {
				t.Fatalf("replay Consume: want ErrEmailLoginCodeInvalid, got %v", err)
			}
		})

		t.Run("EmailLoginCode_UpsertReplacesPrevious", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-upsert@example.com", CodeHash: "old",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert old: %v", err)
			}
			if _, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-upsert@example.com", CodeHash: "new",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 200, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert new: %v", err)
			}
			got, err := r.FindEmailLoginCodeByEmail(ctx, "otp-upsert@example.com")
			if err != nil || got == nil {
				t.Fatalf("Find: err=%v got=%#v", err, got)
			}
			if got.CodeHash != "new" {
				t.Fatalf("upsert did not replace previous code: hash=%q want new", got.CodeHash)
			}
		})

		t.Run("EmailLoginCode_IncrementAttempts", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-attempts@example.com", CodeHash: "h",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			})
			if err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			if err := r.IncrementEmailLoginCodeAttempts(ctx, id); err != nil {
				t.Fatalf("Increment: %v", err)
			}
			if err := r.IncrementEmailLoginCodeAttempts(ctx, id); err != nil {
				t.Fatalf("Increment 2: %v", err)
			}
			got, err := r.FindEmailLoginCodeByEmail(ctx, "otp-attempts@example.com")
			if err != nil || got == nil {
				t.Fatalf("Find: err=%v got=%#v", err, got)
			}
			if got.AttemptCount != 2 {
				t.Fatalf("AttemptCount = %d, want 2", got.AttemptCount)
			}
		})

		t.Run("EmailLoginCode_ConsumeRejectsExpiredAndMissing", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-expired@example.com", CodeHash: "h",
				ExpiresAt: 1_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert expired: %v", err)
			}
			if _, err := r.ConsumeEmailLoginCode(ctx, "otp-expired@example.com", 2_000); !errors.Is(err, service.ErrEmailLoginCodeInvalid) {
				t.Fatalf("Consume expired: want ErrEmailLoginCodeInvalid, got %v", err)
			}
			if _, err := r.ConsumeEmailLoginCode(ctx, "otp-missing@example.com", 2_000); !errors.Is(err, service.ErrEmailLoginCodeInvalid) {
				t.Fatalf("Consume missing: want ErrEmailLoginCodeInvalid, got %v", err)
			}
		})

		t.Run("EmailLoginCode_ConsumeRaceSingleWinner", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-race@example.com", CodeHash: "h",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			const N = 8
			results := make(chan error, N)
			start := make(chan struct{})
			for i := 0; i < N; i++ {
				go func() {
					<-start
					_, err := r.ConsumeEmailLoginCode(ctx, "otp-race@example.com", 200)
					results <- err
				}()
			}
			close(start)
			winners, losers := 0, 0
			for i := 0; i < N; i++ {
				switch err := <-results; {
				case err == nil:
					winners++
				case errors.Is(err, service.ErrEmailLoginCodeInvalid):
					losers++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if winners != 1 || losers != N-1 {
				t.Fatalf("ConsumeEmailLoginCode winners=%d losers=%d, want 1/%d", winners, losers, N-1)
			}
		})

		t.Run("EmailLoginCode_DeleteExpired", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-old@example.com", CodeHash: "h", ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Upsert old: %v", err)
			}
			if _, err := r.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
				Email: "otp-fresh@example.com", CodeHash: "h", ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Upsert fresh: %v", err)
			}
			if err := r.DeleteExpiredEmailLoginCodes(ctx, 5_000, 100); err != nil {
				t.Fatalf("DeleteExpired: %v", err)
			}
			if got, _ := r.FindEmailLoginCodeByEmail(ctx, "otp-old@example.com"); got != nil {
				t.Fatal("expired code survived the sweep")
			}
			if got, _ := r.FindEmailLoginCodeByEmail(ctx, "otp-fresh@example.com"); got == nil {
				t.Fatal("fresh code was swept")
			}
			if err := r.DeleteExpiredEmailLoginCodes(ctx, 5_000, 0); err == nil {
				t.Fatal("DeleteExpired with limit 0: want error, got nil")
			}
		})

		t.Run("MagicLinkToken_ConsumeCAS_HappyPathAndReplay", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
				TokenHash: "ml-1", Email: "ml@example.com", ReturnTo: "https://app/cb",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if id == "" {
				t.Fatal("CreateMagicLinkToken did not return a node id")
			}
			rec, err := r.ConsumeMagicLinkToken(ctx, "ml-1", 200)
			if err != nil {
				t.Fatalf("first Consume: want nil, got %v", err)
			}
			if rec == nil || rec.Email != "ml@example.com" || rec.ReturnTo != "https://app/cb" {
				t.Fatalf("Consume returned wrong record: %#v", rec)
			}
			if rec.ConsumedAt != 200 {
				t.Fatalf("ConsumedAt = %d, want 200", rec.ConsumedAt)
			}
			if _, err := r.ConsumeMagicLinkToken(ctx, "ml-1", 300); !errors.Is(err, service.ErrMagicLinkInvalid) {
				t.Fatalf("replay Consume: want ErrMagicLinkInvalid, got %v", err)
			}
		})

		t.Run("MagicLinkToken_ConsumeRejectsExpiredAndMissing", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
				TokenHash: "ml-expired", Email: "ml-e@example.com",
				ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create expired: %v", err)
			}
			if _, err := r.ConsumeMagicLinkToken(ctx, "ml-expired", 2_000); !errors.Is(err, service.ErrMagicLinkInvalid) {
				t.Fatalf("Consume expired: want ErrMagicLinkInvalid, got %v", err)
			}
			if _, err := r.ConsumeMagicLinkToken(ctx, "ml-missing", 2_000); !errors.Is(err, service.ErrMagicLinkInvalid) {
				t.Fatalf("Consume missing: want ErrMagicLinkInvalid, got %v", err)
			}
		})

		t.Run("MagicLinkToken_ConsumeRaceSingleWinner", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
				TokenHash: "ml-race", Email: "ml-r@example.com",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			const N = 8
			results := make(chan error, N)
			start := make(chan struct{})
			for i := 0; i < N; i++ {
				go func() {
					<-start
					_, err := r.ConsumeMagicLinkToken(ctx, "ml-race", 200)
					results <- err
				}()
			}
			close(start)
			winners, losers := 0, 0
			for i := 0; i < N; i++ {
				switch err := <-results; {
				case err == nil:
					winners++
				case errors.Is(err, service.ErrMagicLinkInvalid):
					losers++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if winners != 1 || losers != N-1 {
				t.Fatalf("ConsumeMagicLinkToken winners=%d losers=%d, want 1/%d", winners, losers, N-1)
			}
		})

		t.Run("MagicLinkToken_DeleteExpired", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
				TokenHash: "ml-old", Email: "ml-old@example.com", ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create old: %v", err)
			}
			if _, err := r.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
				TokenHash: "ml-fresh", Email: "ml-fresh@example.com", ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create fresh: %v", err)
			}
			if err := r.DeleteExpiredMagicLinkTokens(ctx, 5_000, 100); err != nil {
				t.Fatalf("DeleteExpired: %v", err)
			}
			if _, err := r.ConsumeMagicLinkToken(ctx, "ml-old", 6_000); !errors.Is(err, service.ErrMagicLinkInvalid) {
				t.Fatalf("Consume swept token: want ErrMagicLinkInvalid, got %v", err)
			}
			if _, err := r.ConsumeMagicLinkToken(ctx, "ml-fresh", 6_000); err != nil {
				t.Fatalf("Consume surviving token: want nil, got %v", err)
			}
			if err := r.DeleteExpiredMagicLinkTokens(ctx, 5_000, 0); err == nil {
				t.Fatal("DeleteExpired with limit 0: want error, got nil")
			}
		})

		t.Run("TotpCredential_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "totp@example.com")
			id, err := r.CreateTotpCredential(ctx, &service.TotpCredRecord{
				UserID: userID, SecretEncrypted: "enc", CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.GetTotpCredential(ctx, userID)
			if got == nil || got.NodeID != id {
				t.Fatalf("Get: %#v", got)
			}
			if err := r.UpdateTotpCredential(ctx, id, map[string]any{"verified": true}); err != nil {
				t.Fatalf("Update: %v", err)
			}
			got, _ = r.GetTotpCredential(ctx, userID)
			if got == nil || !got.Verified {
				t.Fatalf("after Update: %#v", got)
			}
			if err := r.DeleteTotpCredentialsForUser(ctx, userID); err != nil {
				t.Fatalf("DeleteForUser: %v", err)
			}
			got, _ = r.GetTotpCredential(ctx, userID)
			if got != nil {
				t.Fatal("DeleteForUser left a row")
			}
		})

		t.Run("TotpCredential_DeleteOne", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "totp-del@example.com")
			id, err := r.CreateTotpCredential(ctx, &service.TotpCredRecord{
				UserID: userID, SecretEncrypted: "enc", CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := r.DeleteTotpCredential(ctx, id); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			got, _ := r.GetTotpCredential(ctx, userID)
			if got != nil {
				t.Fatal("Delete left a row")
			}
		})

		t.Run("RecoveryCode_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "rc@example.com")
			id, err := r.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{
				UserID: userID, CodeHash: "hash-1", CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.FindRecoveryCodeByHash(ctx, userID, "hash-1")
			if got == nil || got.NodeID != id {
				t.Fatalf("Find: %#v", got)
			}
			if err := r.UpdateRecoveryCode(ctx, id, map[string]any{"used": true, "used_at": int64(200)}); err != nil {
				t.Fatalf("Update: %v", err)
			}
			if err := r.DeleteRecoveryCodesForUser(ctx, userID); err != nil {
				t.Fatalf("DeleteForUser: %v", err)
			}
		})

		t.Run("LoginChallenge_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userID := createTestUser(t, r, "lc@example.com")
			id, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: "lc-1", UserID: userID, ExpiresAt: 1_000, CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, _ := r.GetLoginChallengeByChallengeID(ctx, "lc-1")
			if got == nil || got.NodeID != id {
				t.Fatalf("Get: %#v", got)
			}
			if err := r.DeleteLoginChallenge(ctx, id); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		})

		t.Run("OAuthIdentity_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid, err := r.CreateUser(ctx, &service.User{Email: "oa@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			// Second user so a duplicate (provider, sub) link can target
			// a different user_id without colliding on email.
			otherUID, err := r.CreateUser(ctx, &service.User{Email: "oa-other@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser other: %v", err)
			}
			oi := &service.OAuthIdentity{
				UserID: uid, Provider: "google", ProviderUserID: "g-123",
				EmailAtLinkTime: "oa@example.com", CreatedAt: 100,
			}
			if err := r.CreateOAuthIdentity(ctx, oi); err != nil {
				t.Fatalf("Create: %v", err)
			}
			// Composite uniqueness: a second link with same (provider, sub)
			// must reject (the schema does not enforce this so the
			// service layer must, and CreateOAuthIdentity is the
			// designated guard).
			dup := &service.OAuthIdentity{UserID: otherUID, Provider: "google", ProviderUserID: "g-123", CreatedAt: 200}
			if err := r.CreateOAuthIdentity(ctx, dup); err == nil {
				t.Fatal("CreateOAuthIdentity duplicate: want error, got nil")
			}
			otherProvider := &service.OAuthIdentity{
				UserID:          uid,
				Provider:        "microsoft",
				ProviderUserID:  "g-123",
				EmailAtLinkTime: "oa@example.com",
				CreatedAt:       300,
			}
			if err := r.CreateOAuthIdentity(ctx, otherProvider); err != nil {
				t.Fatalf("CreateOAuthIdentity other provider same subject: %v", err)
			}
			got, err := r.FindUserByProviderID(ctx, "google", "g-123")
			if err != nil || got == nil {
				t.Fatalf("FindByProvider: %v %#v", err, got)
			}
			if got.ID != uid {
				t.Fatalf("FindByProvider id = %q, want %q", got.ID, uid)
			}
			got, err = r.FindUserByProviderID(ctx, "microsoft", "g-123")
			if err != nil || got == nil {
				t.Fatalf("FindByProvider other provider: %v %#v", err, got)
			}
			if got.ID != uid {
				t.Fatalf("FindByProvider other provider id = %q, want %q", got.ID, uid)
			}
			list, err := r.ListOAuthIdentitiesForUser(ctx, uid)
			if err != nil || len(list) != 2 {
				t.Fatalf("List: len=%d err=%v", len(list), err)
			}
		})

		t.Run("Invitation_FindUpdate", func(t *testing.T) {
			// Only Find + Update are on the Repository interface; the
			// driver-specific create path is exercised via service.DB
			// which sits outside this conformance suite.
			ctx := context.Background()
			r := driver.NewRepo(t)
			got, err := r.FindInvitationByHash(ctx, "no-such")
			if err != nil {
				t.Fatalf("Find missing: %v", err)
			}
			if got != nil {
				t.Fatalf("Find missing: want nil, got %#v", got)
			}
		})

		t.Run("SetUserEmailVerified", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "ev@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := r.SetUserEmailVerified(ctx, id, 555); err != nil {
				t.Fatalf("SetUserEmailVerified: %v", err)
			}
			got, _ := r.GetUser(ctx, id)
			if got == nil || !got.EmailVerified || got.EmailVerifiedAt != 555 {
				t.Fatalf("after Set: %+v", got)
			}
		})

		t.Run("SetUserPhoneVerified", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "pv@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			got, _ := r.GetUser(ctx, id)
			if got == nil || got.PhoneVerified || got.PhoneNumber != "" || got.PhoneVerifiedAt != 0 {
				t.Fatalf("pre-Set: %+v", got)
			}
			if err := r.SetUserPhoneVerified(ctx, id, "+14155550199", 888); err != nil {
				t.Fatalf("SetUserPhoneVerified: %v", err)
			}
			got, _ = r.GetUser(ctx, id)
			if got == nil || !got.PhoneVerified || got.PhoneNumber != "+14155550199" || got.PhoneVerifiedAt != 888 {
				t.Fatalf("after Set: %+v", got)
			}
		})

		t.Run("PhoneVerificationCode_UpsertFindConsume", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "pvc@example.com")
			id, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: uid, PhoneNumber: "+14155550123", CodeHash: "hash-1",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			})
			if err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			if id == "" {
				t.Fatal("UpsertPhoneVerificationCode did not return a node id")
			}
			got, err := r.FindPhoneVerificationCodeByUser(ctx, uid)
			if err != nil || got == nil {
				t.Fatalf("Find: err=%v got=%#v", err, got)
			}
			if got.CodeHash != "hash-1" || got.PhoneNumber != "+14155550123" || got.MaxAttempts != 5 {
				t.Fatalf("Find returned wrong record: %#v", got)
			}
			// Consume succeeds once.
			rec, err := r.ConsumePhoneVerificationCode(ctx, uid, 200)
			if err != nil {
				t.Fatalf("first Consume: want nil, got %v", err)
			}
			if rec == nil || rec.ConsumedAt != 200 {
				t.Fatalf("Consume returned wrong record: %#v", rec)
			}
			// Replay must fail.
			if _, err := r.ConsumePhoneVerificationCode(ctx, uid, 300); !errors.Is(err, service.ErrPhoneCodeInvalid) {
				t.Fatalf("replay Consume: want ErrPhoneCodeInvalid, got %v", err)
			}
		})

		t.Run("PhoneVerificationCode_UpsertReplacesPrevious", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "pvc-upsert@example.com")
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: uid, PhoneNumber: "+14155550123", CodeHash: "old",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert old: %v", err)
			}
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: uid, PhoneNumber: "+14155550123", CodeHash: "new",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 200, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert new: %v", err)
			}
			got, err := r.FindPhoneVerificationCodeByUser(ctx, uid)
			if err != nil || got == nil {
				t.Fatalf("Find: err=%v got=%#v", err, got)
			}
			if got.CodeHash != "new" {
				t.Fatalf("upsert did not replace previous code: hash=%q want new", got.CodeHash)
			}
		})

		t.Run("PhoneVerificationCode_IncrementAttempts", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "pvc-attempts@example.com")
			id, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: uid, PhoneNumber: "+14155550123", CodeHash: "h",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			})
			if err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			if err := r.IncrementPhoneVerificationCodeAttempts(ctx, id); err != nil {
				t.Fatalf("Increment: %v", err)
			}
			if err := r.IncrementPhoneVerificationCodeAttempts(ctx, id); err != nil {
				t.Fatalf("Increment 2: %v", err)
			}
			got, err := r.FindPhoneVerificationCodeByUser(ctx, uid)
			if err != nil || got == nil {
				t.Fatalf("Find: err=%v got=%#v", err, got)
			}
			if got.AttemptCount != 2 {
				t.Fatalf("AttemptCount = %d, want 2", got.AttemptCount)
			}
		})

		t.Run("PhoneVerificationCode_ConsumeRejectsExpiredAndMissing", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "pvc-expired@example.com")
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: uid, PhoneNumber: "+14155550123", CodeHash: "h",
				ExpiresAt: 1_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert expired: %v", err)
			}
			if _, err := r.ConsumePhoneVerificationCode(ctx, uid, 2_000); !errors.Is(err, service.ErrPhoneCodeInvalid) {
				t.Fatalf("Consume expired: want ErrPhoneCodeInvalid, got %v", err)
			}
			missingUID := createTestUser(t, r, "pvc-missing@example.com")
			if _, err := r.ConsumePhoneVerificationCode(ctx, missingUID, 2_000); !errors.Is(err, service.ErrPhoneCodeInvalid) {
				t.Fatalf("Consume missing: want ErrPhoneCodeInvalid, got %v", err)
			}
		})

		t.Run("PhoneVerificationCode_ConsumeRaceSingleWinner", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "pvc-race@example.com")
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: uid, PhoneNumber: "+14155550123", CodeHash: "h",
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			const N = 8
			results := make(chan error, N)
			start := make(chan struct{})
			for i := 0; i < N; i++ {
				go func() {
					<-start
					_, err := r.ConsumePhoneVerificationCode(ctx, uid, 200)
					results <- err
				}()
			}
			close(start)
			winners, losers := 0, 0
			for i := 0; i < N; i++ {
				switch err := <-results; {
				case err == nil:
					winners++
				case errors.Is(err, service.ErrPhoneCodeInvalid):
					losers++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if winners != 1 || losers != N-1 {
				t.Fatalf("ConsumePhoneVerificationCode winners=%d losers=%d, want 1/%d", winners, losers, N-1)
			}
		})

		t.Run("PhoneVerificationCode_DeleteExpired", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			oldUID := createTestUser(t, r, "pvc-old@example.com")
			freshUID := createTestUser(t, r, "pvc-fresh@example.com")
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: oldUID, PhoneNumber: "+14155550111", CodeHash: "h", ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Upsert old: %v", err)
			}
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
				UserID: freshUID, PhoneNumber: "+14155550222", CodeHash: "h", ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Upsert fresh: %v", err)
			}
			if err := r.DeleteExpiredPhoneVerificationCodes(ctx, 5_000, 100); err != nil {
				t.Fatalf("DeleteExpired: %v", err)
			}
			if got, _ := r.FindPhoneVerificationCodeByUser(ctx, oldUID); got != nil {
				t.Fatal("expired code survived the sweep")
			}
			if got, _ := r.FindPhoneVerificationCodeByUser(ctx, freshUID); got == nil {
				t.Fatal("fresh code was swept")
			}
			if err := r.DeleteExpiredPhoneVerificationCodes(ctx, 5_000, 0); err == nil {
				t.Fatal("DeleteExpired with limit 0: want error, got nil")
			}
		})

		t.Run("SetUserIDVVerified", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "idv-flag@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			got, _ := r.GetUser(ctx, id)
			if got == nil || got.IDVVerified || got.IDVVerifiedAt != 0 {
				t.Fatalf("pre-Set: %+v", got)
			}
			if err := r.SetUserIDVVerified(ctx, id, 777); err != nil {
				t.Fatalf("SetUserIDVVerified: %v", err)
			}
			got, _ = r.GetUser(ctx, id)
			if got == nil || !got.IDVVerified || got.IDVVerifiedAt != 777 {
				t.Fatalf("after Set: %+v", got)
			}
		})

		t.Run("Session_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "sess-crud@example.com")

			// CreateSession requires sid + user_id; rejects empty sid.
			if _, err := r.CreateSession(ctx, &service.SessionRecord{UserID: uid}); err == nil {
				t.Fatal("CreateSession with empty sid: want error, got nil")
			}

			// Happy path: insert succeeds and round-trips by sid.
			s := &service.SessionRecord{
				SID: "sess-1", UserID: uid, CreatedAtMs: 1_700_000_000_000,
			}
			id, err := r.CreateSession(ctx, s)
			if err != nil || id == "" {
				t.Fatalf("CreateSession: id=%q err=%v", id, err)
			}
			got, err := r.GetSessionBySid(ctx, "sess-1")
			if err != nil || got == nil {
				t.Fatalf("GetSessionBySid: %v %#v", err, got)
			}
			if got.UserID != uid || got.RevokedAtMs != 0 || got.SID != "sess-1" {
				t.Fatalf("Session round-trip mismatch: %+v", got)
			}

			// Duplicate sid must reject.
			if _, err := r.CreateSession(ctx, &service.SessionRecord{
				SID: "sess-1", UserID: uid, CreatedAtMs: 1_700_000_000_001,
			}); err == nil {
				t.Fatal("CreateSession duplicate sid: want error, got nil")
			} else if !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("CreateSession duplicate sid: want ErrAlreadyExists, got %v", err)
			}

			// Unknown sid returns (nil, nil), not an error.
			miss, err := r.GetSessionBySid(ctx, "no-such-sid")
			if err != nil || miss != nil {
				t.Fatalf("GetSessionBySid unknown: err=%v rec=%#v", err, miss)
			}
		})

		t.Run("Session_Revoke", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "sess-revoke@example.com")

			// RevokeSession on an unknown sid is a successful no-op.
			if err := r.RevokeSession(ctx, "unknown-sid", 200); err != nil {
				t.Fatalf("RevokeSession unknown: %v", err)
			}

			// Seed two sessions; revoke one explicitly, the other via
			// RevokeSessionsForUser.
			if _, err := r.CreateSession(ctx, &service.SessionRecord{
				SID: "sess-a", UserID: uid, CreatedAtMs: 100,
			}); err != nil {
				t.Fatalf("CreateSession a: %v", err)
			}
			if _, err := r.CreateSession(ctx, &service.SessionRecord{
				SID: "sess-b", UserID: uid, CreatedAtMs: 100,
			}); err != nil {
				t.Fatalf("CreateSession b: %v", err)
			}

			if err := r.RevokeSession(ctx, "sess-a", 200); err != nil {
				t.Fatalf("RevokeSession a: %v", err)
			}
			got, _ := r.GetSessionBySid(ctx, "sess-a")
			if got == nil || got.RevokedAtMs != 200 {
				t.Fatalf("after RevokeSession a: %+v", got)
			}

			// Idempotency: revoking the same session a second time must
			// not error and must not overwrite the original timestamp.
			if err := r.RevokeSession(ctx, "sess-a", 300); err != nil {
				t.Fatalf("RevokeSession a (idempotent): %v", err)
			}
			got, _ = r.GetSessionBySid(ctx, "sess-a")
			if got == nil || got.RevokedAtMs != 200 {
				t.Fatalf("idempotent revoke changed timestamp: %+v", got)
			}

			// sess-b still active.
			gotB, _ := r.GetSessionBySid(ctx, "sess-b")
			if gotB == nil || gotB.RevokedAtMs != 0 {
				t.Fatalf("sess-b changed unexpectedly: %+v", gotB)
			}

			// Add a session for a different user so we can verify
			// scope-by-user later.
			otherUID := createTestUser(t, r, "sess-other-user@example.com")
			if _, err := r.CreateSession(ctx, &service.SessionRecord{
				SID: "sess-other", UserID: otherUID, CreatedAtMs: 100,
			}); err != nil {
				t.Fatalf("CreateSession other: %v", err)
			}

			if err := r.RevokeSessionsForUser(ctx, uid, 400); err != nil {
				t.Fatalf("RevokeSessionsForUser: %v", err)
			}
			gotB, _ = r.GetSessionBySid(ctx, "sess-b")
			if gotB == nil || gotB.RevokedAtMs != 400 {
				t.Fatalf("RevokeSessionsForUser: sess-b: %+v", gotB)
			}
			// sess-a already-revoked: original timestamp preserved.
			gotA, _ := r.GetSessionBySid(ctx, "sess-a")
			if gotA == nil || gotA.RevokedAtMs != 200 {
				t.Fatalf("RevokeSessionsForUser preserved-original: %+v", gotA)
			}
			// Other user's session untouched.
			gotOther, _ := r.GetSessionBySid(ctx, "sess-other")
			if gotOther == nil || gotOther.RevokedAtMs != 0 {
				t.Fatalf("RevokeSessionsForUser scope leak: %+v", gotOther)
			}
		})

		t.Run("IdentityVerification_CRUD", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid, err := r.CreateUser(ctx, &service.User{Email: "idv@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}

			first := &service.IdentityVerificationRecord{
				VerificationID:    "idv-1",
				UserID:            uid,
				Provider:          "stub",
				ProviderSessionID: "sess-1",
				Status:            service.IDVStatusPending,
				CreatedAt:         100,
				UpdatedAt:         100,
			}
			if err := r.CreateIdentityVerification(ctx, first); err != nil {
				t.Fatalf("Create idv-1: %v", err)
			}

			got, err := r.GetIdentityVerification(ctx, "idv-1")
			if err != nil || got == nil {
				t.Fatalf("Get idv-1: err=%v rec=%#v", err, got)
			}
			if got.UserID != uid || got.Status != service.IDVStatusPending || got.Provider != "stub" {
				t.Fatalf("Get idv-1 mismatch: %+v", got)
			}

			latest, err := r.GetLatestIdentityVerificationForUser(ctx, uid)
			if err != nil || latest == nil || latest.VerificationID != "idv-1" {
				t.Fatalf("Latest after one create: err=%v rec=%#v", err, latest)
			}

			second := &service.IdentityVerificationRecord{
				VerificationID: "idv-2",
				UserID:         uid,
				Provider:       "stub",
				Status:         service.IDVStatusPending,
				CreatedAt:      200,
				UpdatedAt:      200,
			}
			if err := r.CreateIdentityVerification(ctx, second); err != nil {
				t.Fatalf("Create idv-2: %v", err)
			}
			latest, err = r.GetLatestIdentityVerificationForUser(ctx, uid)
			if err != nil || latest == nil || latest.VerificationID != "idv-2" {
				t.Fatalf("Latest after two creates: err=%v rec=%#v", err, latest)
			}

			if err := r.UpdateIdentityVerificationStatus(ctx, "idv-1", service.IDVStatusApproved, "", 300, 300); err != nil {
				t.Fatalf("UpdateStatus approve: %v", err)
			}
			got, _ = r.GetIdentityVerification(ctx, "idv-1")
			if got == nil || got.Status != service.IDVStatusApproved || got.CompletedAt != 300 || got.UpdatedAt != 300 {
				t.Fatalf("after approve: %+v", got)
			}

			if err := r.UpdateIdentityVerificationStatus(ctx, "idv-2", service.IDVStatusRejected, "document_unreadable", 400, 400); err != nil {
				t.Fatalf("UpdateStatus reject: %v", err)
			}
			got, _ = r.GetIdentityVerification(ctx, "idv-2")
			if got == nil || got.Status != service.IDVStatusRejected || got.RejectionReason != "document_unreadable" {
				t.Fatalf("after reject: %+v", got)
			}

			miss, err := r.GetIdentityVerification(ctx, "idv-missing")
			if err != nil || miss != nil {
				t.Fatalf("Get unknown: err=%v rec=%#v", err, miss)
			}

			latest, err = r.GetLatestIdentityVerificationForUser(ctx, "no-such-user")
			if err != nil || latest != nil {
				t.Fatalf("Latest unknown user: err=%v rec=%#v", err, latest)
			}
		})

		t.Run("DeleteUser_RemovesUserAndDurableRecords", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			uid := createTestUser(t, r, "del@example.com")

			// Seed one row of every user-owned type keyed to uid — both the
			// durable identity/auth records AND the short-lived tokens
			// (password-reset, email verification/change, passkey and login
			// challenges, qr sessions, oauth one-time codes), which are now
			// user_id-indexed on every driver (#168) and so must be drained
			// eagerly rather than left to the TTL sweepers. Invitations are
			// the one user-keyed ephemeral not seeded here — Repository
			// exposes no create method for them (they are written via the
			// entdb graph) — but they remain in the entdb drain list. The
			// email-keyed login codes / magic-link tokens carry no user_id
			// and are left to the sweepers by design.
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "del-rt", UserID: uid, ExpiresAt: 9_000_000_000_000}); err != nil {
				t.Fatalf("CreateRefreshToken: %v", err)
			}
			if _, err := r.CreateSession(ctx, &service.SessionRecord{SID: "del-sid", UserID: uid, CreatedAtMs: 100}); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: uid, Provider: "google", ProviderUserID: "g-del", EmailAtLinkTime: "del@example.com", CreatedAt: 100}); err != nil {
				t.Fatalf("CreateOAuthIdentity: %v", err)
			}
			if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{CredentialID: "del-cred", UserID: uid, PublicKey: "pk", CreatedAt: 100}); err != nil {
				t.Fatalf("CreatePasskeyCredential: %v", err)
			}
			if _, err := r.CreateTotpCredential(ctx, &service.TotpCredRecord{UserID: uid, SecretEncrypted: "s", Verified: true, CreatedAt: 100}); err != nil {
				t.Fatalf("CreateTotpCredential: %v", err)
			}
			if _, err := r.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{UserID: uid, CodeHash: "del-rc", CreatedAt: 100}); err != nil {
				t.Fatalf("CreateRecoveryCode: %v", err)
			}
			if err := r.CreateIdentityVerification(ctx, &service.IdentityVerificationRecord{VerificationID: "del-idv", UserID: uid, Provider: "stub", Status: service.IDVStatusPending, CreatedAt: 100, UpdatedAt: 100}); err != nil {
				t.Fatalf("CreateIdentityVerification: %v", err)
			}
			if _, err := r.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{UserID: uid, PhoneNumber: "+14155550133", CodeHash: "del-pvc", ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5}); err != nil {
				t.Fatalf("UpsertPhoneVerificationCode: %v", err)
			}
			// Short-lived, user_id-indexed tokens. As of #168 these are
			// drained eagerly by DeleteUser on every driver rather than left
			// to the TTL sweepers, so each one is asserted gone below.
			if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{TokenHash: "del-prt", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100}); err != nil {
				t.Fatalf("CreatePasswordResetToken: %v", err)
			}
			if err := r.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{TokenHash: "del-evt", UserID: uid, Email: "del@example.com", ExpiresAt: 9_000_000_000_000, CreatedAt: 100}); err != nil {
				t.Fatalf("CreateEmailVerificationToken: %v", err)
			}
			if err := r.CreateEmailChangeToken(ctx, &service.EmailChangeToken{TokenHash: "del-ect", UserID: uid, OldEmail: "del@example.com", NewEmail: "del2@example.com", ExpiresAt: 9_000_000_000_000, CreatedAt: 100}); err != nil {
				t.Fatalf("CreateEmailChangeToken: %v", err)
			}
			pkChalID, err := r.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{Challenge: "del-pkc", UserID: uid, ChallengeType: "authentication", ExpiresAt: 9_000_000_000_000, CreatedAt: 100})
			if err != nil {
				t.Fatalf("CreatePasskeyChallenge: %v", err)
			}
			if _, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{SessionID: "del-qr", Status: "approved", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, UpdatedAt: 100}); err != nil {
				t.Fatalf("CreateQrLoginSession: %v", err)
			}
			if _, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{ChallengeID: "del-lc", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100}); err != nil {
				t.Fatalf("CreateLoginChallenge: %v", err)
			}
			if _, err := r.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{CodeHash: "del-otc", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100}); err != nil {
				t.Fatalf("CreateOAuthOneTimeCode: %v", err)
			}

			// Second user with its own rows to prove scope isolation.
			keepUID := createTestUser(t, r, "keep@example.com")
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "keep-rt", UserID: keepUID, ExpiresAt: 9_000_000_000_000}); err != nil {
				t.Fatalf("CreateRefreshToken keep: %v", err)
			}
			if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{CredentialID: "keep-cred", UserID: keepUID, PublicKey: "pk", CreatedAt: 100}); err != nil {
				t.Fatalf("CreatePasskeyCredential keep: %v", err)
			}

			if err := r.DeleteUser(ctx, uid); err != nil {
				t.Fatalf("DeleteUser: %v", err)
			}

			// User gone.
			if got, err := r.GetUser(ctx, uid); err != nil || got != nil {
				t.Fatalf("GetUser after delete: err=%v rec=%#v", err, got)
			}
			if got, err := r.FindUserByEmail(ctx, "del@example.com"); err != nil || got != nil {
				t.Fatalf("FindUserByEmail after delete: err=%v rec=%#v", err, got)
			}

			// Every durable record gone.
			if rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, "del-rt"); err != nil || rec != nil {
				t.Fatalf("refresh token survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.GetSessionBySid(ctx, "del-sid"); err != nil || rec != nil {
				t.Fatalf("session survived: err=%v rec=%#v", err, rec)
			}
			if recs, err := r.ListOAuthIdentitiesForUser(ctx, uid); err != nil || len(recs) != 0 {
				t.Fatalf("oauth identities survived: err=%v recs=%#v", err, recs)
			}
			if recs, err := r.ListPasskeyCredentials(ctx, uid); err != nil || len(recs) != 0 {
				t.Fatalf("passkey credentials survived: err=%v recs=%#v", err, recs)
			}
			if rec, err := r.GetTotpCredential(ctx, uid); err != nil || rec != nil {
				t.Fatalf("totp credential survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.FindRecoveryCodeByHash(ctx, uid, "del-rc"); err != nil || rec != nil {
				t.Fatalf("recovery code survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.GetLatestIdentityVerificationForUser(ctx, uid); err != nil || rec != nil {
				t.Fatalf("identity verification survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.FindPhoneVerificationCodeByUser(ctx, uid); err != nil || rec != nil {
				t.Fatalf("phone verification code survived: err=%v rec=%#v", err, rec)
			}
			// Every short-lived user-keyed token drained eagerly (#168).
			if rec, err := r.FindPasswordResetTokenByHash(ctx, "del-prt"); err != nil || rec != nil {
				t.Fatalf("password reset token survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.FindEmailVerificationTokenByHash(ctx, "del-evt"); err != nil || rec != nil {
				t.Fatalf("email verification token survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.FindEmailChangeTokenByHash(ctx, "del-ect"); err != nil || rec != nil {
				t.Fatalf("email change token survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.GetPasskeyChallenge(ctx, pkChalID); err != nil || rec != nil {
				t.Fatalf("passkey challenge survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.FindQrLoginSession(ctx, "del-qr"); err != nil || rec != nil {
				t.Fatalf("qr login session survived: err=%v rec=%#v", err, rec)
			}
			if rec, err := r.GetLoginChallengeByChallengeID(ctx, "del-lc"); err != nil || rec != nil {
				t.Fatalf("login challenge survived: err=%v rec=%#v", err, rec)
			}
			// ConsumeOAuthOneTimeCode returns a non-nil record only if the
			// row outlived the drain (it is unconsumed and unexpired at t=200).
			if rec, _ := r.ConsumeOAuthOneTimeCode(ctx, "del-otc", 200); rec != nil {
				t.Fatalf("oauth one-time code survived: rec=%#v", rec)
			}

			// Second user's rows survive.
			if rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, "keep-rt"); err != nil || rec == nil {
				t.Fatalf("keep user's refresh token must survive: err=%v rec=%#v", err, rec)
			}
			if recs, err := r.ListPasskeyCredentials(ctx, keepUID); err != nil || len(recs) != 1 {
				t.Fatalf("keep user's passkey must survive: err=%v recs=%#v", err, recs)
			}

			// Email reusable.
			newID, err := r.CreateUser(ctx, &service.User{Email: "del@example.com", Status: "active", Role: "member"})
			if err != nil {
				t.Fatalf("re-CreateUser with reused email: %v", err)
			}
			if newID == "" || newID == uid {
				t.Fatalf("re-CreateUser: newID=%q must be non-empty and != old uid %q", newID, uid)
			}
		})

		t.Run("DeleteUser_NonExistentIsNoop", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			keepUID := createTestUser(t, r, "untouched@example.com")

			if err := r.DeleteUser(ctx, "no-such-user"); err != nil {
				t.Fatalf("DeleteUser non-existent: want nil, got %v", err)
			}
			if got, err := r.GetUser(ctx, keepUID); err != nil || got == nil {
				t.Fatalf("pre-existing user must survive: err=%v rec=%#v", err, got)
			}
		})
	})

	// ── Sweeper subtests ────────────────────────────────────────────
	// Drivers that signal service.ErrSweepNotImplemented from a
	// DeleteExpired* method are exempted from the deletion assertions
	// (see runSweepCase). Every backend in tree (memory, postgres,
	// entdb) currently implements the real sweep, so the skip branch
	// is unused — the exemption remains for any future backend that
	// lands its CRUD methods ahead of its sweep.

	t.Run("DeleteExpiredPasswordResetTokens", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "prt-sweep@example.com")
		var keptHash string
		seedExpired := func(t *testing.T) {
			t.Helper()
			h := uniqueHash("prt-exp")
			if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
				TokenHash: h, UserID: uid, ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("seed expired: %v", err)
			}
		}
		seedUnexpired := func(t *testing.T) {
			t.Helper()
			keptHash = uniqueHash("prt-keep")
			if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
				TokenHash: keptHash, UserID: uid, ExpiresAt: 100_000, CreatedAt: 200,
			}); err != nil {
				t.Fatalf("seed unexpired: %v", err)
			}
		}
		stillPresent := func(t *testing.T) bool {
			t.Helper()
			got, err := r.FindPasswordResetTokenByHash(ctx, keptHash)
			if err != nil {
				t.Fatalf("Find kept: %v", err)
			}
			return got != nil
		}
		runSweepCase(t, "PasswordResetTokens", r.DeleteExpiredPasswordResetTokens, seedExpired, seedUnexpired, stillPresent)
	})

	t.Run("DeleteExpiredEmailVerificationTokens", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "evt-sweep@example.com")
		var keptHash string
		seedExpired := func(t *testing.T) {
			t.Helper()
			h := uniqueHash("evt-exp")
			if err := r.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
				TokenHash: h, UserID: uid, Email: "e@example.com",
				ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("seed expired: %v", err)
			}
		}
		seedUnexpired := func(t *testing.T) {
			t.Helper()
			keptHash = uniqueHash("evt-keep")
			if err := r.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
				TokenHash: keptHash, UserID: uid, Email: "e@example.com",
				ExpiresAt: 100_000, CreatedAt: 200,
			}); err != nil {
				t.Fatalf("seed unexpired: %v", err)
			}
		}
		stillPresent := func(t *testing.T) bool {
			t.Helper()
			got, err := r.FindEmailVerificationTokenByHash(ctx, keptHash)
			if err != nil {
				t.Fatalf("Find kept: %v", err)
			}
			return got != nil
		}
		runSweepCase(t, "EmailVerificationTokens", r.DeleteExpiredEmailVerificationTokens, seedExpired, seedUnexpired, stillPresent)
	})

	t.Run("DeleteExpiredEmailChangeTokens", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "ect-sweep@example.com")
		var keptHash string
		seedExpired := func(t *testing.T) {
			t.Helper()
			h := uniqueHash("ect-exp")
			if err := r.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
				TokenHash: h, UserID: uid, OldEmail: "old@x", NewEmail: "new@x",
				ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("seed expired: %v", err)
			}
		}
		seedUnexpired := func(t *testing.T) {
			t.Helper()
			keptHash = uniqueHash("ect-keep")
			if err := r.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
				TokenHash: keptHash, UserID: uid, OldEmail: "old@x", NewEmail: "new@x",
				ExpiresAt: 100_000, CreatedAt: 200,
			}); err != nil {
				t.Fatalf("seed unexpired: %v", err)
			}
		}
		stillPresent := func(t *testing.T) bool {
			t.Helper()
			got, err := r.FindEmailChangeTokenByHash(ctx, keptHash)
			if err != nil {
				t.Fatalf("Find kept: %v", err)
			}
			return got != nil
		}
		runSweepCase(t, "EmailChangeTokens", r.DeleteExpiredEmailChangeTokens, seedExpired, seedUnexpired, stillPresent)
	})

	t.Run("DeleteExpiredLoginChallenges", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "lc-sweep@example.com")
		var keptChallengeID string
		seedExpired := func(t *testing.T) {
			t.Helper()
			cid := uniqueHash("lc-exp")
			if _, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: cid, UserID: uid, ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("seed expired: %v", err)
			}
		}
		seedUnexpired := func(t *testing.T) {
			t.Helper()
			keptChallengeID = uniqueHash("lc-keep")
			if _, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: keptChallengeID, UserID: uid, ExpiresAt: 100_000, CreatedAt: 200,
			}); err != nil {
				t.Fatalf("seed unexpired: %v", err)
			}
		}
		stillPresent := func(t *testing.T) bool {
			t.Helper()
			got, err := r.GetLoginChallengeByChallengeID(ctx, keptChallengeID)
			if err != nil {
				t.Fatalf("Get kept: %v", err)
			}
			return got != nil
		}
		runSweepCase(t, "LoginChallenges", r.DeleteExpiredLoginChallenges, seedExpired, seedUnexpired, stillPresent)
	})

	t.Run("DeleteExpiredWebAuthnChallenges", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		var keptNodeID string
		seedExpired := func(t *testing.T) {
			t.Helper()
			if _, err := r.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
				Challenge:     uniqueHash("pkc-exp"),
				ChallengeType: "registration", ExpiresAt: 1_000, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("seed expired: %v", err)
			}
		}
		seedUnexpired := func(t *testing.T) {
			t.Helper()
			id, err := r.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
				Challenge:     uniqueHash("pkc-keep"),
				ChallengeType: "registration", ExpiresAt: 100_000, CreatedAt: 200,
			})
			if err != nil {
				t.Fatalf("seed unexpired: %v", err)
			}
			keptNodeID = id
		}
		stillPresent := func(t *testing.T) bool {
			t.Helper()
			got, err := r.GetPasskeyChallenge(ctx, keptNodeID)
			if err != nil {
				t.Fatalf("Get kept: %v", err)
			}
			return got != nil
		}
		runSweepCase(t, "WebAuthnChallenges", r.DeleteExpiredWebAuthnChallenges, seedExpired, seedUnexpired, stillPresent)
	})

	t.Run("DeleteExpiredQrLoginSessions", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		var keptSessionID string
		seedExpired := func(t *testing.T) {
			t.Helper()
			if _, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: uniqueHash("qr-exp"), Status: "pending",
				ExpiresAt: 1_000, CreatedAt: 100, UpdatedAt: 100,
			}); err != nil {
				t.Fatalf("seed expired: %v", err)
			}
		}
		seedUnexpired := func(t *testing.T) {
			t.Helper()
			keptSessionID = uniqueHash("qr-keep")
			if _, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
				SessionID: keptSessionID, Status: "pending",
				ExpiresAt: 100_000, CreatedAt: 200, UpdatedAt: 200,
			}); err != nil {
				t.Fatalf("seed unexpired: %v", err)
			}
		}
		stillPresent := func(t *testing.T) bool {
			t.Helper()
			got, err := r.FindQrLoginSession(ctx, keptSessionID)
			if err != nil {
				t.Fatalf("Find kept: %v", err)
			}
			return got != nil
		}
		runSweepCase(t, "QrLoginSessions", r.DeleteExpiredQrLoginSessions, seedExpired, seedUnexpired, stillPresent)
	})

	// DeleteExpiredInvitations is not exercised here: Repository exposes no
	// invitation create method to seed one (invitations are written via the
	// entdb graph). The entdb driver's sweeper unit test covers it directly.

	t.Run("DeleteExpired_RejectsNonPositiveLimit", func(t *testing.T) {
		// A non-positive limit could leave the underlying delete
		// statement with no cap. Every Repository implementation must
		// refuse 0 and negative values rather than silently treating
		// them as "delete all", because the sweeper goroutine relies on
		// the per-tick batch size to keep one tenant's GC from starving
		// every other tenant on the same backend.
		ctx := context.Background()
		r := driver.NewRepo(t)
		for _, limit := range []int{0, -1} {
			if err := r.DeleteExpiredPasswordResetTokens(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredPasswordResetTokens limit=%d: want error, got nil", limit)
			}
			if err := r.DeleteExpiredWebAuthnChallenges(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredWebAuthnChallenges limit=%d: want error, got nil", limit)
			}
			if err := r.DeleteExpiredLoginChallenges(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredLoginChallenges limit=%d: want error, got nil", limit)
			}
			if err := r.DeleteExpiredEmailChangeTokens(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredEmailChangeTokens limit=%d: want error, got nil", limit)
			}
			if err := r.DeleteExpiredEmailVerificationTokens(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredEmailVerificationTokens limit=%d: want error, got nil", limit)
			}
			if err := r.DeleteExpiredQrLoginSessions(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredQrLoginSessions limit=%d: want error, got nil", limit)
			}
			if err := r.DeleteExpiredInvitations(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredInvitations limit=%d: want error, got nil", limit)
			}
		}
	})

	// Extended suites: read-your-writes visibility, pagination/limit
	// correctness, fresh-tenant query handling, and value round-trip.
	// These target the cross-backend bug classes (entdb secondary-index
	// lag, query caps, unopened-tenant errors) the per-method CRUD
	// subtests above don't stress.
	runReadYourWritesConformance(t, driver)
	runPaginationConformance(t, driver)
	runFreshTenantConformance(t, driver)
	runRoundTripConformance(t, driver)
	runConcurrencyConformance(t, driver)
	runMutationConformance(t, driver)
	runKeyFidelityConformance(t, driver)
	runSweeperBoundaryConformance(t, driver)
	runFilteringConformance(t, driver)
	runIdempotencyConformance(t, driver)
	runIsolationConformance(t, driver)
	runProjectIsolationConformance(t, driver)
	runGetLatestConformance(t, driver)
}

// uniqueHash returns a per-call unique token-hash string. Tests use
// it to seed distinct rows whose lifetimes are entirely within the
// subtest scope (and won't collide across parallel runs).
var uniqueHashCounter int64

func uniqueHash(prefix string) string {
	uniqueHashCounter++
	return prefix + "-" + time.Now().Format("150405.000000000") + "-" + strconv.FormatInt(uniqueHashCounter, 10)
}

// createTestUser creates a User in the given repository and returns
// the generated ID. Subtests use this to satisfy backend-imposed FK
// constraints before writing user-scoped rows (refresh tokens, passkey
// credentials, etc.). The email is required-unique-per-tenant, so
// callers pass a distinct email per subtest.
func createTestUser(t *testing.T, r service.Repository, email string) string {
	t.Helper()
	id, err := r.CreateUser(context.Background(), &service.User{
		Email:  email,
		Status: "active",
		Role:   "member",
	})
	if err != nil {
		t.Fatalf("createTestUser %q: %v", email, err)
	}
	if id == "" {
		t.Fatalf("createTestUser %q: empty id", email)
	}
	return id
}
