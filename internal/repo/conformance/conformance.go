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
}

// runSweepCase exercises one DeleteExpired* method. The caller
// supplies seedExpired (creates a row with ExpiresAt < 10_000) and
// seedUnexpired (creates a row with ExpiresAt > 10_000), plus an
// unexpiredStillPresent probe that must return true after the sweep
// for the suite to pass.
//
// The test then asserts:
//   - sweep with beforeMs=100 (below the expired rows' ExpiresAt)
//     deletes nothing,
//   - sweep with beforeMs=10_000, limit=1 deletes exactly 1,
//   - sweep with beforeMs=10_000, limit=10 deletes the remaining 1,
//   - unexpiredStillPresent reports true.
//
// Drivers that return service.ErrSweepNotImplemented on the first
// sweep call are exempt from the data assertions but must still
// return that exact sentinel. As of v0.7.x every shipping backend
// implements the real sweep, so this branch is unused in practice;
// see the package doc for the rationale on keeping it.
func runSweepCase(t *testing.T, label string, sweep func(ctx context.Context, beforeMs int64, limit int) (int, error), seedExpired, seedUnexpired func(t *testing.T), unexpiredStillPresent func(t *testing.T) bool) {
	t.Helper()
	ctx := context.Background()

	seedExpired(t)
	seedExpired(t)
	seedUnexpired(t)

	// First sweep at a time strictly less than the expired rows'
	// ExpiresAt: nothing to delete.
	deleted, err := sweep(ctx, 100, 10)
	if errors.Is(err, service.ErrSweepNotImplemented) {
		t.Logf("%s: backend does not implement sweep — skipping data assertions", label)
		return
	}
	if err != nil {
		t.Fatalf("%s: first sweep: %v", label, err)
	}
	if deleted != 0 {
		t.Fatalf("%s: first sweep deleted %d rows, want 0", label, deleted)
	}

	// Second sweep beyond the expired rows but capped at 1: deletes 1.
	deleted, err = sweep(ctx, 10_000, 1)
	if err != nil {
		t.Fatalf("%s: limit-1 sweep: %v", label, err)
	}
	if deleted != 1 {
		t.Fatalf("%s: limit-1 sweep deleted %d rows, want 1", label, deleted)
	}

	// Final sweep removes the last expired row; unexpired stays.
	deleted, err = sweep(ctx, 10_000, 10)
	if err != nil {
		t.Fatalf("%s: final sweep: %v", label, err)
	}
	if deleted != 1 {
		t.Fatalf("%s: final sweep deleted %d rows, want 1", label, deleted)
	}
	if !unexpiredStillPresent(t) {
		t.Fatalf("%s: unexpired row was deleted by the sweeper", label)
	}

	// One more sweep with the same threshold: nothing left expired.
	deleted, err = sweep(ctx, 10_000, 10)
	if err != nil {
		t.Fatalf("%s: idempotent re-sweep: %v", label, err)
	}
	if deleted != 0 {
		t.Fatalf("%s: idempotent re-sweep deleted %d rows, want 0", label, deleted)
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
				Email:        "alice@example.com",
				Name:         "Alice",
				Status:       "active",
				Role:         "member",
				PasswordHash: "h-1",
				CreatedAt:    now,
				UpdatedAt:    now,
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
			if _, err := r.DeleteExpiredPasswordResetTokens(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredPasswordResetTokens limit=%d: want error, got nil", limit)
			}
			if _, err := r.DeleteExpiredWebAuthnChallenges(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredWebAuthnChallenges limit=%d: want error, got nil", limit)
			}
			if _, err := r.DeleteExpiredLoginChallenges(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredLoginChallenges limit=%d: want error, got nil", limit)
			}
			if _, err := r.DeleteExpiredEmailChangeTokens(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredEmailChangeTokens limit=%d: want error, got nil", limit)
			}
			if _, err := r.DeleteExpiredEmailVerificationTokens(ctx, 1, limit); err == nil {
				t.Errorf("DeleteExpiredEmailVerificationTokens limit=%d: want error, got nil", limit)
			}
		}
	})

	t.Run("Organization_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		ownerID := createTestUser(t, r, "owner@example.com")
		memberID := createTestUser(t, r, "member@example.com")

		// CreateOrganization with empty slug must fail.
		if _, err := r.CreateOrganization(ctx, &service.Organization{DisplayName: "Acme", OwnerUserID: ownerID}); err == nil {
			t.Fatal("CreateOrganization with empty slug: want error, got nil")
		}

		// Create succeeds and assigns an id.
		orgID, err := r.CreateOrganization(ctx, &service.Organization{
			Slug:        "acmecorp",
			DisplayName: "Acme Corp",
			OwnerUserID: ownerID,
			CreatedAtMs: 1_700_000_000_000,
			UpdatedAtMs: 1_700_000_000_000,
		})
		if err != nil {
			t.Fatalf("CreateOrganization: %v", err)
		}
		if orgID == "" {
			t.Fatal("CreateOrganization: empty id")
		}

		// Duplicate slug must reject with ErrAlreadyExists.
		_, err = r.CreateOrganization(ctx, &service.Organization{
			Slug:        "acmecorp",
			DisplayName: "Acme Doppelganger",
			OwnerUserID: ownerID,
		})
		if err == nil {
			t.Fatal("CreateOrganization duplicate slug: want error, got nil")
		}
		if !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("CreateOrganization duplicate slug: want ErrAlreadyExists, got %v", err)
		}

		// GetOrganization by id round-trips every field.
		got, err := r.GetOrganization(ctx, orgID)
		if err != nil || got == nil {
			t.Fatalf("GetOrganization: %v, %#v", err, got)
		}
		if got.ID != orgID || got.Slug != "acmecorp" || got.DisplayName != "Acme Corp" || got.OwnerUserID != ownerID {
			t.Fatalf("GetOrganization round-trip mismatch: %+v", got)
		}
		if got.CreatedAtMs == 0 || got.UpdatedAtMs == 0 {
			t.Fatalf("GetOrganization timestamps unset: %+v", got)
		}

		// GetOrganizationBySlug resolves to the same row.
		bySlug, err := r.GetOrganizationBySlug(ctx, "acmecorp")
		if err != nil || bySlug == nil {
			t.Fatalf("GetOrganizationBySlug: %v, %#v", err, bySlug)
		}
		if bySlug.ID != orgID {
			t.Fatalf("GetOrganizationBySlug id = %q, want %q", bySlug.ID, orgID)
		}

		// Unknown slug returns (nil, nil).
		miss, err := r.GetOrganizationBySlug(ctx, "no-such")
		if err != nil || miss != nil {
			t.Fatalf("GetOrganizationBySlug unknown: %v, %#v", err, miss)
		}

		// AddOrganizationMember for the owner. Stores the role.
		ownerMemID, err := r.AddOrganizationMember(ctx, &service.OrganizationMembership{
			OrganizationID: orgID,
			UserID:         ownerID,
			Role:           "admin",
			CreatedAtMs:    1_700_000_000_000,
		})
		if err != nil || ownerMemID == "" {
			t.Fatalf("AddOrganizationMember owner: %v id=%q", err, ownerMemID)
		}

		// Adding the same (org, user) again must reject.
		_, err = r.AddOrganizationMember(ctx, &service.OrganizationMembership{
			OrganizationID: orgID, UserID: ownerID, Role: "admin",
		})
		if err == nil {
			t.Fatal("AddOrganizationMember duplicate: want error, got nil")
		}
		if !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("AddOrganizationMember duplicate: want ErrAlreadyExists, got %v", err)
		}

		// Add the second user as a regular member.
		if _, err := r.AddOrganizationMember(ctx, &service.OrganizationMembership{
			OrganizationID: orgID,
			UserID:         memberID,
			Role:           "member",
			CreatedAtMs:    1_700_000_000_001,
		}); err != nil {
			t.Fatalf("AddOrganizationMember member: %v", err)
		}

		// A second org the owner does NOT belong to. Used to confirm the
		// listing query is scoped by user_id, not by tenant alone.
		otherOrgID, err := r.CreateOrganization(ctx, &service.Organization{
			Slug:        "betaco",
			DisplayName: "Beta Co",
			OwnerUserID: memberID,
			CreatedAtMs: 1_700_000_001_000,
			UpdatedAtMs: 1_700_000_001_000,
		})
		if err != nil {
			t.Fatalf("CreateOrganization other: %v", err)
		}
		if _, err := r.AddOrganizationMember(ctx, &service.OrganizationMembership{
			OrganizationID: otherOrgID, UserID: memberID, Role: "admin", CreatedAtMs: 1_700_000_001_000,
		}); err != nil {
			t.Fatalf("AddOrganizationMember other-owner: %v", err)
		}

		// ListOrganizationsForUser(owner) returns just the org owner is in.
		ownerOrgs, err := r.ListOrganizationsForUser(ctx, ownerID)
		if err != nil {
			t.Fatalf("ListOrganizationsForUser owner: %v", err)
		}
		if len(ownerOrgs) != 1 {
			t.Fatalf("ListOrganizationsForUser owner: len=%d, want 1; got %+v", len(ownerOrgs), ownerOrgs)
		}
		if ownerOrgs[0].ID != orgID {
			t.Fatalf("ListOrganizationsForUser owner: id=%q, want %q", ownerOrgs[0].ID, orgID)
		}

		// ListOrganizationsForUser(member) returns both orgs.
		memberOrgs, err := r.ListOrganizationsForUser(ctx, memberID)
		if err != nil {
			t.Fatalf("ListOrganizationsForUser member: %v", err)
		}
		if len(memberOrgs) != 2 {
			t.Fatalf("ListOrganizationsForUser member: len=%d, want 2; got %+v", len(memberOrgs), memberOrgs)
		}
		ids := map[string]bool{memberOrgs[0].ID: true, memberOrgs[1].ID: true}
		if !ids[orgID] || !ids[otherOrgID] {
			t.Fatalf("ListOrganizationsForUser member: missing org; got %+v", memberOrgs)
		}

		// Unknown user returns no rows, no error.
		none, err := r.ListOrganizationsForUser(ctx, "no-such-user")
		if err != nil || len(none) != 0 {
			t.Fatalf("ListOrganizationsForUser unknown: err=%v rows=%+v", err, none)
		}
	})
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
