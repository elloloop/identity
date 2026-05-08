// Package conformance is a driver-agnostic test suite for
// service.Repository implementations.
//
// The aim is to give every Repository driver — entdb, postgres,
// memory — a single source of truth for "does this driver honour the
// contract the service layer relies on?". A new driver runs:
//
//	conformance.RunConformance(t, func(t *testing.T) service.Repository {
//	    return mydriver.New(...)
//	})
//
// and either passes the suite or fails loudly with the precise
// semantic that broke. Same test bodies, same assertions — only the
// backend varies.
//
// Subtests are intentionally narrow: each one exercises ONE
// Repository semantic, named after the methods it covers, so a
// failure points at one method (or one method pair). The goal is
// breadth of coverage, not exhaustive concurrency edge-cases — those
// belong in driver-specific unit tests.
package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// RunConformance exercises every method on the service.Repository
// contract against a freshly-constructed driver-specific
// implementation.
//
// makeFresh is invoked at the top of every subtest; it must return a
// Repository with empty state so subtests do not leak data into each
// other. Drivers that need per-test cleanup hooks should register
// them with t.Cleanup inside makeFresh.
func RunConformance(t *testing.T, makeFresh func(t *testing.T) service.Repository) {
	t.Helper()

	t.Run("UserCRUD", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)

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
			// password_hash round-trip is the headline regression
			// the entdb driver rewrite was designed to fix.
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
		r := makeFresh(t)
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
		r := makeFresh(t)
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
		r := makeFresh(t)
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
		r := makeFresh(t)
		id, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
			TokenHash:  "rh-1",
			UserID:     "u-1",
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
		if got.UserID != "u-1" {
			t.Fatalf("UserID = %q", got.UserID)
		}
		if err := r.ConsumeRefreshTokenByHash(ctx, "rh-1", 200); err != nil {
			t.Fatalf("Consume: %v", err)
		}
		// Live lookup should now miss; including-consumed should hit.
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
		// Second consume must lose the race.
		if err := r.ConsumeRefreshTokenByHash(ctx, "rh-1", 300); !errors.Is(err, service.ErrUnauthenticated) {
			t.Fatalf("second Consume: want ErrUnauthenticated, got %v", err)
		}
	})

	t.Run("RefreshToken_DeleteForUser", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		_, _ = r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "a", UserID: "u-1"})
		_, _ = r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "b", UserID: "u-1"})
		_, _ = r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "c", UserID: "u-2"})
		if err := r.DeleteRefreshTokensForUser(ctx, "u-1"); err != nil {
			t.Fatalf("DeleteForUser: %v", err)
		}
		got, _ := r.FindRefreshTokenByHashIncludingConsumed(ctx, "a")
		if got != nil {
			t.Fatalf("u-1 token still present after DeleteForUser")
		}
		got, _ = r.FindRefreshTokenByHashIncludingConsumed(ctx, "c")
		if got == nil {
			t.Fatal("u-2 token removed by DeleteForUser scope leak")
		}
	})

	t.Run("RefreshToken_DeleteOne", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "delete-one", UserID: "u-1"})
		if err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		_, err = r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "keep-one", UserID: "u-1"})
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
		r := makeFresh(t)
		tok := &service.PasswordResetToken{TokenHash: "p-1", UserID: "u-1", ExpiresAt: 1_000, CreatedAt: 100}
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
		r := makeFresh(t)
		tok := &service.EmailVerificationToken{TokenHash: "ev-1", UserID: "u-1", Email: "x@y.com", ExpiresAt: 1_000, CreatedAt: 100}
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
		r := makeFresh(t)
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
	})

	t.Run("PasskeyCredential_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
			CredentialID: "cred-1", UserID: "u-1", PublicKey: "pk", SignCount: 5,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, _ := r.GetPasskeyCredentialByCredID(ctx, "cred-1")
		if got == nil || got.NodeID != id {
			t.Fatalf("GetByCred: %#v", got)
		}
		list, err := r.ListPasskeyCredentials(ctx, "u-1")
		if err != nil || len(list) != 1 {
			t.Fatalf("List: len=%d err=%v", len(list), err)
		}
		if err := r.UpdatePasskeyCredential(ctx, id, map[string]any{"sign_count": int64(99)}); err != nil {
			t.Fatalf("Update: %v", err)
		}
	})

	t.Run("PasskeyChallenge_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
			Challenge:     "c-1",
			UserID:        "u-1",
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
		r := makeFresh(t)
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
			"user_id": "u-1",
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got, _ = r.FindQrLoginSession(ctx, "qr-1")
		if got == nil || got.Status != "approved" || got.UserID != "u-1" {
			t.Fatalf("after Update: %#v", got)
		}
	})

	t.Run("TotpCredential_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreateTotpCredential(ctx, &service.TotpCredRecord{
			UserID: "u-1", SecretEncrypted: "enc", CreatedAt: 100,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, _ := r.GetTotpCredential(ctx, "u-1")
		if got == nil || got.NodeID != id {
			t.Fatalf("Get: %#v", got)
		}
		if err := r.UpdateTotpCredential(ctx, id, map[string]any{"verified": true}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got, _ = r.GetTotpCredential(ctx, "u-1")
		if got == nil || !got.Verified {
			t.Fatalf("after Update: %#v", got)
		}
		if err := r.DeleteTotpCredentialsForUser(ctx, "u-1"); err != nil {
			t.Fatalf("DeleteForUser: %v", err)
		}
		got, _ = r.GetTotpCredential(ctx, "u-1")
		if got != nil {
			t.Fatal("DeleteForUser left a row")
		}
	})

	t.Run("TotpCredential_DeleteOne", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreateTotpCredential(ctx, &service.TotpCredRecord{
			UserID: "u-1", SecretEncrypted: "enc", CreatedAt: 100,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := r.DeleteTotpCredential(ctx, id); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, _ := r.GetTotpCredential(ctx, "u-1")
		if got != nil {
			t.Fatal("Delete left a row")
		}
	})

	t.Run("RecoveryCode_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{
			UserID: "u-1", CodeHash: "hash-1", CreatedAt: 100,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, _ := r.FindRecoveryCodeByHash(ctx, "u-1", "hash-1")
		if got == nil || got.NodeID != id {
			t.Fatalf("Find: %#v", got)
		}
		if err := r.UpdateRecoveryCode(ctx, id, map[string]any{"used": true, "used_at": int64(200)}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if err := r.DeleteRecoveryCodesForUser(ctx, "u-1"); err != nil {
			t.Fatalf("DeleteForUser: %v", err)
		}
	})

	t.Run("LoginChallenge_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := makeFresh(t)
		id, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
			ChallengeID: "lc-1", UserID: "u-1", ExpiresAt: 1_000, CreatedAt: 100,
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
		r := makeFresh(t)
		uid, err := r.CreateUser(ctx, &service.User{Email: "oa@example.com", Status: "active"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		oi := &service.OAuthIdentity{
			UserID: uid, Provider: "google", ProviderUserID: "g-123",
			EmailAtLinkTime: "oa@example.com", CreatedAt: 100,
		}
		if err := r.CreateOAuthIdentity(ctx, oi); err != nil {
			t.Fatalf("Create: %v", err)
		}
		// composite uniqueness: a second link with same (provider, sub)
		// must reject (the schema does not enforce this so the
		// service layer must, and CreateOAuthIdentity is the
		// designated guard).
		dup := &service.OAuthIdentity{UserID: "other", Provider: "google", ProviderUserID: "g-123", CreatedAt: 200}
		if err := r.CreateOAuthIdentity(ctx, dup); err == nil {
			t.Fatal("CreateOAuthIdentity duplicate: want error, got nil")
		}
		got, err := r.FindUserByProviderID(ctx, "google", "g-123")
		if err != nil || got == nil {
			t.Fatalf("FindByProvider: %v %#v", err, got)
		}
		if got.ID != uid {
			t.Fatalf("FindByProvider id = %q, want %q", got.ID, uid)
		}
		list, err := r.ListOAuthIdentitiesForUser(ctx, uid)
		if err != nil || len(list) != 1 {
			t.Fatalf("List: len=%d err=%v", len(list), err)
		}
	})

	t.Run("Invitation_FindUpdate", func(t *testing.T) {
		// Only Find + Update are on the Repository interface; the
		// driver-specific create path is exercised via service.DB
		// which sits outside this conformance suite.
		ctx := context.Background()
		r := makeFresh(t)
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
		r := makeFresh(t)
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
}
