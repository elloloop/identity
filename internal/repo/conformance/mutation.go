package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runMutationConformance covers two mutation edge cases the happy-path
// CRUD subtests skip:
//
//   - Updating a field to its ZERO value (false, "", 0). A patch path
//     that drops zero-valued fields (proto3 default omission, a
//     structpb encode that skips falsey values, a "only set non-empty"
//     guard) silently no-ops the update and leaves the old value — so a
//     user can never un-verify, a TOTP can never be un-marked, a name
//     can never be cleared. Memory and postgres persist the zero value;
//     this catches any backend that doesn't.
//
//   - Re-creating a row under a unique key that was just deleted. The
//     delete must free the unique-key index entry, or the re-create
//     fails with a spurious ALREADY_EXISTS (a tombstone leak).
func runMutationConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/UpdateToZeroValue", func(t *testing.T) {
		t.Run("Bool_TotpVerified_TrueThenFalse", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "zero-totp@example.com")
			id, err := r.CreateTotpCredential(ctx, &service.TotpCredRecord{UserID: uid, SecretEncrypted: "enc", CreatedAt: 100})
			if err != nil {
				t.Fatalf("CreateTotpCredential: %v", err)
			}
			if err := r.UpdateTotpCredential(ctx, id, map[string]any{"verified": true}); err != nil {
				t.Fatalf("Update verified=true: %v", err)
			}
			got, _ := r.GetTotpCredential(ctx, uid)
			if got == nil || !got.Verified {
				t.Fatalf("precondition: verified should be true, got %#v", got)
			}
			if err := r.UpdateTotpCredential(ctx, id, map[string]any{"verified": false}); err != nil {
				t.Fatalf("Update verified=false: %v", err)
			}
			got, _ = r.GetTotpCredential(ctx, uid)
			if got == nil || got.Verified {
				t.Fatalf("update to zero value dropped: verified still true after setting false (%#v)", got)
			}
		})

		t.Run("Bool_UserEmailVerified_TrueThenFalse", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "zero-ev@example.com", Status: "active", Role: "member"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := r.SetUserEmailVerified(ctx, id, 555); err != nil {
				t.Fatalf("SetUserEmailVerified: %v", err)
			}
			got, _ := r.GetUser(ctx, id)
			if got == nil || !got.EmailVerified {
				t.Fatalf("precondition: email_verified should be true, got %#v", got)
			}
			if err := r.UpdateUser(ctx, id, map[string]any{"email_verified": false, "email_verified_at": int64(0)}); err != nil {
				t.Fatalf("UpdateUser email_verified=false: %v", err)
			}
			got, _ = r.GetUser(ctx, id)
			if got == nil || got.EmailVerified {
				t.Fatalf("update to zero value dropped: email_verified still true after setting false (%#v)", got)
			}
		})

		t.Run("String_UserName_ToEmpty", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "zero-name@example.com", Status: "active", Role: "member", Name: "Original"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := r.UpdateUser(ctx, id, map[string]any{"name": ""}); err != nil {
				t.Fatalf("UpdateUser name='': %v", err)
			}
			got, _ := r.GetUser(ctx, id)
			if got == nil || got.Name != "" {
				t.Fatalf("update to zero value dropped: name = %q after setting empty, want empty", got.Name)
			}
		})
	})

	t.Run(driver.Name+"/RecreateAfterDelete", func(t *testing.T) {
		t.Run("RefreshToken_UniqueKeyFreed", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "recreate-rt@example.com")
			id1, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: "reuse-rt", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100,
			})
			if err != nil {
				t.Fatalf("first Create: %v", err)
			}
			if err := r.DeleteRefreshToken(ctx, id1); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if got, _ := r.FindRefreshTokenByHashIncludingConsumed(ctx, "reuse-rt"); got != nil {
				t.Fatalf("token still present after delete: %#v", got)
			}
			id2, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: "reuse-rt", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 200, LastUsedAt: 200,
			})
			if err != nil {
				t.Fatalf("re-create after delete: %v (unique-key index not freed by delete?)", err)
			}
			got, err := r.FindRefreshTokenByHash(ctx, "reuse-rt")
			if err != nil || got == nil {
				t.Fatalf("Find re-created: %v %#v", err, got)
			}
			if got.NodeID != id2 {
				t.Fatalf("Find resolved to stale node %q, want re-created %q", got.NodeID, id2)
			}
		})

		t.Run("LoginChallenge_UniqueKeyFreed", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "recreate-lc@example.com")
			id1, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: "reuse-lc", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
			})
			if err != nil {
				t.Fatalf("first Create: %v", err)
			}
			if err := r.DeleteLoginChallenge(ctx, id1); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: "reuse-lc", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 200,
			}); err != nil {
				t.Fatalf("re-create after delete: %v (unique-key index not freed by delete?)", err)
			}
			got, err := r.GetLoginChallengeByChallengeID(ctx, "reuse-lc")
			if err != nil || got == nil {
				t.Fatalf("Get re-created: %v %#v", err, got)
			}
		})
	})
}
