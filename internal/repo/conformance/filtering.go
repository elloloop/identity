package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runFilteringConformance covers multi-field filter AND-semantics and
// per-user scoping — the read paths where a backend that matches on a
// subset of the filter, or ignores the owning user, leaks one
// principal's rows to another. These are correctness AND security
// checks: a recovery code or credential resolving across users is an
// account-takeover primitive.
func runFilteringConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/MultiFieldFilter", func(t *testing.T) {
		// FindRecoveryCodeByHash filters on (user_id AND code_hash). A
		// backend that matches code_hash alone would let user B redeem
		// user A's recovery code.
		t.Run("RecoveryCode_UserAndHash_Anded", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userA := createTestUser(t, r, "mf-rc-a@example.com")
			userB := createTestUser(t, r, "mf-rc-b@example.com")
			if _, err := r.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{UserID: userA, CodeHash: "hash-A", CreatedAt: 100}); err != nil {
				t.Fatalf("Create A: %v", err)
			}
			if _, err := r.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{UserID: userB, CodeHash: "hash-B", CreatedAt: 100}); err != nil {
				t.Fatalf("Create B: %v", err)
			}
			// Correct owner+hash resolves.
			if got, err := r.FindRecoveryCodeByHash(ctx, userA, "hash-A"); err != nil || got == nil {
				t.Fatalf("Find(A, hash-A): err=%v got=%#v, want a row", err, got)
			}
			// Wrong owner for a real hash must NOT resolve (cross-user leak).
			if got, err := r.FindRecoveryCodeByHash(ctx, userB, "hash-A"); err != nil || got != nil {
				t.Fatalf("cross-user leak: Find(userB, hash-A) returned %#v (err=%v); user A's recovery code must not resolve for user B", got, err)
			}
			// Right owner, wrong hash must not resolve.
			if got, err := r.FindRecoveryCodeByHash(ctx, userA, "hash-B"); err != nil || got != nil {
				t.Fatalf("filter not ANDed: Find(userA, hash-B) returned %#v (err=%v), want nil", got, err)
			}
		})

		// FindUserByProviderID filters on (provider AND provider_user_id).
		// Cross combinations of two real links must not resolve.
		t.Run("OAuthIdentity_ProviderAndSub_Anded", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uA, _ := r.CreateUser(ctx, &service.User{Email: "mf-oa-a@example.com", Status: "active", Role: "member"})
			uB, _ := r.CreateUser(ctx, &service.User{Email: "mf-oa-b@example.com", Status: "active", Role: "member"})
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: uA, Provider: "google", ProviderUserID: "s1", CreatedAt: 100}); err != nil {
				t.Fatalf("Create A: %v", err)
			}
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: uB, Provider: "microsoft", ProviderUserID: "s2", CreatedAt: 100}); err != nil {
				t.Fatalf("Create B: %v", err)
			}
			if got, err := r.FindUserByProviderID(ctx, "google", "s2"); err != nil || got != nil {
				t.Fatalf("filter not ANDed: Find(google, s2) returned %#v (err=%v), want nil (no link has that pair)", got, err)
			}
			if got, err := r.FindUserByProviderID(ctx, "microsoft", "s1"); err != nil || got != nil {
				t.Fatalf("filter not ANDed: Find(microsoft, s1) returned %#v (err=%v), want nil", got, err)
			}
		})
	})

	t.Run(driver.Name+"/FilterScoping", func(t *testing.T) {
		// A user-scoped list must return ONLY the owning user's rows,
		// even when other users have rows of the same type in the tenant.
		t.Run("PasskeyCredentials_PerUser", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userA := createTestUser(t, r, "scope-pk-a@example.com")
			userB := createTestUser(t, r, "scope-pk-b@example.com")
			for i := 0; i < 3; i++ {
				if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{CredentialID: fmt.Sprintf("a-cred-%d", i), UserID: userA, PublicKey: "pk"}); err != nil {
					t.Fatalf("Create A %d: %v", i, err)
				}
			}
			if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{CredentialID: "b-cred-0", UserID: userB, PublicKey: "pk"}); err != nil {
				t.Fatalf("Create B: %v", err)
			}
			a, err := r.ListPasskeyCredentials(ctx, userA)
			if err != nil {
				t.Fatalf("List A: %v", err)
			}
			if len(a) != 3 {
				t.Fatalf("ListPasskeyCredentials(A) = %d rows, want 3 (scope leak or loss)", len(a))
			}
			for _, c := range a {
				if c.UserID != userA {
					t.Fatalf("scope leak: ListPasskeyCredentials(A) returned a row owned by %q", c.UserID)
				}
			}
			b, err := r.ListPasskeyCredentials(ctx, userB)
			if err != nil {
				t.Fatalf("List B: %v", err)
			}
			if len(b) != 1 {
				t.Fatalf("ListPasskeyCredentials(B) = %d rows, want 1", len(b))
			}
		})

		t.Run("OAuthIdentities_PerUser", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			userA, _ := r.CreateUser(ctx, &service.User{Email: "scope-oa-a@example.com", Status: "active", Role: "member"})
			userB, _ := r.CreateUser(ctx, &service.User{Email: "scope-oa-b@example.com", Status: "active", Role: "member"})
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: userA, Provider: "google", ProviderUserID: "a-1", CreatedAt: 100}); err != nil {
				t.Fatalf("Create A1: %v", err)
			}
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: userA, Provider: "github", ProviderUserID: "a-2", CreatedAt: 100}); err != nil {
				t.Fatalf("Create A2: %v", err)
			}
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: userB, Provider: "google", ProviderUserID: "b-1", CreatedAt: 100}); err != nil {
				t.Fatalf("Create B1: %v", err)
			}
			a, err := r.ListOAuthIdentitiesForUser(ctx, userA)
			if err != nil {
				t.Fatalf("List A: %v", err)
			}
			if len(a) != 2 {
				t.Fatalf("ListOAuthIdentitiesForUser(A) = %d, want 2", len(a))
			}
			for _, oi := range a {
				if oi.UserID != userA {
					t.Fatalf("scope leak: ListOAuthIdentitiesForUser(A) returned a row owned by %q", oi.UserID)
				}
			}
		})
	})
}
