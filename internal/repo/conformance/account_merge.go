package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAccountMergeConformance pins ApplyAccountMerge across drivers: one
// transaction that retires the other account, moves what it is asked to, and
// refuses (changing nothing) when either account is no longer active and
// unmerged.
func runAccountMergeConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/AccountMerge", func(t *testing.T) {
		t.Run("MovesCredentialsEmailAndTearsDownSessions", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Username: "am-carol"})
			if err != nil {
				t.Fatal(err)
			}
			other, err := r.CreateUser(ctx, &service.User{
				Status: "active", Role: "member", Email: "am-carol@example.com",
				EmailVerified: true, EmailVerifiedAt: 500,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: other, Provider: "google", ProviderUserID: "am-g-1", CreatedAt: 1}); err != nil {
				t.Fatalf("CreateOAuthIdentity: %v", err)
			}
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "am-rt-1", UserID: other, ExpiresAt: 9_000_000_000_000, CreatedAt: 1, LastUsedAt: 1}); err != nil {
				t.Fatalf("CreateRefreshToken: %v", err)
			}
			if _, err := r.CreateSession(ctx, &service.SessionRecord{SID: "am-sid-live", UserID: other, CreatedAtMs: 1}); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			if _, err := r.CreateSession(ctx, &service.SessionRecord{SID: "am-sid-old", UserID: other, CreatedAtMs: 1}); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			if err := r.RevokeSession(ctx, "am-sid-old", 700); err != nil {
				t.Fatalf("RevokeSession: %v", err)
			}

			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, MoveEmail: true, AtMs: 1000}); err != nil {
				t.Fatalf("ApplyAccountMerge: %v", err)
			}
			s, _ := r.GetUser(ctx, survivor)
			o, _ := r.GetUser(ctx, other)
			if s.Email != "am-carol@example.com" || !s.EmailVerified || s.EmailVerifiedAt != 500 || s.Username != "am-carol" {
				t.Fatalf("survivor after merge: %#v", s)
			}
			if o.Email != "" {
				t.Fatalf("retired keeps the moved email: %q", o.Email)
			}
			linked, err := r.FindUserByProviderID(ctx, "google", "am-g-1")
			if err != nil || linked == nil || linked.ID != survivor {
				t.Fatalf("provider identity after merge: %#v %v", linked, err)
			}
			if rt, err := r.FindRefreshTokenByHash(ctx, "am-rt-1"); err != nil || rt != nil {
				t.Fatalf("retired refresh token must be gone: %#v %v", rt, err)
			}
			if live, err := r.GetSessionBySid(ctx, "am-sid-live"); err != nil || live == nil || live.RevokedAtMs != 1000 {
				t.Fatalf("live session after merge: %#v %v", live, err)
			}
			if old, err := r.GetSessionBySid(ctx, "am-sid-old"); err != nil || old == nil || old.RevokedAtMs != 700 {
				t.Fatalf("an already-revoked session keeps its time: %#v %v", old, err)
			}
		})

		t.Run("SurvivorFieldFilledMeanwhileIsAConflict", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor, _ := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Email: "am-d@example.com"})
			other, _ := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Username: "am-dave"})
			// MoveEmail was decided while the survivor had no email; it has one now.
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, MoveEmail: true, AtMs: 1}); !errors.Is(err, service.ErrMergeConflict) {
				t.Fatalf("want ErrMergeConflict, got %v", err)
			}
			if o, _ := r.GetUser(ctx, other); o.Status != "active" {
				t.Fatalf("a conflicting merge changed the other account: %#v", o)
			}
		})

		t.Run("MovesAndRetires", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Email: "am-s@example.com", AccountAddress: "am-s@accounts.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			other, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Username: "am-bob", PasswordHash: "hash", AccountAddress: "am-bob@accounts.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{
				SurvivorID: survivor, OtherID: other,
				MoveUsername: true, MovePassword: true, SwapAddress: true, AtMs: 1000,
			}); err != nil {
				t.Fatalf("ApplyAccountMerge: %v", err)
			}
			s, _ := r.GetUser(ctx, survivor)
			o, _ := r.GetUser(ctx, other)
			if s.Username != "am-bob" || s.PasswordHash != "hash" || s.AccountAddress != "am-bob@accounts.example.com" {
				t.Fatalf("survivor after merge: %#v", s)
			}
			if o.Status != "deactivated" || o.MergedIntoUserID != survivor || o.Username != "" || o.AccountAddress != "am-s@accounts.example.com" {
				t.Fatalf("retired after merge: %#v", o)
			}
			// A second merge of the same account is a conflict and changes nothing.
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, AtMs: 2000}); !errors.Is(err, service.ErrMergeConflict) {
				t.Fatalf("second merge: want ErrMergeConflict, got %v", err)
			}
			// Nor can the survivor be merged into the retired account.
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: other, OtherID: survivor, AtMs: 3000}); !errors.Is(err, service.ErrMergeConflict) {
				t.Fatalf("reverse merge: want ErrMergeConflict, got %v", err)
			}
			s2, _ := r.GetUser(ctx, survivor)
			if s2.Status != "active" || s2.Username != "am-bob" {
				t.Fatalf("a refused merge changed the survivor: %#v", s2)
			}
		})
	})
}
