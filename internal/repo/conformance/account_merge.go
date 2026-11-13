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
			if o.Email != "" || o.EmailVerified || o.EmailVerifiedAt != 0 {
				t.Fatalf("retired keeps the moved email or its verification: %#v", o)
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

		t.Run("MovesRecoveryEmailsAndThePhoneClaim", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor := createTestUser(t, r, "am-rec-s@example.com")
			other := createTestUser(t, r, "am-rec-o@example.com")
			third := createTestUser(t, r, "am-rec-t@example.com")
			for user, addrs := range map[string][]string{survivor: {"s-spare@example.net"}, other: {"o-spare@example.net", "o-second@example.net"}} {
				for _, addr := range addrs {
					if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: user, Email: addr, VerifiedAt: 1}, 5); err != nil {
						t.Fatalf("AddRecoveryEmail %s: %v", addr, err)
					}
				}
			}
			const number = "+14155550142"
			if _, err := r.ClaimPhoneNumber(ctx, other, number, 10, 0); err != nil {
				t.Fatalf("ClaimPhoneNumber: %v", err)
			}

			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, MovePhone: true, RecoveryEmailsMax: 3, AtMs: 1000}); err != nil {
				t.Fatalf("ApplyAccountMerge: %v", err)
			}
			list, err := r.ListRecoveryEmails(ctx, survivor)
			if err != nil || len(list) != 3 {
				t.Fatalf("survivor's recovery emails = %#v %v, want all three", list, err)
			}
			if gone, _ := r.ListRecoveryEmails(ctx, other); len(gone) != 0 {
				t.Fatalf("the retired account keeps recovery emails: %#v", gone)
			}
			if holder, err := r.FindRecoveryEmailHolder(ctx, "o-spare@example.net"); err != nil || holder == nil || holder.UserID != survivor {
				t.Fatalf("holder of a moved address = %#v %v, want the survivor", holder, err)
			}
			s, _ := r.GetUser(ctx, survivor)
			o, _ := r.GetUser(ctx, other)
			if s.PhoneNumber != number || !s.PhoneVerified || s.PhoneVerifiedAt != 10 {
				t.Fatalf("survivor's phone after merge: %q %t %d", s.PhoneNumber, s.PhoneVerified, s.PhoneVerifiedAt)
			}
			if o.PhoneNumber != "" || o.PhoneVerified {
				t.Fatalf("the retired account keeps the moved phone: %q %t", o.PhoneNumber, o.PhoneVerified)
			}
			// The claim moved with the number: another account still may not
			// take it, and the survivor holds it already.
			if _, err := r.ClaimPhoneNumber(ctx, third, number, 2000, 0); !errors.Is(err, service.ErrPhoneNumberTaken) {
				t.Fatalf("a third account claims the moved number: want ErrPhoneNumberTaken, got %v", err)
			}
			if previous, err := r.ClaimPhoneNumber(ctx, survivor, number, 2000, 0); err != nil || previous != "" {
				t.Fatalf("the survivor claims its own number = %q %v", previous, err)
			}
		})

		t.Run("RecoveryEmailsPastTheCapRefuseTheMerge", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor := createTestUser(t, r, "am-cap-s@example.com")
			other := createTestUser(t, r, "am-cap-o@example.com")
			for user, addr := range map[string]string{survivor: "cap-s@example.net", other: "cap-o@example.net"} {
				if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: user, Email: addr, VerifiedAt: 1}, 5); err != nil {
					t.Fatalf("AddRecoveryEmail: %v", err)
				}
			}
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, RecoveryEmailsMax: 1, AtMs: 1000}); !errors.Is(err, service.ErrRecoveryEmailLimit) {
				t.Fatalf("want ErrRecoveryEmailLimit, got %v", err)
			}
			if o, _ := r.GetUser(ctx, other); o.Status != "active" {
				t.Fatalf("a refused merge retired the other account: %#v", o)
			}
			if list, _ := r.ListRecoveryEmails(ctx, other); len(list) != 1 {
				t.Fatalf("a refused merge moved recovery emails: %#v", list)
			}
		})

		t.Run("ReleasesTheRetiredNumberWhenTheSurvivorHasOne", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor := createTestUser(t, r, "am-ph-s@example.com")
			other := createTestUser(t, r, "am-ph-o@example.com")
			third := createTestUser(t, r, "am-ph-t@example.com")
			if _, err := r.ClaimPhoneNumber(ctx, survivor, "+14155550143", 10, 0); err != nil {
				t.Fatalf("ClaimPhoneNumber survivor: %v", err)
			}
			if _, err := r.ClaimPhoneNumber(ctx, other, "+14155550144", 10, 0); err != nil {
				t.Fatalf("ClaimPhoneNumber other: %v", err)
			}
			// MovePhone was decided while the survivor had no number; it has one.
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, MovePhone: true, RecoveryEmailsMax: 5, AtMs: 1000}); !errors.Is(err, service.ErrMergeConflict) {
				t.Fatalf("MovePhone onto a survivor with a phone: want ErrMergeConflict, got %v", err)
			}
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, RecoveryEmailsMax: 5, AtMs: 1000}); err != nil {
				t.Fatalf("ApplyAccountMerge: %v", err)
			}
			if s, _ := r.GetUser(ctx, survivor); s.PhoneNumber != "+14155550143" {
				t.Fatalf("survivor's phone = %q, want its own", s.PhoneNumber)
			}
			if previous, err := r.ClaimPhoneNumber(ctx, third, "+14155550144", 2000, 0); err != nil || previous != "" {
				t.Fatalf("the retired account's number is not free: %q %v", previous, err)
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
