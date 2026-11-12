package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runRecoveryEmailConformance pins the recovery-email store: the code's
// upsert/find/consume, and the rule that an address is held once in a
// project, as one account's primary email or one account's recovery email,
// whichever write comes first.
func runRecoveryEmailConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/RecoveryEmailCode_UpsertFindConsume", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-code@example.com")
		if got, err := r.FindRecoveryEmailCodeByUser(ctx, uid); err != nil || got != nil {
			t.Fatalf("Find before any code = %#v %v, want nil nil", got, err)
		}
		for _, hash := range []string{"old", "new"} {
			if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
				UserID: uid, Email: "spare@example.net", CodeHash: hash,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert %s: %v", hash, err)
			}
		}
		got, err := r.FindRecoveryEmailCodeByUser(ctx, uid)
		if err != nil || got == nil || got.CodeHash != "new" || got.Email != "spare@example.net" || got.MaxAttempts != 5 || got.NodeID == "" {
			t.Fatalf("Find after two upserts = %#v %v", got, err)
		}
		if err := r.IncrementRecoveryEmailCodeAttempts(ctx, got.NodeID); err != nil {
			t.Fatalf("Increment: %v", err)
		}
		if got, _ = r.FindRecoveryEmailCodeByUser(ctx, uid); got == nil || got.AttemptCount != 1 {
			t.Fatalf("after Increment: %#v", got)
		}
		rec, err := r.ConsumeRecoveryEmailCode(ctx, uid, 200)
		if err != nil || rec == nil || rec.ConsumedAt != 200 {
			t.Fatalf("first Consume = %#v %v", rec, err)
		}
		if _, err := r.ConsumeRecoveryEmailCode(ctx, uid, 300); !errors.Is(err, service.ErrRecoveryEmailCodeInvalid) {
			t.Fatalf("replay Consume: want ErrRecoveryEmailCodeInvalid, got %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmailCode_ExpiredIsNotConsumedAndIsSwept", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-expired@example.com")
		if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
			UserID: uid, Email: "spare@example.net", CodeHash: "h", ExpiresAt: 150, CreatedAt: 100,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if _, err := r.ConsumeRecoveryEmailCode(ctx, uid, 150); !errors.Is(err, service.ErrRecoveryEmailCodeInvalid) {
			t.Fatalf("Consume at expiry: want ErrRecoveryEmailCodeInvalid, got %v", err)
		}
		if err := r.DeleteExpiredRecoveryEmailCodes(ctx, 151, 10); err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if got, err := r.FindRecoveryEmailCodeByUser(ctx, uid); err != nil || got != nil {
			t.Fatalf("Find after sweep = %#v %v, want nil nil", got, err)
		}
		if err := r.DeleteExpiredRecoveryEmailCodes(ctx, 151, 0); err == nil {
			t.Fatal("DeleteExpired with limit 0: want an error")
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_AddListRemove", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-owner@example.com")
		if list, err := r.ListRecoveryEmails(ctx, uid); err != nil || len(list) != 0 {
			t.Fatalf("List before any = %v %v", list, err)
		}
		for i, addr := range []string{"first@example.net", "second@example.net"} {
			if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: addr, VerifiedAt: int64(100 + i)}, 2); err != nil {
				t.Fatalf("Add %s: %v", addr, err)
			}
		}
		list, err := r.ListRecoveryEmails(ctx, uid)
		if err != nil || len(list) != 2 || list[0].Email != "first@example.net" || list[1].Email != "second@example.net" ||
			list[0].VerifiedAt != 100 || list[0].UserID != uid {
			t.Fatalf("List = %#v %v, want first then second", list, err)
		}
		// The same address again changes nothing, whatever its case, and is
		// not counted against the cap.
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "FIRST@example.net", VerifiedAt: 999}, 2); err != nil {
			t.Fatalf("re-Add held address: %v", err)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "third@example.net", VerifiedAt: 300}, 2); !errors.Is(err, service.ErrRecoveryEmailLimit) {
			t.Fatalf("Add past the cap: want ErrRecoveryEmailLimit, got %v", err)
		}
		if removed, err := r.RemoveRecoveryEmail(ctx, uid, "First@example.net"); err != nil || !removed {
			t.Fatalf("Remove = %v %v, want true nil", removed, err)
		}
		if removed, err := r.RemoveRecoveryEmail(ctx, uid, "first@example.net"); err != nil || removed {
			t.Fatalf("Remove again = %v %v, want false nil", removed, err)
		}
		if list, _ = r.ListRecoveryEmails(ctx, uid); len(list) != 1 || list[0].Email != "second@example.net" || list[0].VerifiedAt != 101 {
			t.Fatalf("List after remove = %#v", list)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: "no-such-user", Email: "x@example.net", VerifiedAt: 1}, 2); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("Add for a missing user: want ErrNotFound, got %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_OneAccountPerAddress", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		a := createTestUser(t, r, "rec-a@example.com")
		b := createTestUser(t, r, "rec-b@example.com")
		// Another account's primary email, and the account's own.
		for _, addr := range []string{"REC-B@example.com", "rec-a@example.com"} {
			if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: a, Email: addr, VerifiedAt: 1}, 5); !errors.Is(err, service.ErrRecoveryEmailTaken) {
				t.Fatalf("Add primary %s: want ErrRecoveryEmailTaken, got %v", addr, err)
			}
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: a, Email: "shared@example.net", VerifiedAt: 1}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: b, Email: "Shared@example.net", VerifiedAt: 2}, 5); !errors.Is(err, service.ErrRecoveryEmailTaken) {
			t.Fatalf("Add another account's recovery email: want ErrRecoveryEmailTaken, got %v", err)
		}
		if list, _ := r.ListRecoveryEmails(ctx, b); len(list) != 0 {
			t.Fatalf("the refused account holds %#v", list)
		}

		// No account may take a recovery email as its primary email.
		if _, err := r.CreateUser(ctx, &service.User{Email: "SHARED@example.net", Status: "active"}); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("CreateUser on a recovery email: want ErrAlreadyExists, got %v", err)
		}
		if err := r.UpdateUser(ctx, b, map[string]any{"email": "shared@example.net"}); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("UpdateUser onto a recovery email: want ErrAlreadyExists, got %v", err)
		}
		if err := r.UpdateUserEmail(ctx, a, "shared@example.net", 5); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("UpdateUserEmail onto the account's own recovery email: want ErrAlreadyExists, got %v", err)
		}
		if got, _ := r.GetUser(ctx, b); got == nil || got.Email != "rec-b@example.com" {
			t.Fatalf("a refused update changed the user: %#v", got)
		}

		// Released, the address is free again.
		if _, err := r.RemoveRecoveryEmail(ctx, a, "shared@example.net"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := r.UpdateUserEmail(ctx, b, "shared@example.net", 6); err != nil {
			t.Fatalf("UpdateUserEmail onto a released address: %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_DeletedWithTheUser", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-gone@example.com")
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "freed@example.net", VerifiedAt: 1}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
			UserID: uid, Email: "other@example.net", CodeHash: "h", ExpiresAt: 9_000_000_000_000, CreatedAt: 1,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if err := r.DeleteUser(ctx, uid); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if list, err := r.ListRecoveryEmails(ctx, uid); err != nil || len(list) != 0 {
			t.Fatalf("List after delete = %#v %v", list, err)
		}
		if got, err := r.FindRecoveryEmailCodeByUser(ctx, uid); err != nil || got != nil {
			t.Fatalf("code after delete = %#v %v", got, err)
		}
		if _, err := r.CreateUser(ctx, &service.User{Email: "freed@example.net", Status: "active"}); err != nil {
			t.Fatalf("CreateUser on the freed address: %v", err)
		}
	})
}
