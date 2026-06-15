package entdb

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// TestPhoneVerificationCode_MemoryClient exercises the EntDB
// phone-verification-code methods against the memoryEntClient fake
// (which mirrors the real SDK scope's query/get/update/delete behaviour
// via proto reflection). The conformance suite repeats these
// assertions end-to-end against the real EntDB server when
// GATEWAY_ENTDB_ADDRESS is set.
func TestPhoneVerificationCode_MemoryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &entRepository{client: newMemoryEntClient(), projectID: "t"}

	id, err := repo.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
		UserID: "u-1", PhoneNumber: "+14155550123", CodeHash: "h1",
		ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if id == "" {
		t.Fatal("Upsert returned empty node id")
	}

	got, err := repo.FindPhoneVerificationCodeByUser(ctx, "u-1")
	if err != nil || got == nil {
		t.Fatalf("Find: err=%v got=%#v", err, got)
	}
	if got.CodeHash != "h1" || got.PhoneNumber != "+14155550123" || got.MaxAttempts != 5 {
		t.Fatalf("Find returned wrong record: %#v", got)
	}

	// Upsert replaces the previous live code.
	if _, err := repo.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
		UserID: "u-1", PhoneNumber: "+14155550123", CodeHash: "h2",
		ExpiresAt: 9_000_000_000_000, CreatedAt: 200, MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("Upsert replace: %v", err)
	}
	got, _ = repo.FindPhoneVerificationCodeByUser(ctx, "u-1")
	if got == nil || got.CodeHash != "h2" {
		t.Fatalf("Upsert did not replace: %#v", got)
	}

	if err := repo.IncrementPhoneVerificationCodeAttempts(ctx, got.NodeID); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	got, _ = repo.FindPhoneVerificationCodeByUser(ctx, "u-1")
	if got == nil || got.AttemptCount != 1 {
		t.Fatalf("AttemptCount = %#v, want 1", got)
	}

	// Consume succeeds once; replay fails.
	rec, err := repo.ConsumePhoneVerificationCode(ctx, "u-1", 300)
	if err != nil || rec == nil || rec.ConsumedAt != 300 {
		t.Fatalf("Consume: err=%v rec=%#v", err, rec)
	}
	if _, err := repo.ConsumePhoneVerificationCode(ctx, "u-1", 400); !errors.Is(err, service.ErrPhoneCodeInvalid) {
		t.Fatalf("replay Consume: want ErrPhoneCodeInvalid, got %v", err)
	}

	// Unknown user → ErrPhoneCodeInvalid.
	if _, err := repo.ConsumePhoneVerificationCode(ctx, "no-such", 400); !errors.Is(err, service.ErrPhoneCodeInvalid) {
		t.Fatalf("Consume missing: want ErrPhoneCodeInvalid, got %v", err)
	}
}

func TestSetUserPhoneVerified_MemoryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := newMemoryEntClient()
	repo := &entRepository{client: mem, projectID: "t"}

	uid, err := repo.CreateUser(ctx, &service.User{Email: "pv@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := repo.SetUserPhoneVerified(ctx, uid, "+14155550199", 777); err != nil {
		t.Fatalf("SetUserPhoneVerified: %v", err)
	}
	got, err := repo.GetUser(ctx, uid)
	if err != nil || got == nil {
		t.Fatalf("GetUser: err=%v got=%#v", err, got)
	}
	if !got.PhoneVerified || got.PhoneNumber != "+14155550199" || got.PhoneVerifiedAt != 777 {
		t.Fatalf("phone not set: %+v", got)
	}
}

func TestDeleteExpiredPhoneVerificationCodes_MemoryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &entRepository{client: newMemoryEntClient(), projectID: "t"}

	if _, err := repo.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
		UserID: "old", PhoneNumber: "+14155550111", CodeHash: "h", ExpiresAt: 1_000, CreatedAt: 100,
	}); err != nil {
		t.Fatalf("Upsert old: %v", err)
	}
	if _, err := repo.UpsertPhoneVerificationCode(ctx, &service.PhoneVerificationCodeRecord{
		UserID: "fresh", PhoneNumber: "+14155550222", CodeHash: "h", ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
	}); err != nil {
		t.Fatalf("Upsert fresh: %v", err)
	}
	if err := repo.DeleteExpiredPhoneVerificationCodes(ctx, 5_000, 100); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if got, _ := repo.FindPhoneVerificationCodeByUser(ctx, "old"); got != nil {
		t.Fatal("expired code survived the sweep")
	}
	if got, _ := repo.FindPhoneVerificationCodeByUser(ctx, "fresh"); got == nil {
		t.Fatal("fresh code was swept")
	}
	if err := repo.DeleteExpiredPhoneVerificationCodes(ctx, 5_000, 0); err == nil {
		t.Fatal("DeleteExpired with limit 0: want error, got nil")
	}
}
