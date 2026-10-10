package service

import (
	"context"
	"errors"
	"testing"
)

// moveEmailAfterRead moves the account to another mailbox, unverified, right
// after the next read of it: a SCIM write landing between a proof's read of
// the account and the write that records the proof.
func moveEmailAfterRead(repo *fakeRepo, to string) {
	repo.afterGetUserHook = func(stored *User) {
		repo.afterGetUserHook = nil
		stored.Email = to
		stored.EmailVerified = false
		stored.EmailVerifiedAt = 0
	}
}

func TestVerifyEmail_EmailChangedAfterTheReadIsRefused(t *testing.T) {
	ctx := context.Background()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "before@test.com", "x", "active")
	if err := svc.SendEmailVerification(ctx, user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	tok := extractTokenFromLink(t, rec.Sent()[0].Text)
	moveEmailAfterRead(repo, "after@test.com")

	if _, err := svc.VerifyEmail(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated, got %v", err)
	}
	got, _ := repo.GetUser(ctx, user.ID)
	if got.Email != "after@test.com" || got.EmailVerified {
		t.Fatalf("the moved address was verified by a link mailed to the old one: %+v", got)
	}
	if stored, _ := repo.FindEmailVerificationTokenByHash(ctx, sha256Hex(tok)); stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("the refused token should be consumed; stored=%+v", stored)
	}
}

func TestExternalProof_EmailChangedAfterTheReadVerifiesNothing(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seeded := seedUser(repo, "before@example.com", hashPW(t, strongPW), "active")
	moveEmailAfterRead(repo, "after@example.com")
	user, err := repo.GetUser(ctx, seeded.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.markEmailVerifiedViaExternalProof(ctx, user, externalProof{address: "before@example.com", method: "oauth"}, nowMs()); err != nil {
		t.Fatalf("markEmailVerifiedViaExternalProof: %v", err)
	}
	if user.EmailVerified || user.PasswordHash == "" {
		t.Fatalf("the in-memory account took a proof that did not land: %+v", user)
	}
	got, _ := repo.GetUser(ctx, seeded.ID)
	if got.Email != "after@example.com" || got.EmailVerified || got.PasswordHash == "" {
		t.Fatalf("a proof of the old address verified the moved account: %+v", got)
	}
}
