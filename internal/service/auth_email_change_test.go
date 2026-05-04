package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/passwords"
)

// helper: seed a user with a known password.
func seedUserWithPassword(t *testing.T, repo *fakeRepo, addr, plain string) *User {
	t.Helper()
	pwHash, err := passwords.Hash(plain)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return seedUser(repo, addr, pwHash, "active")
}

// extract the email-change token from the verification email body.
func extractChangeTokenFromBody(t *testing.T, body string) string {
	t.Helper()
	if !strings.Contains(body, "/auth/confirm-email-change?token=") {
		t.Fatalf("body missing confirm-email-change link: %q", body)
	}
	return extractTokenFromLink(t, body)
}

// ── RequestEmailChange ─────────────────────────────────────────────────

func TestRequestEmailChange_Success_BothEmailsSent(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	if err := svc.RequestEmailChange(context.Background(), user.ID, "new@test.com", "Str0ng!Pass1"); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}

	sent := rec.Sent()
	if len(sent) != 2 {
		t.Fatalf("expected 2 emails sent (verify + notice), got %d", len(sent))
	}

	// The order is: verify (to new), then notice (to old).
	verify, notice := sent[0], sent[1]
	if verify.To != "new@test.com" {
		t.Errorf("verify To: got %q, want new@test.com", verify.To)
	}
	if notice.To != "old@test.com" {
		t.Errorf("notice To: got %q, want old@test.com", notice.To)
	}
	if !strings.Contains(verify.Text, "https://app.test/auth/confirm-email-change?token=") {
		t.Errorf("verify body missing confirm link: %q", verify.Text)
	}
	// Security notice MUST NOT carry the token.
	if strings.Contains(notice.Text, "token=") {
		t.Errorf("notice body must not include token: %q", notice.Text)
	}

	// Token persisted with hashed value, unconsumed.
	tok := extractChangeTokenFromBody(t, verify.Text)
	stored, err := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
	if err != nil || stored == nil {
		t.Fatalf("token not stored: err=%v rec=%v", err, stored)
	}
	if stored.UserID != user.ID {
		t.Errorf("stored.UserID: got %q want %q", stored.UserID, user.ID)
	}
	if stored.OldEmail != "old@test.com" || stored.NewEmail != "new@test.com" {
		t.Errorf("stored emails: old=%q new=%q", stored.OldEmail, stored.NewEmail)
	}
	if stored.ConsumedAt != 0 {
		t.Errorf("freshly created token must have consumed_at=0, got %d", stored.ConsumedAt)
	}
}

func TestRequestEmailChange_NewEmailNormalisedLowercase(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	if err := svc.RequestEmailChange(context.Background(), user.ID, "  NEW@Test.COM  ", "Str0ng!Pass1"); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	sent := rec.Sent()
	if len(sent) != 2 {
		t.Fatalf("want 2 emails, got %d", len(sent))
	}
	if sent[0].To != "new@test.com" {
		t.Errorf("verify To: want lowercase trimmed, got %q", sent[0].To)
	}
}

func TestRequestEmailChange_WrongPasswordRejected(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	err := svc.RequestEmailChange(context.Background(), user.ID, "new@test.com", "WrongPass1!")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("wrong password: want ErrUnauthenticated, got %v", err)
	}
	if got := len(rec.Sent()); got != 0 {
		t.Errorf("no emails should be sent on wrong password, got %d", got)
	}
}

func TestRequestEmailChange_NewEmailAlreadyInUseRejected(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	seedUserWithPassword(t, repo, "taken@test.com", "Other!Pass99")
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	err := svc.RequestEmailChange(context.Background(), user.ID, "taken@test.com", "Str0ng!Pass1")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("conflict: want ErrAlreadyExists, got %v", err)
	}
	if got := len(rec.Sent()); got != 0 {
		t.Errorf("no emails should be sent on conflict, got %d", got)
	}
}

func TestRequestEmailChange_SameAsCurrentRejected(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")
	err := svc.RequestEmailChange(context.Background(), user.ID, "OLD@test.com", "Str0ng!Pass1")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("same email: want ErrInvalidArgument, got %v", err)
	}
}

func TestRequestEmailChange_InvalidNewEmailRejected(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")
	err := svc.RequestEmailChange(context.Background(), user.ID, "not-an-email", "Str0ng!Pass1")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("invalid: want ErrInvalidArgument, got %v", err)
	}
}

func TestRequestEmailChange_UnknownUser(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuthSvcWithMailer(t)
	err := svc.RequestEmailChange(context.Background(), "no-such-user", "new@test.com", "Str0ng!Pass1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: want ErrNotFound, got %v", err)
	}
}

// ── ConfirmEmailChange ─────────────────────────────────────────────────

// requestAndExtractChangeToken triggers RequestEmailChange and pulls the
// token out of the verification email body.
func requestAndExtractChangeToken(t *testing.T, svc *AuthService, repo *fakeRepo, rec *recordingTransport, userID, newEmail, password string) string {
	t.Helper()
	rec.Reset()
	if err := svc.RequestEmailChange(context.Background(), userID, newEmail, password); err != nil {
		t.Fatalf("request email change: %v", err)
	}
	sent := rec.Sent()
	if len(sent) < 1 {
		t.Fatalf("no emails sent")
	}
	_ = repo
	return extractChangeTokenFromBody(t, sent[0].Text)
}

func TestConfirmEmailChange_Success(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	// Pre-create a refresh token to verify it gets revoked.
	_, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: "rh-1", UserID: user.ID, ExpiresAt: nowMs() + 60_000,
	})
	if err != nil {
		t.Fatalf("create refresh: %v", err)
	}

	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "new@test.com", "Str0ng!Pass1")

	got, err := svc.ConfirmEmailChange(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}
	if got.Email != "new@test.com" {
		t.Errorf("returned user email: got %q want new@test.com", got.Email)
	}
	if !got.EmailVerified {
		t.Errorf("returned user must be EmailVerified=true")
	}

	// User in repo updated.
	updated, _ := repo.GetUser(context.Background(), user.ID)
	if updated.Email != "new@test.com" {
		t.Errorf("repo email: got %q want new@test.com", updated.Email)
	}
	if !updated.EmailVerified {
		t.Errorf("repo user must be marked verified")
	}
	if updated.EmailVerifiedAt == 0 {
		t.Errorf("EmailVerifiedAt must be set")
	}

	// Token consumed.
	stored, _ := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("token must be consumed; stored=%+v", stored)
	}

	// Refresh tokens revoked.
	if list, _ := repo.refreshTokenSnapshot(); len(list) != 0 {
		t.Errorf("expected refresh tokens cleared, got %d", len(list))
	}
}

func TestConfirmEmailChange_InvalidToken(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuthSvcWithMailer(t)
	_, err := svc.ConfirmEmailChange(context.Background(), "nope-not-a-real-token")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("invalid: want ErrUnauthenticated, got %v", err)
	}
}

func TestConfirmEmailChange_MissingToken(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuthSvcWithMailer(t)
	_, err := svc.ConfirmEmailChange(context.Background(), "")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty: want ErrInvalidArgument, got %v", err)
	}
}

func TestConfirmEmailChange_ExpiredToken(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")
	tok := "expired-tok"
	_ = repo.CreateEmailChangeToken(context.Background(), &EmailChangeToken{
		TokenHash: sha256Hex(tok),
		UserID:    user.ID,
		OldEmail:  user.Email,
		NewEmail:  "new@test.com",
		ExpiresAt: nowMs() - 1000,
		CreatedAt: nowMs() - 7200_000,
	})
	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired: want ErrTokenExpired, got %v", err)
	}
}

func TestConfirmEmailChange_ReplayedToken(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")
	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "new@test.com", "Str0ng!Pass1")

	if _, err := svc.ConfirmEmailChange(context.Background(), tok); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("replay: want ErrUnauthenticated, got %v", err)
	}
}

// TestConfirmEmailChange_NewEmailClaimedBetweenRequestAndConfirm verifies
// the documented "rejected" behaviour: if another user takes the new
// email between the request and confirm calls, ConfirmEmailChange
// returns ErrAlreadyExists and does NOT consume the token (so the user
// can retry should the contention clear before expiry).
func TestConfirmEmailChange_NewEmailClaimedBeforeConfirm(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "new@test.com", "Str0ng!Pass1")

	// Another user grabs the new email between request and confirm.
	seedUserWithPassword(t, repo, "new@test.com", "Other!Pass99")

	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("conflict: want ErrAlreadyExists, got %v", err)
	}
	// Token is intentionally NOT consumed so the user can retry.
	stored, _ := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil {
		t.Fatalf("token should still be stored")
	}
	if stored.ConsumedAt != 0 {
		t.Errorf("token must remain unconsumed on conflict; consumed_at=%d", stored.ConsumedAt)
	}
	// Original user's email is unchanged.
	got, _ := repo.GetUser(context.Background(), user.ID)
	if got.Email != "old@test.com" {
		t.Errorf("user email must be unchanged, got %q", got.Email)
	}
}
