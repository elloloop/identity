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

func TestRequestEmailChange_UniquenessLookupErrorFailsClosed(t *testing.T) {
	t.Parallel()
	repo := newErrorRepo()
	user := seedUserWithPassword(t, repo.fakeRepo, "old@test.com", "Str0ng!Pass1")
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)

	repo.failFindUserByEmail = true
	err := svc.RequestEmailChange(context.Background(), user.ID, "new@test.com", "Str0ng!Pass1")
	if err == nil {
		t.Fatal("expected uniqueness lookup error, got nil")
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("no emails should be sent when uniqueness cannot be checked, got %d", got)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if got := len(repo.emailChanges); got != 0 {
		t.Fatalf("no email-change token should be created when uniqueness cannot be checked, got %d", got)
	}
}

func TestRequestEmailChange_UserLookupErrorFailsClosed(t *testing.T) {
	t.Parallel()
	repo := newErrorRepo()
	user := seedUserWithPassword(t, repo.fakeRepo, "old@test.com", "Str0ng!Pass1")
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)

	repo.failGetUser = true
	err := svc.RequestEmailChange(context.Background(), user.ID, "new@test.com", "Str0ng!Pass1")
	if err == nil {
		t.Fatal("expected user lookup error, got nil")
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("no emails should be sent when user lookup fails, got %d", got)
	}
}

func TestRequestEmailChange_TokenCreateFailureDoesNotSendEmails(t *testing.T) {
	t.Parallel()
	repo := newErrorRepo()
	user := seedUserWithPassword(t, repo.fakeRepo, "old@test.com", "Str0ng!Pass1")
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)

	repo.failCreateEmailChangeToken = true
	err := svc.RequestEmailChange(context.Background(), user.ID, "new@test.com", "Str0ng!Pass1")
	if err == nil {
		t.Fatal("expected token create error, got nil")
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("no emails should be sent when token persistence fails, got %d", got)
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

func TestLooksLikeEmailRejectsMalformedAddresses(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"alice@example.com":       true,
		"alice@example":           false,
		"alice example@test.com":  false,
		"alice@example.com\nbcc":  false,
		"@example.com":            false,
		"alice@":                  false,
		"alice@sub.example.com":   true,
		"alice+label@example.com": true,
	}
	for addr, want := range cases {
		if got := looksLikeEmail(addr); got != want {
			t.Fatalf("looksLikeEmail(%q) = %v, want %v", addr, got, want)
		}
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

func TestRequestEmailChange_RejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	cases := []struct {
		name  string
		id    string
		email string
		pass  string
		want  error
	}{
		{"missing_user", "", "new@test.com", "Str0ng!Pass1", ErrUnauthenticated},
		{"missing_email", user.ID, " ", "Str0ng!Pass1", ErrInvalidArgument},
		{"missing_password", user.ID, "new@test.com", "", ErrInvalidArgument},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.RequestEmailChange(context.Background(), tt.id, tt.email, tt.pass)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, err)
			}
			if got := len(rec.Sent()); got != 0 {
				t.Fatalf("no emails should be sent on invalid request, got %d", got)
			}
		})
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

func createEmailChangeToken(t *testing.T, repo Repository, user *User, token, newEmail string) {
	t.Helper()
	if err := repo.CreateEmailChangeToken(context.Background(), &EmailChangeToken{
		TokenHash: sha256Hex(token),
		UserID:    user.ID,
		OldEmail:  user.Email,
		NewEmail:  newEmail,
		ExpiresAt: nowMs() + 60_000,
		CreatedAt: nowMs(),
	}); err != nil {
		t.Fatalf("CreateEmailChangeToken: %v", err)
	}
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

func TestConfirmEmailChange_TokenLookupError(t *testing.T) {
	t.Parallel()
	repo := newErrorRepo()
	svc, _ := newAuthSvcWithMailerForRepo(t, repo)

	repo.failFindEmailChangeToken = true
	_, err := svc.ConfirmEmailChange(context.Background(), "email-change-token")
	if err == nil {
		t.Fatal("expected token lookup error, got nil")
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

func TestConfirmEmailChange_UserMissingLeavesTokenUnconsumed(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := &User{ID: "missing-user", Email: "old@test.com"}
	tok := "missing-user-token"
	createEmailChangeToken(t, repo, user, tok, "new@test.com")

	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	stored, _ := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil {
		t.Fatal("token should remain stored")
	}
	if stored.ConsumedAt != 0 {
		t.Fatalf("token must remain unconsumed when the user is missing, got %d", stored.ConsumedAt)
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

func TestConfirmEmailChange_UniquenessLookupErrorLeavesTokenUnconsumed(t *testing.T) {
	t.Parallel()
	repo := newErrorRepo()
	user := seedUserWithPassword(t, repo.fakeRepo, "old@test.com", "Str0ng!Pass1")
	svc, _ := newAuthSvcWithMailerForRepo(t, repo)

	tok := "email-change-token"
	createEmailChangeToken(t, repo, user, tok, "new@test.com")

	repo.failFindUserByEmail = true
	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	if err == nil {
		t.Fatal("expected uniqueness lookup error, got nil")
	}

	stored, _ := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil {
		t.Fatal("token should remain stored")
	}
	if stored.ConsumedAt != 0 {
		t.Fatalf("token must remain unconsumed when uniqueness cannot be checked, got %d", stored.ConsumedAt)
	}
	got, _ := repo.GetUser(context.Background(), user.ID)
	if got.Email != "old@test.com" {
		t.Fatalf("user email changed despite failed uniqueness check: %q", got.Email)
	}
}

func TestConfirmEmailChange_UpdateFailureLeavesTokenAndSessionsUntouched(t *testing.T) {
	t.Parallel()
	repo := newErrorRepo()
	user := seedUserWithPassword(t, repo.fakeRepo, "old@test.com", "Str0ng!Pass1")
	svc, _ := newAuthSvcWithMailerForRepo(t, repo)
	if _, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: "rh-1", UserID: user.ID, ExpiresAt: nowMs() + 60_000,
	}); err != nil {
		t.Fatalf("create refresh: %v", err)
	}
	tok := "update-failure-token"
	createEmailChangeToken(t, repo, user, tok, "new@test.com")

	repo.failUpdateUserEmail = true
	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	if err == nil {
		t.Fatal("expected email update error, got nil")
	}
	stored, _ := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil {
		t.Fatal("token should remain stored")
	}
	if stored.ConsumedAt != 0 {
		t.Fatalf("token must remain unconsumed when email update fails, got %d", stored.ConsumedAt)
	}
	if list, _ := repo.refreshTokenSnapshot(); len(list) != 1 {
		t.Fatalf("refresh token must remain active when email update fails, got %d tokens", len(list))
	}
	got, _ := repo.GetUser(context.Background(), user.ID)
	if got.Email != "old@test.com" {
		t.Fatalf("user email changed despite update failure: %q", got.Email)
	}
}

func TestConfirmEmailChange_PostUpdateSideEffectFailuresStillReturnUpdatedUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                    string
		failMarkConsumed        bool
		failDeleteRefreshTokens bool
		wantRefreshCount        int
		wantConsumed            bool
	}{
		{"consume_failure", true, false, 0, false},
		{"session_revoke_failure", false, true, 1, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			repo := newErrorRepo()
			user := seedUserWithPassword(t, repo.fakeRepo, "old@test.com", "Str0ng!Pass1")
			svc, _ := newAuthSvcWithMailerForRepo(t, repo)
			if _, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
				TokenHash: "rh-1", UserID: user.ID, ExpiresAt: nowMs() + 60_000,
			}); err != nil {
				t.Fatalf("create refresh: %v", err)
			}
			tok := "side-effect-token-" + tt.name
			createEmailChangeToken(t, repo, user, tok, "new@test.com")
			repo.failMarkEmailChangeConsumed = tt.failMarkConsumed
			repo.failDeleteRefreshTokensForUser = tt.failDeleteRefreshTokens

			got, err := svc.ConfirmEmailChange(context.Background(), tok)
			if err != nil {
				t.Fatalf("ConfirmEmailChange: %v", err)
			}
			if got.Email != "new@test.com" || !got.EmailVerified {
				t.Fatalf("returned user not updated: %+v", got)
			}
			stored, _ := repo.FindEmailChangeTokenByHash(context.Background(), sha256Hex(tok))
			if stored == nil {
				t.Fatal("token should remain queryable")
			}
			if (stored.ConsumedAt > 0) != tt.wantConsumed {
				t.Fatalf("consumed=%v, want %v; token=%+v", stored.ConsumedAt > 0, tt.wantConsumed, stored)
			}
			if list, _ := repo.refreshTokenSnapshot(); len(list) != tt.wantRefreshCount {
				t.Fatalf("refresh token count = %d, want %d", len(list), tt.wantRefreshCount)
			}
			updated, _ := repo.GetUser(context.Background(), user.ID)
			if updated.Email != "new@test.com" || !updated.EmailVerified {
				t.Fatalf("repo user not updated: %+v", updated)
			}
		})
	}
}
