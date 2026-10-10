package service

import (
	"context"
	"errors"
	"html"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
)

// recordingTransport captures every email.Send call so tests can
// assert on what would have been delivered.
type recordingTransport struct {
	mu   sync.Mutex
	sent []email.Message
	fail error
}

func (r *recordingTransport) Send(_ context.Context, m email.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.sent = append(r.sent, m)
	return nil
}

func (r *recordingTransport) Sent() []email.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]email.Message, len(r.sent))
	copy(out, r.sent)
	return out
}

func (r *recordingTransport) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = nil
}

// newAuthSvcWithMailer constructs an AuthService backed by a fakeRepo
// and a recording transport so tests can assert on outbound mail.
func newAuthSvcWithMailer(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	repo := newFakeRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	return svc, repo, rec
}

func newAuthSvcWithMailerForRepo(t *testing.T, repo Repository) (*AuthService, *recordingTransport) {
	t.Helper()
	cfg := testConfig()
	cfg.AppBaseURL = "https://app.test"
	cfg.EmailTokenExpirySeconds = 3600
	cfg.SMTPFrom = "no-reply@test.local"
	kr := testKeyRing(t)
	pkSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	rec := &recordingTransport{}
	svc := NewAuthService(repo, cfg, kr, pkSvc,
		audit.NewLogger(nil, "test", zap.NewNop()),
		testTotpKey(), testTotpRecoveryPepper(), rec, nil, zap.NewNop())
	return svc, rec
}

// extractTokenFromLink pulls the ?token=... query value from a URL.
// We don't bother with full URL parsing — the templates always produce
// the literal "?token=" prefix, and the token is hex, so it ends at the
// next parameter, whitespace, or quote.
func extractTokenFromLink(t *testing.T, body string) string {
	t.Helper()
	idx := strings.Index(body, "token=")
	if idx == -1 {
		t.Fatalf("token= not found in body: %q", body)
	}
	rest := body[idx+len("token="):]
	end := len(rest)
	for i, ch := range rest {
		if ch == '&' || ch == ' ' || ch == '\n' || ch == '\r' || ch == '"' || ch == '<' {
			end = i
			break
		}
	}
	return rest[:end]
}

// linkInBody returns the whole link in a plain-text email body that starts
// with prefix, up to the next whitespace.
func linkInBody(t *testing.T, body, prefix string) string {
	t.Helper()
	idx := strings.Index(body, prefix)
	if idx == -1 {
		t.Fatalf("no link starting %q in body: %q", prefix, body)
	}
	link := body[idx:]
	if end := strings.IndexAny(link, " \r\n"); end != -1 {
		link = link[:end]
	}
	return link
}

// ── RequestPasswordReset ───────────────────────────────────────────────

func TestRequestPasswordReset_Success(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("RequestPasswordReset err: %v", err)
	}
	sent := rec.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(sent))
	}
	if sent[0].To != "alice@test.com" {
		t.Errorf("To: got %q, want alice@test.com", sent[0].To)
	}
	token := extractTokenFromLink(t, sent[0].Text)
	if len(token) < 32 {
		t.Errorf("token too short: %q", token)
	}
	if !strings.Contains(sent[0].Text, "https://app.test/auth/reset-password?token=") {
		t.Errorf("text body missing reset URL: %q", sent[0].Text)
	}
	// Token persists with hashed value.
	tokenHash := sha256Hex(token)
	rec2, err := repo.FindPasswordResetTokenByHash(context.Background(), tokenHash)
	if err != nil || rec2 == nil {
		t.Fatalf("token not stored: err=%v rec=%v", err, rec2)
	}
	if rec2.UserID != user.ID {
		t.Errorf("token user_id: got %q, want %q", rec2.UserID, user.ID)
	}
	if rec2.ConsumedAt != 0 {
		t.Errorf("freshly created token should have consumed_at=0, got %d", rec2.ConsumedAt)
	}
}

func TestRequestPasswordReset_CanonicalizesEmail(t *testing.T) {
	// A request with non-canonical casing/dots/+tag must still find the account
	// stored under its canonical key rather than silently report "unknown".
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo, "alicesmith@gmail.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "Alice.Smith+promo@gmail.com", EmailLinkParams{}); err != nil {
		t.Fatalf("RequestPasswordReset err: %v", err)
	}
	sent := rec.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 email to the canonical account, got %d", len(sent))
	}
	if sent[0].To != "alicesmith@gmail.com" {
		t.Errorf("To: got %q, want alicesmith@gmail.com", sent[0].To)
	}
	token := extractTokenFromLink(t, sent[0].Text)
	rec2, err := repo.FindPasswordResetTokenByHash(context.Background(), sha256Hex(token))
	if err != nil || rec2 == nil {
		t.Fatalf("token not stored: err=%v rec=%v", err, rec2)
	}
	if rec2.UserID != user.ID {
		t.Errorf("token user_id: got %q, want %q", rec2.UserID, user.ID)
	}
}

func TestRequestPasswordReset_UnknownEmail_NoEnumeration(t *testing.T) {
	svc, _, rec := newAuthSvcWithMailer(t)
	if err := svc.RequestPasswordReset(context.Background(), "nobody@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("expected nil error for unknown email, got %v", err)
	}
	if len(rec.Sent()) != 0 {
		t.Errorf("expected 0 emails sent for unknown address, got %d", len(rec.Sent()))
	}
}

func TestRequestPasswordReset_TransportFailureSwallowed(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	rec.fail = errors.New("smtp down")
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")
	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("expected nil despite transport failure, got %v", err)
	}
}

func TestRequestPasswordReset_DisabledNoOps(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.PasswordResetEnabled = false
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("expected nil when reset is disabled, got %v", err)
	}
	if len(rec.Sent()) != 0 {
		t.Fatalf("expected 0 emails when reset is disabled, got %d", len(rec.Sent()))
	}
	if len(repo.passwordResets) != 0 {
		t.Fatalf("expected 0 reset tokens when reset is disabled, got %d", len(repo.passwordResets))
	}
}

// ── ConfirmPasswordReset ───────────────────────────────────────────────

// requestAndExtractResetToken triggers RequestPasswordReset and pulls
// the token out of the resulting email body. Test helper.
func requestAndExtractResetToken(t *testing.T, svc *AuthService, rec *recordingTransport, emailAddr string) string {
	t.Helper()
	rec.Reset()
	if err := svc.RequestPasswordReset(context.Background(), emailAddr, EmailLinkParams{}); err != nil {
		t.Fatalf("request reset: %v", err)
	}
	sent := rec.Sent()
	if len(sent) == 0 {
		t.Fatalf("no email sent")
	}
	return extractTokenFromLink(t, sent[0].Text)
}

func TestConfirmPasswordReset_Success(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo, "alice@test.com", pwHash, "active")

	// Pre-create a refresh token to assert it's revoked.
	_, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: "rh", UserID: user.ID, ExpiresAt: nowMs() + 60_000,
	})
	if err != nil {
		t.Fatalf("create refresh: %v", err)
	}

	token := requestAndExtractResetToken(t, svc, rec, "alice@test.com")
	if err := svc.ConfirmPasswordReset(context.Background(), token, "NewStr0ng!Pass"); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}

	// Password updated.
	got, err := repo.GetUser(context.Background(), user.ID)
	if err != nil || got == nil {
		t.Fatalf("user lookup: %v", err)
	}
	if !passwords.Verify("NewStr0ng!Pass", got.PasswordHash) {
		t.Errorf("new password did not verify")
	}

	// Token consumed, and bound to the address it was mailed to.
	stored, _ := repo.FindPasswordResetTokenByHash(context.Background(), sha256Hex(token))
	if stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("expected token to be consumed; stored=%+v", stored)
	}
	if stored != nil && stored.Email != "alice@test.com" {
		t.Errorf("stored token address = %q, want alice@test.com", stored.Email)
	}

	// Refresh tokens revoked.
	if list, _ := repo.refreshTokenSnapshot(); len(list) != 0 {
		t.Errorf("expected refresh tokens cleared, got %d", len(list))
	}
}

func TestConfirmPasswordReset_UpdateFailureDoesNotConsumeTokenOrRevokeSessions(t *testing.T) {
	repo := newErrorRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo.fakeRepo, "alice@test.com", pwHash, "active")
	if _, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: "rh", UserID: user.ID, ExpiresAt: nowMs() + 60_000,
	}); err != nil {
		t.Fatalf("create refresh: %v", err)
	}

	token := requestAndExtractResetToken(t, svc, rec, "alice@test.com")
	repo.failUpdateUser = true
	err := svc.ConfirmPasswordReset(context.Background(), token, "NewStr0ng!Pass")
	if err == nil {
		t.Fatal("expected password update error, got nil")
	}

	stored, _ := repo.FindPasswordResetTokenByHash(context.Background(), sha256Hex(token))
	if stored == nil {
		t.Fatal("reset token should remain stored")
	}
	if stored.ConsumedAt != 0 {
		t.Fatalf("reset token must remain unconsumed when password update fails, got %d", stored.ConsumedAt)
	}
	if list, _ := repo.refreshTokenSnapshot(); len(list) != 1 {
		t.Fatalf("refresh token must remain active when password update fails, got %d tokens", len(list))
	}
	got, _ := repo.GetUser(context.Background(), user.ID)
	if !passwords.Verify("OldStr0ng!Pass", got.PasswordHash) {
		t.Fatal("old password should remain valid when password update fails")
	}
}

func TestConfirmPasswordReset_InvalidTokenRejected(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	err := svc.ConfirmPasswordReset(context.Background(), "deadbeef", "NewStr0ng!Pass")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("invalid token: want ErrUnauthenticated, got %v", err)
	}
}

func TestConfirmPasswordReset_ExpiredTokenRejected(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUser(repo, "alice@test.com", "x", "active")
	tok := "abc123"
	_ = repo.CreatePasswordResetToken(context.Background(), &PasswordResetToken{
		TokenHash: sha256Hex(tok), UserID: user.ID,
		ExpiresAt: nowMs() - 1000, CreatedAt: nowMs() - 7200_000,
	})
	err := svc.ConfirmPasswordReset(context.Background(), tok, "NewStr0ng!Pass")
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token: want ErrTokenExpired, got %v", err)
	}
}

// A reset link is bound to the address it was mailed to. Once the account
// has moved to another mailbox, the old mailbox's link must not reset the
// password; it is refused exactly like an invalid link, and spent.
func TestConfirmPasswordReset_EmailChangedSinceSendIsRefused(t *testing.T) {
	ctx := context.Background()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "before@test.com", "OldStr0ng!Pass")
	resetTok := requestAndExtractResetToken(t, svc, rec, "before@test.com")

	rec.Reset()
	if err := svc.RequestEmailChange(ctx, user.ID, "after@test.com", "OldStr0ng!Pass"); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if _, err := svc.ConfirmEmailChange(ctx, extractChangeTokenFromBody(t, rec.Sent()[0].Text)); err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}

	err := svc.ConfirmPasswordReset(ctx, resetTok, "NewStr0ng!Pass")
	invalid := svc.ConfirmPasswordReset(ctx, "deadbeef", "NewStr0ng!Pass")
	if !errors.Is(err, ErrUnauthenticated) || err.Error() != invalid.Error() {
		t.Fatalf("want the invalid-token error %q, got %v", invalid, err)
	}
	got, _ := repo.GetUser(ctx, user.ID)
	if !passwords.Verify("OldStr0ng!Pass", got.PasswordHash) {
		t.Errorf("a link mailed to the old address reset the password")
	}
	if stored, _ := repo.FindPasswordResetTokenByHash(ctx, sha256Hex(resetTok)); stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("the refused token should be consumed; stored=%+v", stored)
	}
}

// A link mailed to another spelling of the same mailbox still resets it.
func TestConfirmPasswordReset_SameMailboxSpellingResets(t *testing.T) {
	ctx := context.Background()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "firstlast@gmail.com", "OldStr0ng!Pass")
	tok := requestAndExtractResetToken(t, svc, rec, "firstlast@gmail.com")
	if err := repo.UpdateUser(ctx, user.ID, map[string]any{"email": "First.Last@gmail.com"}); err != nil {
		t.Fatalf("respell email: %v", err)
	}

	if err := svc.ConfirmPasswordReset(ctx, tok, "NewStr0ng!Pass"); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
}

// A token stored without the address it was issued for cannot prove the
// account still holds it, so it is refused while the account has an address.
func TestConfirmPasswordReset_TokenWithoutAddressIsRefused(t *testing.T) {
	ctx := context.Background()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "alice@test.com", "OldStr0ng!Pass")
	tok := "issued-without-address"
	if err := repo.CreatePasswordResetToken(ctx, &PasswordResetToken{
		TokenHash: sha256Hex(tok), UserID: user.ID,
		ExpiresAt: nowMs() + 60_000, CreatedAt: nowMs(),
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := svc.ConfirmPasswordReset(ctx, tok, "NewStr0ng!Pass"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated, got %v", err)
	}
}

func TestResetTokenBindsAddress(t *testing.T) {
	cases := []struct {
		issuedFor, current string
		want               bool
	}{
		{"alice@example.com", "alice@example.com", true},
		{"Alice@Example.com", "alice@example.com", true},
		{"alice@example.com", "bob@example.com", false},
		{"", "alice@example.com", false},
		{"alice@example.com", "", false},
		{"", "", true},
	}
	for _, tc := range cases {
		if got := resetTokenBindsAddress(tc.issuedFor, tc.current); got != tc.want {
			t.Errorf("resetTokenBindsAddress(%q, %q) = %v, want %v", tc.issuedFor, tc.current, got, tc.want)
		}
	}
}

func TestConfirmPasswordReset_ReplayedTokenRejected(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")
	tok := requestAndExtractResetToken(t, svc, rec, "alice@test.com")

	if err := svc.ConfirmPasswordReset(context.Background(), tok, "NewStr0ng!Pass"); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	err := svc.ConfirmPasswordReset(context.Background(), tok, "AnotherStr0ng!Pass")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("replay: want ErrUnauthenticated, got %v", err)
	}
}

func TestConfirmPasswordReset_WeakPasswordRejected(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")
	tok := requestAndExtractResetToken(t, svc, rec, "alice@test.com")

	err := svc.ConfirmPasswordReset(context.Background(), tok, "weak")
	if !errors.Is(err, ErrWeakPassword) {
		t.Errorf("weak password: want ErrWeakPassword, got %v", err)
	}
}

// ── SendEmailVerification ──────────────────────────────────────────────

func TestSendEmailVerification_Success(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")
	if err := svc.SendEmailVerification(context.Background(), user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	sent := rec.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(sent))
	}
	if !strings.Contains(sent[0].Text, "https://app.test/auth/verify-email?token=") {
		t.Errorf("verify URL missing: %q", sent[0].Text)
	}
	tok := extractTokenFromLink(t, sent[0].Text)
	stored, _ := repo.FindEmailVerificationTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil {
		t.Errorf("token not persisted")
	}
}

func TestSendEmailVerification_UnknownUser(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	err := svc.SendEmailVerification(context.Background(), "no-such-user", EmailLinkParams{})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestSendEmailVerification_IdempotentMultipleTokens(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")
	for i := 0; i < 3; i++ {
		if err := svc.SendEmailVerification(context.Background(), user.ID, EmailLinkParams{}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := len(rec.Sent()); got != 3 {
		t.Errorf("expected 3 emails, got %d", got)
	}
	// Verify each stored token is independent (different hashes).
	repo.mu.Lock()
	count := len(repo.emailVerifications)
	repo.mu.Unlock()
	if count != 3 {
		t.Errorf("expected 3 stored verification tokens, got %d", count)
	}
}

// ── VerifyEmail ────────────────────────────────────────────────────────

func TestVerifyEmail_Success(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")
	if err := svc.SendEmailVerification(context.Background(), user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	tok := extractTokenFromLink(t, rec.Sent()[0].Text)

	got, err := svc.VerifyEmail(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !got.EmailVerified {
		t.Errorf("user.EmailVerified should be true")
	}
	stored, _ := repo.FindEmailVerificationTokenByHash(context.Background(), sha256Hex(tok))
	if stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("token should be consumed; stored=%+v", stored)
	}
	// User record updated in repo.
	updated, _ := repo.GetUser(context.Background(), user.ID)
	if !updated.EmailVerified {
		t.Errorf("repo user not updated")
	}
}

// A verification link proves only the address it was mailed to. Once the
// account holds another address, redeeming it must not verify that address,
// and the link is spent.
func TestVerifyEmail_AddressChangedSinceSendIsRefused(t *testing.T) {
	ctx := context.Background()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "before@test.com", "x", "active")
	if err := svc.SendEmailVerification(ctx, user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	tok := extractTokenFromLink(t, rec.Sent()[0].Text)
	if err := repo.UpdateUser(ctx, user.ID, map[string]any{"email": "after@test.com"}); err != nil {
		t.Fatalf("change email: %v", err)
	}

	if _, err := svc.VerifyEmail(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated, got %v", err)
	}
	if got, _ := repo.GetUser(ctx, user.ID); got.EmailVerified {
		t.Errorf("the new address was verified by a link mailed to the old one")
	}
	if stored, _ := repo.FindEmailVerificationTokenByHash(ctx, sha256Hex(tok)); stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("the refused token should be consumed; stored=%+v", stored)
	}
}

// A link mailed to another spelling of the same mailbox still verifies it.
func TestVerifyEmail_SameMailboxSpellingVerifies(t *testing.T) {
	ctx := context.Background()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "First.Last@gmail.com", "x", "active")
	if err := svc.SendEmailVerification(ctx, user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	tok := extractTokenFromLink(t, rec.Sent()[0].Text)
	if err := repo.UpdateUser(ctx, user.ID, map[string]any{"email": "firstlast@gmail.com"}); err != nil {
		t.Fatalf("canonicalize email: %v", err)
	}

	got, err := svc.VerifyEmail(ctx, tok)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !got.EmailVerified {
		t.Errorf("the same mailbox should be verified")
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	_, err := svc.VerifyEmail(context.Background(), "deadbeef")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("invalid token: want ErrUnauthenticated, got %v", err)
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")
	tok := "expired"
	_ = repo.CreateEmailVerificationToken(context.Background(), &EmailVerificationToken{
		TokenHash: sha256Hex(tok), UserID: user.ID, Email: user.Email,
		ExpiresAt: nowMs() - 1000, CreatedAt: nowMs() - 7200_000,
	})
	_, err := svc.VerifyEmail(context.Background(), tok)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired: want ErrTokenExpired, got %v", err)
	}
}

func TestVerifyEmail_ReplayedToken(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")
	if err := svc.SendEmailVerification(context.Background(), user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	tok := extractTokenFromLink(t, rec.Sent()[0].Text)
	if _, err := svc.VerifyEmail(context.Background(), tok); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := svc.VerifyEmail(context.Background(), tok)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("replay: want ErrUnauthenticated, got %v", err)
	}
}

func TestVerifyEmail_AlreadyVerifiedIsIdempotent(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")

	// Verify once.
	if err := svc.SendEmailVerification(context.Background(), user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send 1: %v", err)
	}
	tok1 := extractTokenFromLink(t, rec.Sent()[0].Text)
	if _, err := svc.VerifyEmail(context.Background(), tok1); err != nil {
		t.Fatalf("verify 1: %v", err)
	}

	// Send a fresh token after the user is already verified, then verify
	// it. The call must succeed and the token must still be marked
	// consumed (preventing re-use).
	rec.Reset()
	if err := svc.SendEmailVerification(context.Background(), user.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("send 2: %v", err)
	}
	tok2 := extractTokenFromLink(t, rec.Sent()[0].Text)
	got, err := svc.VerifyEmail(context.Background(), tok2)
	if err != nil {
		t.Fatalf("verify 2 (already verified): %v", err)
	}
	if !got.EmailVerified {
		t.Errorf("expected EmailVerified=true after idempotent verify")
	}
	stored, _ := repo.FindEmailVerificationTokenByHash(context.Background(), sha256Hex(tok2))
	if stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("idempotent verify should still consume the second token")
	}
}

// ── PasswordSignup hook ────────────────────────────────────────────────

func TestPasswordSignup_FiresVerificationEmail(t *testing.T) {
	svc, _, rec := newAuthSvcWithMailer(t)
	res, err := svc.PasswordSignup(context.Background(), "carol@test.com", "Str0ng!Pass1", "Carol", "", 0, "", EmailLinkParams{})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	sent := rec.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 verification email after signup, got %d", len(sent))
	}
	if sent[0].To != "carol@test.com" {
		t.Errorf("verification email To: got %q, want carol@test.com", sent[0].To)
	}
	if !strings.Contains(sent[0].Subject, "Verify") {
		t.Errorf("subject: want 'Verify ...' got %q", sent[0].Subject)
	}
	if res.AccessToken == "" {
		t.Errorf("signup should return an access token")
	}
}

// ── InviteUser hook ────────────────────────────────────────────────────

func TestInviteUser_FiresInvitationEmail(t *testing.T) {
	// AdminService uses the *DB* interface, not Repository, so we need
	// the fakeDB. This test constructs a minimal AdminService with the
	// recording transport.
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	cfg := testConfig()
	cfg.AppBaseURL = "https://app.test"
	cfg.SMTPFrom = "no-reply@test.local"
	cfg.TOTPIssuer = "Identity Test"
	rec := &recordingTransport{}
	svc := NewAdminService(newFakeRepo(), db, "test-tenant",
		audit.NewLogger(nil, "test", zap.NewNop()),
		cfg, rec, zap.NewNop())

	result, err := svc.InviteUser(context.Background(), "admin-1",
		"new@test.com", "New User", "member", "", 0, false)
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	if result.InvitationToken == "" {
		t.Errorf("invitation token missing in result")
	}
	sent := rec.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 invitation email, got %d", len(sent))
	}
	if sent[0].To != "new@test.com" {
		t.Errorf("invitation To: got %q, want new@test.com", sent[0].To)
	}
	if !strings.Contains(sent[0].Text, result.InvitationToken) {
		t.Errorf("invitation body missing token; body=%q", sent[0].Text)
	}
	if !strings.Contains(sent[0].Text, "https://app.test/auth/accept-invitation?token=") {
		t.Errorf("invitation body missing setup URL; body=%q", sent[0].Text)
	}
}

// ── Misc helpers used above ────────────────────────────────────────────

func TestFormatExpiresIn(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{time.Hour, "1 hour"},
		{2 * time.Hour, "2 hours"},
		{30 * time.Minute, "30 minutes"},
		{time.Minute, "1 minute"},
	}
	for _, c := range cases {
		if got := formatExpiresIn(c.d); got != c.want {
			t.Errorf("formatExpiresIn(%v): got %q, want %q", c.d, got, c.want)
		}
	}
}

// ── fakeRepo helpers used by the tests above ───────────────────────────

func (r *fakeRepo) refreshTokenSnapshot() ([]*RefreshTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*RefreshTokenRecord, 0, len(r.refreshTokens))
	for _, t := range r.refreshTokens {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

// ── Per-recipient throttle ─────────────────────────────────────────────

func TestRequestPasswordReset_PerRecipientThrottle(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.EmailSendCooldownSeconds = 60
	svc.emailThrottle = newEmailSendThrottle(int64(svc.cfg.EmailSendCooldownSeconds)*1000, 0)

	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("second reset: %v", err)
	}
	if got := len(rec.Sent()); got != 1 {
		t.Fatalf("expected throttle to drop the second send (1 email), got %d", got)
	}
}

func TestSendEmailVerification_PerRecipientThrottle(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.EmailSendCooldownSeconds = 60
	svc.emailThrottle = newEmailSendThrottle(int64(svc.cfg.EmailSendCooldownSeconds)*1000, 0)

	u := seedUser(repo, "bob@test.com", "x", "active")

	if err := svc.SendEmailVerification(context.Background(), u.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := svc.SendEmailVerification(context.Background(), u.ID, EmailLinkParams{}); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if got := len(rec.Sent()); got != 1 {
		t.Fatalf("expected throttle to drop second send (1 email), got %d", got)
	}
}

// ── Email link base and link params ────────────────────────────────────

const (
	hubLinkBase      = "https://signin.example.test"
	hubReturnTo      = "https://acme.example.test/after?step=2"
	hubReturnToQuery = "https%3A%2F%2Facme.example.test%2Fafter%3Fstep%3D2"
)

// hubLinkParams is what a sign-in hub sends: a product named as the hub's
// ?product= names it (any case) and an allowlisted return URL.
var hubLinkParams = EmailLinkParams{Product: "Acme", ReturnTo: hubReturnTo}

// newHubLinkAuthSvc is newAuthSvcWithMailer for a deployment whose reset and
// verification pages live on a hub (GATEWAY_EMAIL_LINK_BASE_URL, configured
// with a trailing slash) and that trusts the acme app as a return URL.
func newHubLinkAuthSvc(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.EmailLinkBaseURL = hubLinkBase + "/"
	svc.returnAllow = mustReturnAllowlist(t, "https://acme.example.test")
	return svc, repo, rec
}

func TestRequestPasswordReset_LinkOnEmailLinkBaseCarriesParams(t *testing.T) {
	svc, repo, rec := newHubLinkAuthSvc(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", hubLinkParams); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	sent := rec.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(sent))
	}
	tok := extractTokenFromLink(t, sent[0].Text)
	want := hubLinkBase + "/reset-password?token=" + tok + "&product=acme&redirect=" + hubReturnToQuery
	if got := linkInBody(t, sent[0].Text, hubLinkBase); got != want {
		t.Fatalf("reset link:\n got  %s\n want %s", got, want)
	}
	if href := `href="` + html.EscapeString(want) + `"`; !strings.Contains(sent[0].HTML, href) {
		t.Errorf("HTML body missing %s: %q", href, sent[0].HTML)
	}
	// The token on the hub link redeems like any other.
	if err := svc.ConfirmPasswordReset(context.Background(), tok, "NewStr0ng!Pass1"); err != nil {
		t.Fatalf("ConfirmPasswordReset with the hub link's token: %v", err)
	}
}

// TestRequestPasswordReset_NoLinkBaseKeepsAppLink: with no
// GATEWAY_EMAIL_LINK_BASE_URL and no link params the link is
// <app base>/auth/reset-password?token=<token>.
func TestRequestPasswordReset_NoLinkBaseKeepsAppLink(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{}); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	text := rec.Sent()[0].Text
	tok := extractTokenFromLink(t, text)
	if got, want := linkInBody(t, text, "https://app.test/"), "https://app.test/auth/reset-password?token="+tok; got != want {
		t.Fatalf("reset link = %q, want %q", got, want)
	}
}

// TestRequestPasswordReset_RefusedLinkParamsSendNothing: a return_to off the
// allowlist is the one error RequestPasswordReset reports, and it is the
// same whether or not the email has an account — no enumeration — with no
// token minted and nothing sent.
func TestRequestPasswordReset_RefusedLinkParamsSendNothing(t *testing.T) {
	svc, repo, rec := newHubLinkAuthSvc(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")

	for _, addr := range []string{"alice@test.com", "nobody@test.com"} {
		err := svc.RequestPasswordReset(context.Background(), addr,
			EmailLinkParams{Product: "acme", ReturnTo: "https://evil.test/"})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%s: err = %v, want ErrInvalidArgument", addr, err)
		}
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("refused request sent %d emails", got)
	}
	repo.mu.Lock()
	minted := len(repo.passwordResets)
	repo.mu.Unlock()
	if minted != 0 {
		t.Fatalf("refused request minted %d reset tokens", minted)
	}
}

// TestRequestPasswordReset_RefusedLinkParamsWhileDisabled: the link params
// are checked before the reset toggle, so a refused return_to is refused the
// same way whether or not reset is enabled — and still sends nothing.
func TestRequestPasswordReset_RefusedLinkParamsWhileDisabled(t *testing.T) {
	svc, repo, rec := newHubLinkAuthSvc(t)
	svc.cfg.PasswordResetEnabled = false
	seedUser(repo, "alice@test.com", "x", "active")

	err := svc.RequestPasswordReset(context.Background(), "alice@test.com", EmailLinkParams{ReturnTo: "https://evil.test/"})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("refused request sent %d emails", got)
	}
}

func TestSendEmailVerification_LinkOnEmailLinkBaseCarriesParams(t *testing.T) {
	svc, repo, rec := newHubLinkAuthSvc(t)
	user := seedUser(repo, "bob@test.com", "x", "active")

	if err := svc.SendEmailVerification(context.Background(), user.ID, hubLinkParams); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	text := rec.Sent()[0].Text
	tok := extractTokenFromLink(t, text)
	want := hubLinkBase + "/verify-email?token=" + tok + "&product=acme&redirect=" + hubReturnToQuery
	if got := linkInBody(t, text, hubLinkBase); got != want {
		t.Fatalf("verify link:\n got  %s\n want %s", got, want)
	}
	if _, err := svc.VerifyEmail(context.Background(), tok); err != nil {
		t.Fatalf("VerifyEmail with the hub link's token: %v", err)
	}
}

func TestSendEmailVerification_RefusedLinkParamsSendNothing(t *testing.T) {
	svc, repo, rec := newHubLinkAuthSvc(t)
	user := seedUser(repo, "bob@test.com", "x", "active")

	for _, params := range []EmailLinkParams{
		{ReturnTo: "https://evil.test/"},
		{Product: "not a slug"},
	} {
		if err := svc.SendEmailVerification(context.Background(), user.ID, params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%+v: err = %v, want ErrInvalidArgument", params, err)
		}
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("refused request sent %d emails", got)
	}
	repo.mu.Lock()
	minted := len(repo.emailVerifications)
	repo.mu.Unlock()
	if minted != 0 {
		t.Fatalf("refused request minted %d verification tokens", minted)
	}
}

func TestPasswordSignup_VerificationLinkCarriesParams(t *testing.T) {
	svc, _, rec := newHubLinkAuthSvc(t)

	if _, err := svc.PasswordSignup(context.Background(), "carol@test.com", "Str0ng!Pass1", "Carol", "", 0, "", hubLinkParams); err != nil {
		t.Fatalf("signup: %v", err)
	}
	text := rec.Sent()[0].Text
	tok := extractTokenFromLink(t, text)
	want := hubLinkBase + "/verify-email?token=" + tok + "&product=acme&redirect=" + hubReturnToQuery
	if got := linkInBody(t, text, hubLinkBase); got != want {
		t.Fatalf("signup verify link:\n got  %s\n want %s", got, want)
	}
}

// TestPasswordSignup_RefusedLinkParamsCreateNoAccount: the link params are
// checked before any account work, so a refused return_to leaves nothing
// behind — no account, no email.
func TestPasswordSignup_RefusedLinkParamsCreateNoAccount(t *testing.T) {
	svc, repo, rec := newHubLinkAuthSvc(t)

	_, err := svc.PasswordSignup(context.Background(), "carol@test.com", "Str0ng!Pass1", "Carol", "", 0, "",
		EmailLinkParams{ReturnTo: "https://evil.test/"})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
	if u, _ := repo.FindUserByEmail(context.Background(), "carol@test.com"); u != nil {
		t.Fatalf("refused signup created account %q", u.ID)
	}
	if got := len(rec.Sent()); got != 0 {
		t.Fatalf("refused signup sent %d emails", got)
	}
}
