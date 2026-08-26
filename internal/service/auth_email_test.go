package service

import (
	"context"
	"errors"
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
// the literal "?token=" prefix.
func extractTokenFromLink(t *testing.T, body string) string {
	t.Helper()
	idx := strings.Index(body, "token=")
	if idx == -1 {
		t.Fatalf("token= not found in body: %q", body)
	}
	rest := body[idx+len("token="):]
	// Trim at first whitespace or quote.
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\n' || ch == '\r' || ch == '"' || ch == '<' {
			end = i
			break
		}
	}
	return rest[:end]
}

// ── RequestPasswordReset ───────────────────────────────────────────────

func TestRequestPasswordReset_Success(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com"); err != nil {
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

	if err := svc.RequestPasswordReset(context.Background(), "Alice.Smith+promo@gmail.com"); err != nil {
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
	if err := svc.RequestPasswordReset(context.Background(), "nobody@test.com"); err != nil {
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
	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com"); err != nil {
		t.Fatalf("expected nil despite transport failure, got %v", err)
	}
}

func TestRequestPasswordReset_DisabledNoOps(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.PasswordResetEnabled = false
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	seedUser(repo, "alice@test.com", pwHash, "active")

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com"); err != nil {
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
	if err := svc.RequestPasswordReset(context.Background(), emailAddr); err != nil {
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

	// Token consumed.
	stored, _ := repo.FindPasswordResetTokenByHash(context.Background(), sha256Hex(token))
	if stored == nil || stored.ConsumedAt == 0 {
		t.Errorf("expected token to be consumed; stored=%+v", stored)
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
	if err := svc.SendEmailVerification(context.Background(), user.ID); err != nil {
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
	err := svc.SendEmailVerification(context.Background(), "no-such-user")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestSendEmailVerification_IdempotentMultipleTokens(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUser(repo, "bob@test.com", "x", "active")
	for i := 0; i < 3; i++ {
		if err := svc.SendEmailVerification(context.Background(), user.ID); err != nil {
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
	if err := svc.SendEmailVerification(context.Background(), user.ID); err != nil {
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
	if err := svc.SendEmailVerification(context.Background(), user.ID); err != nil {
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
	if err := svc.SendEmailVerification(context.Background(), user.ID); err != nil {
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
	if err := svc.SendEmailVerification(context.Background(), user.ID); err != nil {
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
	res, err := svc.PasswordSignup(context.Background(), "carol@test.com", "Str0ng!Pass1", "Carol", "", 0, "")
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

	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com"); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	if err := svc.RequestPasswordReset(context.Background(), "alice@test.com"); err != nil {
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

	if err := svc.SendEmailVerification(context.Background(), u.ID); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := svc.SendEmailVerification(context.Background(), u.ID); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if got := len(rec.Sent()); got != 1 {
		t.Fatalf("expected throttle to drop second send (1 email), got %d", got)
	}
}
