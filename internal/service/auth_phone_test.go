package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/sms"
)

// fakeSMSSender records each Send so tests can assert on the delivered
// body (and the OTP it contains). An optional err makes Send fail.
type fakeSMSSender struct {
	mu       sync.Mutex
	messages []sms.Message
	err      error
}

func (f *fakeSMSSender) Send(_ context.Context, m sms.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.messages = append(f.messages, m)
	return nil
}

func (f *fakeSMSSender) last() (sms.Message, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.messages) == 0 {
		return sms.Message{}, false
	}
	return f.messages[len(f.messages)-1], true
}

func (f *fakeSMSSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.messages)
}

// newTestPhoneService builds an AuthService with SMS enabled and the
// supplied fake sender. The returned config is mutated for SMS so the
// service's SMSEnabled gate is on.
func newTestPhoneService(t *testing.T, repo *fakeRepo, sender sms.Sender) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.SMSEnabled = true
	cfg.SMSProvider = "twilio"
	cfg.PhoneCodeTTLSeconds = 300
	cfg.PhoneCodeMaxAttempts = 5
	cfg.PhoneCodeCooldownSeconds = 60
	kr := testKeyRing(t)
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, kr, passkeysSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), testTotpRecoveryPepper(), nil, sender, zap.NewNop(),
		defaultTestOAuthRegistry(),
	)
}

// extractCode pulls the 6-digit OTP out of the message the service
// generated. The body is "Your verification code is NNNNNN. ...".
func extractCode(t *testing.T, body string) string {
	t.Helper()
	const prefix = "Your verification code is "
	i := indexOf(body, prefix)
	if i < 0 {
		t.Fatalf("body has no code prefix: %q", body)
	}
	rest := body[i+len(prefix):]
	if len(rest) < emailLoginCodeDigits {
		t.Fatalf("body too short for a code: %q", body)
	}
	return rest[:emailLoginCodeDigits]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func seedPhoneUser(t *testing.T, repo *fakeRepo, email string) string {
	t.Helper()
	id, err := repo.CreateUser(context.Background(), &User{Email: email, Status: "active", Role: "member"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return id
}

func TestRequestPhoneVerification_HappyPath(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "p1@example.com")

	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("RequestPhoneVerification: %v", err)
	}
	msg, ok := sender.last()
	if !ok {
		t.Fatal("no SMS sent")
	}
	if msg.To != "+14155550123" {
		t.Fatalf("SMS to = %q", msg.To)
	}
	// The code is stored hashed, not in plaintext.
	rec, _ := repo.FindPhoneVerificationCodeByUser(context.Background(), uid)
	if rec == nil {
		t.Fatal("no code stored")
	}
	code := extractCode(t, msg.Body)
	if rec.CodeHash != sha256Hex(code) {
		t.Fatal("stored hash does not match the delivered code")
	}
	if rec.CodeHash == code {
		t.Fatal("code stored in plaintext")
	}
}

func TestRequestPhoneVerification_SMSDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo) // SMS disabled by default
	uid := seedPhoneUser(t, repo, "p-disabled@example.com")
	err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123")
	if !errors.Is(err, ErrSMSDisabled) {
		t.Fatalf("want ErrSMSDisabled, got %v", err)
	}
}

func TestRequestPhoneVerification_InvalidNumber(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestPhoneService(t, repo, &fakeSMSSender{})
	uid := seedPhoneUser(t, repo, "p-bad@example.com")
	err := svc.RequestPhoneVerification(context.Background(), uid, "14155550123") // no +
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
}

func TestRequestPhoneVerification_Cooldown(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "p-cool@example.com")

	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// Second immediate request is throttled: returns nil but sends no SMS.
	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("second request: %v", err)
	}
	if sender.count() != 1 {
		t.Fatalf("cooldown breached: sent %d SMS, want 1", sender.count())
	}
}

func TestRequestPhoneVerification_AlreadyVerified(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestPhoneService(t, repo, &fakeSMSSender{})
	uid := seedPhoneUser(t, repo, "p-verified@example.com")
	if err := repo.SetUserPhoneVerified(context.Background(), uid, "+14155550123", 1); err != nil {
		t.Fatalf("seed verified: %v", err)
	}
	err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123")
	if !errors.Is(err, ErrPhoneAlreadyVerified) {
		t.Fatalf("want ErrPhoneAlreadyVerified, got %v", err)
	}
}

func TestRequestPhoneVerification_SendFailureSurfaces(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{err: errors.New("provider down")}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "p-sendfail@example.com")
	err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123")
	if !errors.Is(err, ErrSMSDisabled) {
		t.Fatalf("send failure should surface (wrapped ErrSMSDisabled), got %v", err)
	}
}

func TestVerifyPhoneCode_HappyPath(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "v1@example.com")

	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	msg, _ := sender.last()
	code := extractCode(t, msg.Body)

	user, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", code)
	if err != nil {
		t.Fatalf("VerifyPhoneCode: %v", err)
	}
	if user == nil || !user.PhoneVerified || user.PhoneNumber != "+14155550123" {
		t.Fatalf("user not marked verified: %+v", user)
	}
	// Replay is rejected (code consumed).
	if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", code); !errors.Is(err, ErrPhoneCodeInvalid) {
		t.Fatalf("replay: want ErrPhoneCodeInvalid, got %v", err)
	}
}

func TestVerifyPhoneCode_WrongCodeIncrementsAttempts(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "v-wrong@example.com")
	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("Request: %v", err)
	}

	if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", "000000"); !errors.Is(err, ErrPhoneCodeInvalid) {
		t.Fatalf("wrong code: want ErrPhoneCodeInvalid, got %v", err)
	}
	rec, _ := repo.FindPhoneVerificationCodeByUser(context.Background(), uid)
	if rec == nil || rec.AttemptCount != 1 {
		t.Fatalf("attempt not counted: %#v", rec)
	}
}

func TestVerifyPhoneCode_MaxAttemptsBurnsCode(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "v-max@example.com")
	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	msg, _ := sender.last()
	realCode := extractCode(t, msg.Body)

	// Exhaust the 5-attempt budget with wrong guesses.
	for i := 0; i < 5; i++ {
		if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", "999999"); !errors.Is(err, ErrPhoneCodeInvalid) {
			t.Fatalf("attempt %d: want ErrPhoneCodeInvalid, got %v", i, err)
		}
	}
	// The real code is now burned — even a correct guess fails.
	if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", realCode); !errors.Is(err, ErrPhoneCodeInvalid) {
		t.Fatalf("post-cap correct code: want ErrPhoneCodeInvalid, got %v", err)
	}
}

func TestVerifyPhoneCode_Expired(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestPhoneService(t, repo, &fakeSMSSender{})
	uid := seedPhoneUser(t, repo, "v-exp@example.com")
	// Seed an already-expired code directly.
	if _, err := repo.UpsertPhoneVerificationCode(context.Background(), &PhoneVerificationCodeRecord{
		UserID: uid, PhoneNumber: "+14155550123", CodeHash: sha256Hex("123456"),
		ExpiresAt: 1, CreatedAt: 0, MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", "123456"); !errors.Is(err, ErrPhoneCodeInvalid) {
		t.Fatalf("expired: want ErrPhoneCodeInvalid, got %v", err)
	}
}

func TestVerifyPhoneCode_NumberMismatch(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSMSSender{}
	svc := newTestPhoneService(t, repo, sender)
	uid := seedPhoneUser(t, repo, "v-mismatch@example.com")
	if err := svc.RequestPhoneVerification(context.Background(), uid, "+14155550123"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	msg, _ := sender.last()
	code := extractCode(t, msg.Body)
	// Verifying against a different number must fail even with the right code.
	if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550999", code); !errors.Is(err, ErrPhoneCodeInvalid) {
		t.Fatalf("number mismatch: want ErrPhoneCodeInvalid, got %v", err)
	}
}

func TestVerifyPhoneCode_SMSDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	uid := seedPhoneUser(t, repo, "v-disabled@example.com")
	if _, err := svc.VerifyPhoneCode(context.Background(), uid, "+14155550123", "123456"); !errors.Is(err, ErrSMSDisabled) {
		t.Fatalf("want ErrSMSDisabled, got %v", err)
	}
}

func TestNormalizePhone(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{"+15551234567", "+15551234567", true},
		{"  +15551234567  ", "+15551234567", true},
		{"15551234567", "15551234567", false}, // no leading +
		{"+", "+", false},                     // too short
		{"+1555abc4567", "+1555abc4567", false},
		{"", "", false},
		{"+1", "+1", true},
	}
	for _, c := range cases {
		got, ok := normalizePhone(c.in)
		if got != c.want || ok != c.valid {
			t.Errorf("normalizePhone(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.valid)
		}
	}
}

func TestRedactPhone(t *testing.T) {
	cases := map[string]string{
		"+15551234567": "+1********67",
		"+123":         "***", // <= 4 chars
		"":             "***",
		"+123456":      "+1***56",
	}
	for in, want := range cases {
		if got := redactPhone(in); got != want {
			t.Errorf("redactPhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPhoneCodeTTLAndAttempts(t *testing.T) {
	// Configured values win.
	s := &AuthService{cfg: &config.Config{PhoneCodeTTLSeconds: 120, PhoneCodeMaxAttempts: 7}}
	if got := s.phoneCodeTTL(); got != 120*time.Second {
		t.Errorf("phoneCodeTTL configured = %v, want 120s", got)
	}
	if got := s.phoneCodeMaxAttempts(); got != 7 {
		t.Errorf("phoneCodeMaxAttempts configured = %d, want 7", got)
	}
	// Zero falls back to defaults.
	d := &AuthService{cfg: &config.Config{}}
	if got := d.phoneCodeTTL(); got != defaultPhoneCodeTTL {
		t.Errorf("phoneCodeTTL default = %v, want %v", got, defaultPhoneCodeTTL)
	}
	if got := d.phoneCodeMaxAttempts(); got != defaultCodeMaxAttempts {
		t.Errorf("phoneCodeMaxAttempts default = %d, want %d", got, defaultCodeMaxAttempts)
	}
}
