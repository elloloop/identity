package connect

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// fakeVerifier is a captcha.Verifier whose Verify result is fixed at
// construction. It records the last token/ip it saw so a test can assert
// the handler forwarded them.
type fakeVerifier struct {
	err        error
	lastToken  string
	lastRemote string
	calls      int
}

func (f *fakeVerifier) Name() string { return "fake" }

func (f *fakeVerifier) Verify(_ context.Context, token, remoteip string) error {
	f.calls++
	f.lastToken = token
	f.lastRemote = remoteip
	return f.err
}

// enableCaptcha turns every per-endpoint toggle on so a test only has to
// flip CaptchaEnabled-driven behaviour, mirroring a deployment that gates
// all five endpoints.
func enableCaptcha(c *config.Config) {
	c.CaptchaEnabled = true
	c.CaptchaProvider = config.CaptchaProviderTurnstile
	c.CaptchaTurnstileSecret = "secret"
	c.CaptchaEnforcePasswordSignup = true
	c.CaptchaEnforcePasswordLogin = true
	c.CaptchaEnforcePasswordReset = true
	c.CaptchaEnforceEmailLoginCode = true
	c.CaptchaEnforceMagicLink = true
	c.CaptchaEnforcePasskeySignup = true
}

func seedLoginUser(t *testing.T, h *testHarness) *service.User {
	t.Helper()
	return h.repo.seedUser(&service.User{
		Email:        "captcha@example.com",
		Status:       "active",
		Role:         "member",
		PasswordHash: mustHash(t, strongPW),
	})
}

// ── PasswordLogin (password endpoint) ───────────────────────────────────

func TestCaptcha_PasswordLogin_DisabledBehavesAsBefore(t *testing.T) {
	// No verifier wired and CAPTCHA off: a token-less request logs in
	// exactly as it did before the feature existed.
	h := newHarness(t)
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "captcha@example.com",
		Password: strongPW,
	})))
	if err != nil {
		t.Fatalf("PasswordLogin (captcha disabled): %v", err)
	}
}

func TestCaptcha_PasswordLogin_EnabledValidTokenPasses(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:        "captcha@example.com",
		Password:     strongPW,
		CaptchaToken: "valid-token",
	})))
	if err != nil {
		t.Fatalf("PasswordLogin (valid captcha): %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
	if fv.lastToken != "valid-token" {
		t.Fatalf("verifier token = %q; want valid-token", fv.lastToken)
	}
	if fv.lastRemote != "10.0.0.1" {
		t.Fatalf("verifier remoteip = %q; want forwarded client IP", fv.lastRemote)
	}
}

func TestCaptcha_PasswordLogin_MissingTokenPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "captcha@example.com",
		Password: strongPW,
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called for a missing token; calls = %d", fv.calls)
	}
}

func TestCaptcha_PasswordLogin_InvalidTokenPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("provider rejected")}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:        "captcha@example.com",
		Password:     strongPW,
		CaptchaToken: "rejected-token",
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
}

func TestCaptcha_PasswordLogin_PerEndpointToggleOffSkipsCheck(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("would reject if called")}
	h := newHarnessWithCaptcha(t, fv, func(c *config.Config) {
		enableCaptcha(c)
		c.CaptchaEnforcePasswordLogin = false
	})
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "captcha@example.com",
		Password: strongPW,
	})))
	if err != nil {
		t.Fatalf("PasswordLogin (login toggle off): %v", err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called when the login toggle is off; calls = %d", fv.calls)
	}
}

// ── RequestEmailLoginCode (passwordless endpoint) ───────────────────────

func TestCaptcha_RequestEmailLoginCode_DisabledBehavesAsBefore(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.RequestEmailLoginCode(context.Background(), connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: "anyone@example.com",
	})); err != nil {
		t.Fatalf("RequestEmailLoginCode (captcha disabled): %v", err)
	}
}

func TestCaptcha_RequestEmailLoginCode_EnabledValidTokenPasses(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)
	if _, err := h.client.RequestEmailLoginCode(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email:        "anyone@example.com",
		CaptchaToken: "valid-token",
	}))); err != nil {
		t.Fatalf("RequestEmailLoginCode (valid captcha): %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
}

func TestCaptcha_RequestEmailLoginCode_MissingTokenPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)
	_, err := h.client.RequestEmailLoginCode(context.Background(), connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: "anyone@example.com",
	}))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called for a missing token; calls = %d", fv.calls)
	}
}

// ── RequestPasswordReset (enumeration-safe endpoint) ─────────────────────

// A failed CAPTCHA on RequestPasswordReset surfaces the error even though
// the endpoint is otherwise enumeration-safe: a CAPTCHA failure is identical
// for any email, so it is not an account-existence oracle.
func TestCaptcha_RequestPasswordReset_InvalidTokenPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("rejected")}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)

	_, err := h.client.RequestPasswordReset(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email:        "anyone@example.com",
		CaptchaToken: "rejected",
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
}

func TestCaptcha_RequestPasswordReset_ValidTokenStaysEnumerationSafe(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)

	if _, err := h.client.RequestPasswordReset(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email:        "unknown@example.com",
		CaptchaToken: "valid",
	}))); err != nil {
		t.Fatalf("RequestPasswordReset (valid captcha, unknown email): %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
}

// ── BeginPasskeySignup (account-creation endpoint) ──────────────────────
//
// WebAuthn's user-presence/verification flags are asserted by the authenticator
// itself, so a scripted attacker can forge them in software and spam this
// endpoint into creating dummy accounts + sending emails. The CAPTCHA gate is
// the real bot wall — it must run BEFORE any passkey work.

func TestCaptcha_BeginPasskeySignup_MissingTokenPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)

	_, err := h.client.BeginPasskeySignup(context.Background(), connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:      "passkey-captcha@example.com",
		DeviceName: "iPhone",
	}))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called for a missing token; calls = %d", fv.calls)
	}
}

func TestCaptcha_BeginPasskeySignup_InvalidTokenPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("provider rejected")}
	h := newHarnessWithCaptcha(t, fv, enableCaptcha)

	_, err := h.client.BeginPasskeySignup(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:        "passkey-captcha@example.com",
		DeviceName:   "iPhone",
		CaptchaToken: "rejected-token",
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
}

func TestCaptcha_BeginPasskeySignup_EnabledValidTokenPasses(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithCaptcha(t, fv, func(c *config.Config) {
		enableCaptcha(c)
		c.PasskeySignupEnabled = true
	})

	resp, err := h.client.BeginPasskeySignup(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:        "passkey-captcha@example.com",
		DeviceName:   "iPhone",
		CaptchaToken: "valid-token",
	})))
	if err != nil {
		t.Fatalf("BeginPasskeySignup (valid captcha): %v", err)
	}
	if resp.Msg.GetOptionsJson() == "" || resp.Msg.GetChallengeId() == "" {
		t.Fatalf("expected creation options + challenge id; got %+v", resp.Msg)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
	if fv.lastToken != "valid-token" {
		t.Fatalf("verifier token = %q; want valid-token", fv.lastToken)
	}
	if fv.lastRemote != "10.0.0.1" {
		t.Fatalf("verifier remoteip = %q; want forwarded client IP", fv.lastRemote)
	}
}

func TestCaptcha_BeginPasskeySignup_PerEndpointToggleOffSkipsCheck(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("would reject if called")}
	h := newHarnessWithCaptcha(t, fv, func(c *config.Config) {
		enableCaptcha(c)
		c.PasskeySignupEnabled = true
		c.CaptchaEnforcePasskeySignup = false
	})

	if _, err := h.client.BeginPasskeySignup(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:      "passkey-captcha@example.com",
		DeviceName: "iPhone",
	}))); err != nil {
		t.Fatalf("BeginPasskeySignup (passkey toggle off): %v", err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called when the passkey toggle is off; calls = %d", fv.calls)
	}
}
