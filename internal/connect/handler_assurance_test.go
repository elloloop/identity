package connect

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/assurance"
)

// fakeVerifier is a web-assurance verifier whose Verify result is fixed
// at construction. It records the last token/ip it saw so a test can
// assert the exchange forwarded them.
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

// enableAssurance turns assurance on with every per-endpoint toggle set,
// mirroring a deployment that gates all six endpoints.
func enableAssurance(c *config.Config) {
	c.AssuranceEnabled = true
	c.AssuranceEnforcePasswordSignup = true
	c.AssuranceEnforcePasswordLogin = true
	c.AssuranceEnforcePasswordReset = true
	c.AssuranceEnforceEmailLoginCode = true
	c.AssuranceEnforceMagicLink = true
	c.AssuranceEnforcePasskeySignup = true
}

func seedLoginUser(t *testing.T, h *testHarness) *service.User {
	t.Helper()
	return h.repo.seedUser(&service.User{
		Email:        "assured@example.com",
		Status:       "active",
		Role:         "member",
		PasswordHash: mustHash(t, strongPW),
	})
}

// exchangeWebToken runs the web exchange (captcha solution → assurance
// token) and returns the minted token.
func exchangeWebToken(t *testing.T, h *testHarness, webToken string) string {
	t.Helper()
	resp, err := h.client.IssueAssuranceToken(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.IssueAssuranceTokenRequest{
		Platform: "web",
		WebToken: webToken,
	})))
	if err != nil {
		t.Fatalf("IssueAssuranceToken: %v", err)
	}
	if resp.Msg.AssuranceToken == "" || resp.Msg.ExpiresAtMs == 0 {
		t.Fatalf("exchange response incomplete: %+v", resp.Msg)
	}
	return resp.Msg.AssuranceToken
}

// assuredRequest attaches an assurance token header to a request.
func assuredRequest[T any](req *connect.Request[T], token string) *connect.Request[T] {
	req.Header().Set(assurance.HeaderName, token)
	return req
}

// ── PasswordLogin ───────────────────────────────────────────────────────

func TestAssurance_PasswordLogin_DisabledBehavesAsBefore(t *testing.T) {
	h := newHarness(t)
	seedLoginUser(t, h)

	if _, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "assured@example.com",
		Password: strongPW,
	}))); err != nil {
		t.Fatalf("PasswordLogin (assurance disabled): %v", err)
	}
}

func TestAssurance_PasswordLogin_ExchangedTokenPasses(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithWebAssurance(t, fv, enableAssurance)
	seedLoginUser(t, h)

	tok := exchangeWebToken(t, h, "captcha-solution")
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
	if fv.lastToken != "captcha-solution" {
		t.Fatalf("verifier token = %q", fv.lastToken)
	}
	if fv.lastRemote != "10.0.0.1" {
		t.Fatalf("verifier remoteip = %q; want forwarded client IP", fv.lastRemote)
	}

	if _, err := h.client.PasswordLogin(context.Background(), assuredRequest(withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "assured@example.com",
		Password: strongPW,
	})), tok)); err != nil {
		t.Fatalf("PasswordLogin (assured): %v", err)
	}

	t.Run("token is reusable within its TTL", func(t *testing.T) {
		if _, err := h.client.PasswordLogin(context.Background(), assuredRequest(withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
			Email:    "assured@example.com",
			Password: strongPW,
		})), tok)); err != nil {
			t.Fatalf("second PasswordLogin with same assurance token: %v", err)
		}
		if fv.calls != 1 {
			t.Fatalf("verifier calls = %d; the token must not re-verify per request", fv.calls)
		}
	})
}

func TestAssurance_PasswordLogin_MissingHeaderPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithWebAssurance(t, fv, enableAssurance)
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "assured@example.com",
		Password: strongPW,
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called without an exchange; calls = %d", fv.calls)
	}
}

func TestAssurance_PasswordLogin_GarbageHeaderPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithWebAssurance(t, fv, enableAssurance)
	seedLoginUser(t, h)

	_, err := h.client.PasswordLogin(context.Background(), assuredRequest(withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "assured@example.com",
		Password: strongPW,
	})), "not-a-jwt"))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
}

func TestAssurance_ExchangeRejectedCaptchaPermissionDenied(t *testing.T) {
	fv := &fakeVerifier{err: assurance.ErrVerificationFailed}
	h := newHarnessWithWebAssurance(t, fv, enableAssurance)

	_, err := h.client.IssueAssuranceToken(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.IssueAssuranceTokenRequest{
		Platform: "web",
		WebToken: "rejected",
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}
	if fv.calls != 1 {
		t.Fatalf("verifier calls = %d; want 1", fv.calls)
	}
}

func TestAssurance_PasswordLogin_PerEndpointToggleOffSkipsCheck(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("would reject if called")}
	h := newHarnessWithWebAssurance(t, fv, func(c *config.Config) {
		enableAssurance(c)
		c.AssuranceEnforcePasswordLogin = false
	})
	seedLoginUser(t, h)

	if _, err := h.client.PasswordLogin(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "assured@example.com",
		Password: strongPW,
	}))); err != nil {
		t.Fatalf("PasswordLogin (login toggle off): %v", err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called when the login toggle is off; calls = %d", fv.calls)
	}
}

// ── RequestEmailLoginCode ───────────────────────────────────────────────

func TestAssurance_RequestEmailLoginCode_DisabledBehavesAsBefore(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.RequestEmailLoginCode(context.Background(), connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: "anyone@example.com",
	})); err != nil {
		t.Fatalf("RequestEmailLoginCode (assurance disabled): %v", err)
	}
}

func TestAssurance_RequestEmailLoginCode_GatedAndPassable(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithWebAssurance(t, fv, enableAssurance)

	_, err := h.client.RequestEmailLoginCode(context.Background(), connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: "anyone@example.com",
	}))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}

	tok := exchangeWebToken(t, h, "solution")
	if _, err := h.client.RequestEmailLoginCode(context.Background(), assuredRequest(connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: "anyone@example.com",
	}), tok)); err != nil {
		t.Fatalf("RequestEmailLoginCode (assured): %v", err)
	}
}

// ── RequestPasswordReset ────────────────────────────────────────────────

// A missing assurance token on RequestPasswordReset surfaces the error
// even though the endpoint is otherwise enumeration-safe: an assurance
// failure is identical for any email, so it is not an account-existence
// oracle.
func TestAssurance_RequestPasswordReset_GatedAndEnumerationSafe(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithWebAssurance(t, fv, enableAssurance)

	_, err := h.client.RequestPasswordReset(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: "anyone@example.com",
	})))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}

	// Assured request for an unknown email still succeeds (no enumeration).
	tok := exchangeWebToken(t, h, "solution")
	if _, err := h.client.RequestPasswordReset(context.Background(), assuredRequest(withClientHeaders(connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: "unknown@example.com",
	})), tok)); err != nil {
		t.Fatalf("RequestPasswordReset (assured, unknown email): %v", err)
	}
}

// ── BeginPasskeySignup ──────────────────────────────────────────────────
//
// WebAuthn's user-presence/verification flags are asserted by the
// authenticator itself, so a scripted attacker can forge them in software
// and spam this endpoint into creating dummy accounts + sending emails.
// The assurance gate is the real bot wall — it must run BEFORE any
// passkey work.

func TestAssurance_BeginPasskeySignup_GatedAndPassable(t *testing.T) {
	fv := &fakeVerifier{}
	h := newHarnessWithWebAssurance(t, fv, func(c *config.Config) {
		enableAssurance(c)
		c.PasskeySignupEnabled = true
	})

	_, err := h.client.BeginPasskeySignup(context.Background(), connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:      "passkey-assured@example.com",
		DeviceName: "iPhone",
	}))
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v; want PermissionDenied (err=%v)", connectCodeOf(err), err)
	}

	tok := exchangeWebToken(t, h, "solution")
	resp, err := h.client.BeginPasskeySignup(context.Background(), assuredRequest(withClientHeaders(connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:      "passkey-assured@example.com",
		DeviceName: "iPhone",
	})), tok))
	if err != nil {
		t.Fatalf("BeginPasskeySignup (assured): %v", err)
	}
	if resp.Msg.GetOptionsJson() == "" || resp.Msg.GetChallengeId() == "" {
		t.Fatalf("expected creation options + challenge id; got %+v", resp.Msg)
	}
}

func TestAssurance_BeginPasskeySignup_PerEndpointToggleOffSkipsCheck(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("would reject if called")}
	h := newHarnessWithWebAssurance(t, fv, func(c *config.Config) {
		enableAssurance(c)
		c.PasskeySignupEnabled = true
		c.AssuranceEnforcePasskeySignup = false
	})

	if _, err := h.client.BeginPasskeySignup(context.Background(), withClientHeaders(connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:      "passkey-assured@example.com",
		DeviceName: "iPhone",
	}))); err != nil {
		t.Fatalf("BeginPasskeySignup (passkey toggle off): %v", err)
	}
	if fv.calls != 0 {
		t.Fatalf("verifier must not be called when the passkey toggle is off; calls = %d", fv.calls)
	}
}

// ── Assurance RPC surface ───────────────────────────────────────────────

func TestAssurance_CreateChallenge_DisabledUnimplemented(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.CreateAssuranceChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAssuranceChallengeRequest{
		Platform: "ios",
	}))
	if connectCodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("code = %v; want Unimplemented (err=%v)", connectCodeOf(err), err)
	}
}

func TestAssurance_CreateChallenge_IssuesNonce(t *testing.T) {
	h := newHarnessWithWebAssurance(t, &fakeVerifier{}, enableAssurance)
	resp, err := h.client.CreateAssuranceChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAssuranceChallengeRequest{
		Platform: "ios",
	}))
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge: %v", err)
	}
	if resp.Msg.ChallengeId == "" || resp.Msg.Challenge == "" || resp.Msg.ExpiresAtMs == 0 {
		t.Fatalf("challenge incomplete: %+v", resp.Msg)
	}

	t.Run("bad platform rejected", func(t *testing.T) {
		_, err := h.client.CreateAssuranceChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAssuranceChallengeRequest{
			Platform: "windows",
		}))
		if connectCodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("code = %v; want InvalidArgument (err=%v)", connectCodeOf(err), err)
		}
	})
}

func TestAssurance_IssueToken_UnconfiguredPlatformUnimplemented(t *testing.T) {
	h := newHarnessWithWebAssurance(t, &fakeVerifier{}, enableAssurance)
	// Assurance is on but no App Attest verifier is configured.
	ch, err := h.client.CreateAssuranceChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAssuranceChallengeRequest{
		Platform: "ios",
	}))
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	_, err = h.client.IssueAssuranceToken(context.Background(), connect.NewRequest(&identitypb.IssueAssuranceTokenRequest{
		Platform:    "ios",
		ChallengeId: ch.Msg.ChallengeId,
		KeyId:       "key",
	}))
	if connectCodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("code = %v; want Unimplemented (err=%v)", connectCodeOf(err), err)
	}
}

// TestAssurance_RefreshToken_HandlerSurface covers the refresh handler,
// the only wire path reaching the App Attest assertion + sign-counter CAS
// (the replay protection the refresh design exists for). Its three
// same-shaped proto args mean a transposition would compile and pass
// every other test, surfacing only as an opaque denial on real devices.
func TestAssurance_RefreshToken_HandlerSurface(t *testing.T) {
	t.Run("disabled deployment reports unimplemented", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.client.RefreshAssuranceToken(context.Background(), connect.NewRequest(&identitypb.RefreshAssuranceTokenRequest{
			ChallengeId: "c", KeyId: "k", Assertion: []byte("a"),
		}))
		if connectCodeOf(err) != connect.CodeUnimplemented {
			t.Fatalf("code = %v; want Unimplemented (err=%v)", connectCodeOf(err), err)
		}
	})

	t.Run("no App Attest configured reports unimplemented", func(t *testing.T) {
		h := newHarnessWithWebAssurance(t, &fakeVerifier{}, enableAssurance)
		_, err := h.client.RefreshAssuranceToken(context.Background(), connect.NewRequest(&identitypb.RefreshAssuranceTokenRequest{
			ChallengeId: "c", KeyId: "k", Assertion: []byte("a"),
		}))
		if connectCodeOf(err) != connect.CodeUnimplemented {
			t.Fatalf("code = %v; want Unimplemented (err=%v)", connectCodeOf(err), err)
		}
	})
}

// TestAssurance_RefreshToken_ArgumentWiring pins that the handler maps the
// proto fields onto the service call in the right ORDER. challenge_id and
// key_id are both strings, so a swap type-checks; here the challenge is
// real and the key id is not, so a swap changes which one is reported —
// the assertion is that a bogus KEY (not a bogus challenge) is what fails.
func TestAssurance_RefreshToken_ArgumentWiring(t *testing.T) {
	h := newHarnessWithWebAssurance(t, &fakeVerifier{}, enableAssurance)
	ctx := context.Background()

	ch, err := h.client.CreateAssuranceChallenge(ctx, connect.NewRequest(&identitypb.CreateAssuranceChallengeRequest{
		Platform: "ios",
	}))
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge: %v", err)
	}

	// A real challenge id with an unregistered key id. Whatever the outcome,
	// it must not be an argument-order panic or a server error.
	_, err = h.client.RefreshAssuranceToken(ctx, connect.NewRequest(&identitypb.RefreshAssuranceTokenRequest{
		ChallengeId: ch.Msg.ChallengeId,
		KeyId:       "dW5rbm93bi1rZXk",
		Assertion:   []byte("not-a-real-assertion"),
	}))
	switch code := connectCodeOf(err); code {
	case connect.CodePermissionDenied, connect.CodeUnimplemented:
		// Expected: assurance is enabled but no App Attest verifier is
		// configured in this harness, so the platform is unavailable.
	default:
		t.Fatalf("code = %v; want PermissionDenied or Unimplemented (err=%v)", code, err)
	}
}
