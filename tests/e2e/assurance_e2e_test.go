//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/assurance"
)

// stubWebVerifier accepts exactly one captcha token value, standing in
// for Turnstile/reCAPTCHA at the HTTP boundary.
type stubWebVerifier struct{ accept string }

func (stubWebVerifier) Name() string { return "stub-web" }
func (v stubWebVerifier) Verify(_ context.Context, token, _ string) error {
	if token == v.accept {
		return nil
	}
	return assurance.ErrVerificationFailed
}

// startAssuredServer boots the harness with assurance enabled, every
// enforce toggle on, and the stub web verifier injected.
func startAssuredServer(t *testing.T) *Harness {
	t.Helper()
	return StartServerWith(t, func(c *config.Config) {
		c.AssuranceEnabled = true
		c.AssuranceChallengeTTLSeconds = 300
		c.AssuranceTokenTTLSeconds = 3600
		c.AssuranceEnforcePasswordSignup = true
		c.AssuranceEnforcePasswordLogin = true
		c.AssuranceEnforcePasswordReset = true
		c.AssuranceEnforceEmailLoginCode = true
		c.AssuranceEnforceMagicLink = true
		c.AssuranceEnforcePasskeySignup = true
	}, func(d *app.Deps) {
		d.AssuranceWebVerifier = stubWebVerifier{accept: "good-captcha"}
	})
}

// TestAssuranceE2E_WebExchangeGatesSignup drives the full web assurance
// flow over the HTTP wire: exchange a captcha solution for an assurance
// token, then use it to pass the enforced PasswordSignup gate.
func TestAssuranceE2E_WebExchangeGatesSignup(t *testing.T) {
	h := startAssuredServer(t)

	// Unassured signup is rejected (403 PermissionDenied on the wire).
	_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email": "gated@example.com", "password": "Str0ng-Passw0rd!",
	}, "")
	if status != http.StatusForbidden {
		t.Fatalf("unassured signup status = %d; want 403", status)
	}

	// A rejected captcha cannot be exchanged.
	_, status = h.rpcCall(t, "IssueAssuranceToken", map[string]any{
		"platform": "web", "webToken": "bad-captcha",
	}, "")
	if status != http.StatusForbidden {
		t.Fatalf("bad captcha exchange status = %d; want 403", status)
	}

	// A valid captcha exchanges for an assurance token.
	resp, status := h.rpcCall(t, "IssueAssuranceToken", map[string]any{
		"platform": "web", "webToken": "good-captcha",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("exchange status = %d (resp=%v)", status, resp)
	}
	token, _ := resp["assuranceToken"].(string)
	if token == "" {
		t.Fatalf("no assuranceToken in %v", resp)
	}

	// The token passes the signup gate via the X-Assurance-Token header.
	resp, status = h.rpcCallHeaders(t, "PasswordSignup", map[string]any{
		"email": "gated@example.com", "password": "Str0ng-Passw0rd!",
	}, "", map[string]string{assurance.HeaderName: token})
	if status != http.StatusOK {
		t.Fatalf("assured signup status = %d (resp=%v)", status, resp)
	}
	if resp["accessToken"] == "" {
		t.Fatalf("assured signup returned no access token: %v", resp)
	}

	// A garbage assurance token does not.
	_, status = h.rpcCallHeaders(t, "PasswordLogin", map[string]any{
		"email": "gated@example.com", "password": "Str0ng-Passw0rd!",
	}, "", map[string]string{assurance.HeaderName: "garbage"})
	if status != http.StatusForbidden {
		t.Fatalf("garbage-token login status = %d; want 403", status)
	}

	// The real token is reusable within its TTL for login too.
	_, status = h.rpcCallHeaders(t, "PasswordLogin", map[string]any{
		"email": "gated@example.com", "password": "Str0ng-Passw0rd!",
	}, "", map[string]string{assurance.HeaderName: token})
	if status != http.StatusOK {
		t.Fatalf("assured login status = %d", status)
	}
}

// TestAssuranceE2E_ChallengeSurface exercises the mobile challenge RPC
// over the wire: nonce issuance, platform validation, and the
// unconfigured-platform rejection for evidence exchange. (The full App
// Attest cryptographic path is covered by the service-layer tests with a
// synthetic CA; the wire adds the JWT-exemption and JSON shape.)
func TestAssuranceE2E_ChallengeSurface(t *testing.T) {
	h := startAssuredServer(t)

	resp, status := h.rpcCall(t, "CreateAssuranceChallenge", map[string]any{"platform": "ios"}, "")
	if status != http.StatusOK {
		t.Fatalf("challenge status = %d (resp=%v)", status, resp)
	}
	if resp["challengeId"] == "" || resp["challenge"] == "" {
		t.Fatalf("challenge incomplete: %v", resp)
	}

	if _, status := h.rpcCall(t, "CreateAssuranceChallenge", map[string]any{"platform": "windows"}, ""); status != http.StatusBadRequest {
		t.Fatalf("bad platform status = %d; want 400", status)
	}

	// iOS evidence with no App Attest configured: 501 Unimplemented.
	if _, status := h.rpcCall(t, "IssueAssuranceToken", map[string]any{
		"platform": "ios", "challengeId": resp["challengeId"], "keyId": "a2V5",
	}, ""); status != http.StatusNotImplemented {
		t.Fatalf("unconfigured ios status = %d; want 501", status)
	}
}

// TestAssuranceE2E_DisabledDeploymentUnchanged pins the default-off
// posture: with assurance disabled nothing is gated and the assurance
// surface reports Unimplemented.
func TestAssuranceE2E_DisabledDeploymentUnchanged(t *testing.T) {
	h := StartServer(t)

	if _, _, userID := h.Signup(t, "plain@example.com", "Str0ng-Passw0rd!"); userID == "" {
		t.Fatal("signup failed on a disabled deployment")
	}
	if _, status := h.rpcCall(t, "CreateAssuranceChallenge", map[string]any{"platform": "ios"}, ""); status != http.StatusNotImplemented {
		t.Fatalf("disabled challenge status = %d; want 501", status)
	}
}
