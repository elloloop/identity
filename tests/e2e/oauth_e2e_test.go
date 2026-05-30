//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// TestE2E_OAuth_DisabledFlows verifies that OAuth endpoints properly return
// Connect-RPC error status CodeUnavailable when OAuth is unconfigured.
func TestE2E_OAuth_DisabledFlows(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// 1. BeginOAuthLogin
	resp, status := h.rpcCall(t, "BeginOAuthLogin", map[string]any{
		"redirectUri": "http://localhost/callback",
		"provider":    "google",
	}, "")
	if status == http.StatusOK {
		t.Fatalf("BeginOAuthLogin unexpectedly succeeded when OAuth is disabled: %v", resp)
	}
	code, _ := resp["code"].(string)
	if code != "unavailable" {
		t.Errorf("BeginOAuthLogin code = %q, want 'unavailable'", code)
	}

	// 2. OAuthLogin
	resp, status = h.rpcCall(t, "OAuthLogin", map[string]any{
		"code":        "fake-code",
		"redirectUri": "http://localhost/callback",
		"provider":    "google",
	}, "")
	if status == http.StatusOK {
		t.Fatalf("OAuthLogin unexpectedly succeeded when OAuth is disabled: %v", resp)
	}
	code, _ = resp["code"].(string)
	if code != "unavailable" {
		t.Errorf("OAuthLogin code = %q, want 'unavailable'", code)
	}

	// 3. RedeemOAuthCode
	resp, status = h.rpcCall(t, "RedeemOAuthCode", map[string]any{
		"code": "fake-code",
	}, "")
	if status == http.StatusOK {
		t.Fatalf("RedeemOAuthCode unexpectedly succeeded when OAuth is disabled: %v", resp)
	}
	code, _ = resp["code"].(string)
	if code != "unavailable" {
		t.Errorf("RedeemOAuthCode code = %q, want 'unavailable'", code)
	}
}

// TestE2E_OrganizationSignup_SingleTenantMode verifies that OrganizationSignup
// returns CodeUnimplemented when the service is configured in mode=single (default).
func TestE2E_OrganizationSignup_SingleTenantMode(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	resp, status := h.rpcCall(t, "OrganizationSignup", map[string]any{
		"slug":          "my-cool-org",
		"displayName":   "My Cool Org",
		"adminEmail":    "org-admin@example.com",
		"adminPassword": goodPassword,
		"adminName":     "Org Admin",
	}, "")
	if status == http.StatusOK {
		t.Fatalf("OrganizationSignup unexpectedly succeeded in single-tenant mode: %v", resp)
	}
	code, _ := resp["code"].(string)
	if code != "unimplemented" {
		t.Errorf("OrganizationSignup code = %q, want 'unimplemented'", code)
	}
}
