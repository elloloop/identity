//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// TestE2E_OAuth_DisabledFlows verifies that OAuth endpoints properly return
// Connect-RPC error status CodeUnavailable when OAuth is unconfigured. The
// return allowlist is cleared too: it alone enables the hosted magic-link
// page, whose handover codes RedeemOAuthCode also redeems.
func TestE2E_OAuth_DisabledFlows(t *testing.T) {
	t.Parallel()
	h := StartServerWith(t, func(c *config.Config) { c.OAuthAllowedReturnURLs = "" }, nil)

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
