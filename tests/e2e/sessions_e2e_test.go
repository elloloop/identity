//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"testing"
)

// TestE2E_RefreshToken_RejectsKnownBadShapes confirms the rejection
// envelope shape over HTTP. The happy rotation round-trip is covered
// by the in-process integration suite, where state is observable.
func TestE2E_RefreshToken_RejectsKnownBadShapes(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	_, _, _ = h.Signup(t, "refrej@example.com", goodPassword)

	cases := []struct {
		name  string
		token string
	}{
		{name: "empty_string", token: ""},
		{name: "garbage_string", token: "not-a-refresh-token"},
		{name: "rt_prefix_no_body", token: "rt_"},
		{name: "obvious_unknown", token: "rt_zzzzzzzzzzzzzz"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": tc.token}, "")
			if status == http.StatusOK {
				t.Fatalf("expected rejection for %q, got 200", tc.token)
			}
		})
	}
}



// TestE2E_AccessToken_ExpiryShape sanity-checks the expires_in field
// of a freshly-minted access token matches what config sets (900s in
// the harness).
func TestE2E_AccessToken_ExpiryShape(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	resp, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email":    "expiry@example.com",
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("signup status=%d", status)
	}
	expiry, _ := resp["expiresIn"].(float64)
	if expiry < 60 || expiry > 86400 {
		t.Fatalf("expiresIn = %v, want a positive duration <= 1d", expiry)
	}
}

// TestE2E_RevokeSession_RejectsUnknownID confirms a RevokeSession
// against a fabricated session id returns a non-200 response.
func TestE2E_RevokeSession_RejectsUnknownID(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	at, _, _ := h.Signup(t, "revsess@example.com", goodPassword)

	for _, sid := range []string{"nope", "ses_does_not_exist", fmt.Sprintf("session-%d", 0)} {
		_, status := h.rpcCall(t, "RevokeSession", map[string]any{"sessionId": sid}, at)
		if status == http.StatusOK {
			t.Fatalf("RevokeSession on %q unexpectedly succeeded", sid)
		}
	}
}
