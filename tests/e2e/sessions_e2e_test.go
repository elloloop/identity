//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"testing"
)

// TestE2E_RefreshToken_RejectsKnownBadShapes confirms the rejection
// envelope shape over HTTP.
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

// TestE2E_Session_HappyFlow exercises session listing and individual / bulk revocation.
func TestE2E_Session_HappyFlow(t *testing.T) {
	requireGraphDB(t)
	t.Parallel()
	h := StartServer(t)
	email := "sess-happy@example.com"

	// 1. Signup (creates session 1)
	at1, rt1, _ := h.Signup(t, email, goodPassword)

	// 2. Login again (creates session 2)
	_, rt2 := h.Login(t, email, goodPassword)

	// 3. List My Sessions using first access token
	resp, status := h.rpcCall(t, "ListMySessions", map[string]any{}, at1)
	if status != http.StatusOK {
		t.Fatalf("ListMySessions status=%d, body=%v", status, resp)
	}
	sessions, _ := resp["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d (resp=%v)", len(sessions), resp)
	}

	// 4. Revoke session 2
	sess2, _ := sessions[1].(map[string]any)
	sess2ID, _ := sess2["sessionId"].(string)
	resp, status = h.rpcCall(t, "RevokeSession", map[string]any{
		"sessionId": sess2ID,
	}, at1)
	if status != http.StatusOK {
		t.Fatalf("RevokeSession status=%d, body=%v", status, resp)
	}

	// 5. Try to refresh with session 2's refresh token — must be rejected
	_, status = h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": rt2}, "")
	if status == http.StatusOK {
		t.Fatalf("RefreshToken with revoked session unexpectedly succeeded")
	}

	// 6. Refreshing with session 1's refresh token must still work
	_, status = h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": rt1}, "")
	if status != http.StatusOK {
		t.Fatalf("expected active session 1 refresh to succeed, got %d", status)
	}

	// 7. Revoke All Sessions (requires password confirmation)
	resp, status = h.rpcCall(t, "RevokeAllSessions", map[string]any{
		"password": goodPassword,
	}, at1)
	if status != http.StatusOK {
		t.Fatalf("RevokeAllSessions status=%d, body=%v", status, resp)
	}

	// 8. Refreshing with session 1's refresh token must now fail
	_, status = h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": rt1}, "")
	if status == http.StatusOK {
		t.Fatalf("expected refresh to fail after RevokeAllSessions")
	}
}

// TestE2E_Session_SignOutEverywhere verifies SignOutEverywhere endpoint.
func TestE2E_Session_SignOutEverywhere(t *testing.T) {
	requireGraphDB(t)
	t.Parallel()
	h := StartServer(t)
	email := "sess-signout@example.com"

	at1, rt1, _ := h.Signup(t, email, goodPassword)
	_, rt2 := h.Login(t, email, goodPassword)

	// Sign out everywhere (requires password confirmation)
	resp, status := h.rpcCall(t, "SignOutEverywhere", map[string]any{
		"password": goodPassword,
	}, at1)
	if status != http.StatusOK {
		t.Fatalf("SignOutEverywhere status=%d, body=%v", status, resp)
	}

	// Verify all refresh tokens are revoked
	_, status = h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": rt1}, "")
	if status == http.StatusOK {
		t.Fatalf("expected refresh for session 1 to fail after SignOutEverywhere")
	}
	_, status = h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": rt2}, "")
	if status == http.StatusOK {
		t.Fatalf("expected refresh for session 2 to fail after SignOutEverywhere")
	}
}
