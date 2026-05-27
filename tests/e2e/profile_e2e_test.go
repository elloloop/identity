//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// TestE2E_ChangePassword_RejectionMatrix tests every shape the
// ChangePassword call can be wrong: bad current, weak new, missing
// bearer. The happy-path round-trip is covered by the in-process
// integration test in tests/integration; this matrix focuses on the
// HTTP-surface rejection envelopes.
func TestE2E_ChangePassword_RejectionMatrix(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	at, _, _ := h.Signup(t, "chgmatrix@example.com", goodPassword)

	cases := []struct {
		name        string
		token       string
		curPassword string
		newPassword string
	}{
		{name: "wrong_current", token: at, curPassword: "Wr0ng!Pass", newPassword: "Bigger!Pass99"},
		{name: "weak_new_too_short", token: at, curPassword: goodPassword, newPassword: "Ab1!"},
		{name: "weak_new_no_special", token: at, curPassword: goodPassword, newPassword: "NoSpec1234"},
		{name: "weak_new_no_digit", token: at, curPassword: goodPassword, newPassword: "NoDigits!Abcd"},
		{name: "missing_bearer", token: "", curPassword: goodPassword, newPassword: "Bigger!Pass99"},
		{name: "garbage_bearer", token: "garbage", curPassword: goodPassword, newPassword: "Bigger!Pass99"},
		{name: "empty_new", token: at, curPassword: goodPassword, newPassword: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "ChangePassword", map[string]any{
				"currentPassword": tc.curPassword,
				"newPassword":     tc.newPassword,
			}, tc.token)
			if status == http.StatusOK {
				t.Fatalf("expected rejection for %s, got 200", tc.name)
			}
		})
	}
}

// TestE2E_RequestPasswordReset_AlwaysAccepts covers anti-enumeration on
// the reset request: every variant (existing / non-existing / weird)
// returns 200 so an attacker can't probe.
func TestE2E_RequestPasswordReset_AlwaysAccepts(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	h.Signup(t, "reset@example.com", goodPassword)

	cases := []string{
		"reset@example.com",
		"ghost@example.com",
		"weird+addr@sub.example.com",
		"NOREG@example.com",
	}
	for _, email := range cases {
		email := email
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "RequestPasswordReset", map[string]any{"email": email}, "")
			if status != http.StatusOK {
				t.Fatalf("RequestPasswordReset for %q: status=%d, want 200 (anti-enumeration)", email, status)
			}
		})
	}
}

// TestE2E_ConfirmPasswordReset_RejectionMatrix covers the bad-token
// rejection paths over HTTP. The happy round-trip needs the email
// recovery-address pipeline which is exercised separately.
func TestE2E_ConfirmPasswordReset_RejectionMatrix(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	cases := []struct {
		name        string
		token       string
		newPassword string
	}{
		{name: "empty_token", token: "", newPassword: "Bigger!Pass99"},
		{name: "garbage_token", token: "not-a-token", newPassword: "Bigger!Pass99"},
		{name: "weak_password", token: "prt_zzzz", newPassword: "weak"},
		{name: "empty_password", token: "prt_zzzz", newPassword: ""},
		{name: "obvious_unknown", token: "prt_does_not_exist", newPassword: "Bigger!Pass99"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "ConfirmPasswordReset", map[string]any{
				"token":       tc.token,
				"newPassword": tc.newPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("expected rejection for %s, got 200", tc.name)
			}
		})
	}
}
