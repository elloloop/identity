//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// TestE2E_EmailCanonicalization_GmailDotsAreIgnored is the cornerstone
// of the dedup story: a Gmail user that signs up as alice.smith and
// later tries to log in as alicesmith (no dot) is the SAME human and
// should resolve to the SAME account. Gmail's own SMTP layer treats
// dots in @gmail.com local parts as cosmetic; identity mirrors that
// so one human === one account.
func TestE2E_EmailCanonicalization_GmailDotsAreIgnored(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// Signup with dots in the local part.
	_, _, uid := h.Signup(t, "alice.smith@gmail.com", goodPassword)

	// Login with the dot-stripped equivalent — must succeed and resolve
	// to the same user id.
	resp, status := h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    "alicesmith@gmail.com",
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login as canonical-equivalent: status=%d body=%v", status, resp)
	}
	loggedIn, _ := resp["user"].(map[string]any)
	if loggedIn == nil {
		t.Fatalf("missing user in login response: %v", resp)
	}
	if got := loggedIn["id"]; got != uid {
		t.Fatalf("logged-in user id = %v, want signup id %q (dot-stripping not honoured)", got, uid)
	}
}

// TestE2E_EmailCanonicalization_PlusTagsAreIgnored covers the
// universal plus-tag rule. Most modern mail servers support `+`
// addressing (Gmail, Outlook, FastMail, ProtonMail, Yandex); the
// canonical form is the un-tagged address. A user that signs up as
// arun+app1 and logs in as arun (or arun+app2) is the same human.
func TestE2E_EmailCanonicalization_PlusTagsAreIgnored(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		signupEmail string
		loginEmail  string
	}{
		{name: "gmail_with_plus", signupEmail: "arun+app1@gmail.com", loginEmail: "arun@gmail.com"},
		{name: "gmail_two_plus_tags", signupEmail: "arun+app1@gmail.com", loginEmail: "arun+app2@gmail.com"},
		{name: "outlook_with_plus", signupEmail: "bob+invoices@outlook.com", loginEmail: "bob@outlook.com"},
		{name: "custom_domain_with_plus", signupEmail: "carol+spam@example.com", loginEmail: "carol@example.com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, _, uid := h.Signup(t, tc.signupEmail, goodPassword)

			resp, status := h.rpcCall(t, "PasswordLogin", map[string]any{
				"email":    tc.loginEmail,
				"password": goodPassword,
			}, "")
			if status != http.StatusOK {
				t.Fatalf("login %q after signup %q: status=%d", tc.loginEmail, tc.signupEmail, status)
			}
			user, _ := resp["user"].(map[string]any)
			if got := user["id"]; got != uid {
				t.Fatalf("login %q resolved to %v, want signup id %q", tc.loginEmail, got, uid)
			}
		})
	}
}

// TestE2E_EmailCanonicalization_NonGmailDotsArePreserved is the
// negative twin: dot-stripping must NOT apply to non-Gmail domains.
// Many SMTP servers (university edu domains, Outlook in some
// configurations, custom corporate mail) treat dots as significant.
// Two non-Gmail addresses that differ only in dot placement must
// remain distinct accounts.
func TestE2E_EmailCanonicalization_NonGmailDotsArePreserved(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		firstSig  string
		secondSig string
	}{
		{name: "outlook", firstSig: "first.last@outlook.com", secondSig: "firstlast@outlook.com"},
		{name: "custom_edu", firstSig: "first.last@university.edu", secondSig: "firstlast@university.edu"},
		{name: "fastmail", firstSig: "user.name@fastmail.com", secondSig: "username@fastmail.com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, _, firstID := h.Signup(t, tc.firstSig, goodPassword)

			// The second signup should be a DIFFERENT user (or at least
			// not silently log in as the first one). We assert the
			// stronger version: a login with the second variant against
			// the first user's password should fail because no user
			// exists at that canonical form.
			_, status := h.rpcCall(t, "PasswordLogin", map[string]any{
				"email":    tc.secondSig,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("non-Gmail dot variant %q should NOT resolve to first signup %q (id %q)",
					tc.secondSig, tc.firstSig, firstID)
			}
		})
	}
}

// TestE2E_EmailCanonicalization_GoogleMailCollapses pins
// googlemail.com -> gmail.com normalization. Google treats them as
// the same domain; identity should too.
func TestE2E_EmailCanonicalization_GoogleMailCollapses(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	_, _, uid := h.Signup(t, "test.user+work@googlemail.com", goodPassword)

	resp, status := h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    "testuser@gmail.com",
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login after googlemail signup: status=%d body=%v", status, resp)
	}
	user, _ := resp["user"].(map[string]any)
	if got := user["id"]; got != uid {
		t.Fatalf("googlemail did not collapse to gmail (login id=%v, signup id=%q)", got, uid)
	}
}
