//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestE2E_EmailHardening_RejectsDisposable blocks signup with the
// well-known disposable-email services. These are designed for
// one-time use and are the #1 vector for free-tier signup abuse
// (one human ↔ unlimited accounts). The block is a built-in list
// of the most common providers; deployers can extend it via the
// GATEWAY_DISPOSABLE_EMAIL_DOMAINS environment variable (CSV).
func TestE2E_EmailHardening_RejectsDisposable(t *testing.T) {
	t.Parallel()
	disposable := []string{
		"abuser@mailinator.com",
		"throwaway@10minutemail.com",
		"spammer@guerrillamail.com",
		"temp@yopmail.com",
		"single-use@tempmail.org",
		"throwaway@trashmail.com",
		"abuser@sharklasers.com", // guerrillamail alias
		"throwaway@dispostable.com",
		"someone@maildrop.cc",
		"someone@getnada.com",
	}
	for _, email := range disposable {
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    email,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("disposable address %q accepted (status=200) — should be rejected", email)
			}
			if status != http.StatusBadRequest {
				t.Errorf("disposable %q: status=%d, want 400", email, status)
			}
		})
	}
}

// TestE2E_EmailHardening_RejectsReservedTLDs covers the RFC-2606 / RFC-6761
// reserved TLDs (.test, .example, .invalid, .localhost) and a few
// internal-only TLDs (.local, .internal) that aren't valid public mail
// domains. Accepting these stores garbage addresses that can never
// receive password resets.
func TestE2E_EmailHardening_RejectsReservedTLDs(t *testing.T) {
	t.Parallel()
	cases := []string{
		"alice@example.test",
		"alice@example.example",
		"alice@example.invalid",
		"alice@example.localhost",
		"alice@server.local",
		"alice@server.internal",
		"alice@bob.localdomain",
	}
	for _, email := range cases {
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    email,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("reserved-TLD %q accepted (status=200) — should be rejected", email)
			}
			if status != http.StatusBadRequest {
				t.Errorf("reserved-TLD %q: status=%d, want 400", email, status)
			}
		})
	}
}

// TestE2E_EmailHardening_RejectsOversized enforces the RFC-5321
// length caps so the storage layer and downstream mail servers don't
// see garbage. Local part max 64, domain max 253, total max 254.
func TestE2E_EmailHardening_RejectsOversized(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		email string
	}{
		{name: "local_part_65_chars", email: strings.Repeat("a", 65) + "@example.com"},
		{name: "local_part_100_chars", email: strings.Repeat("a", 100) + "@example.com"},
		{name: "domain_254_chars", email: "alice@" + strings.Repeat("a", 250) + ".com"},
		{name: "total_255_chars", email: strings.Repeat("a", 64) + "@" + strings.Repeat("b", 190) + ".com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    tc.email,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("oversized %s (len=%d) accepted", tc.name, len(tc.email))
			}
			if status != http.StatusBadRequest {
				t.Errorf("%s: status=%d, want 400", tc.name, status)
			}
		})
	}
}

// TestE2E_EmailHardening_RejectsConsecutiveDots covers the RFC-5322
// rule that the local part may not contain two adjacent dots. Many
// SMTP servers reject these on send.
func TestE2E_EmailHardening_RejectsConsecutiveDots(t *testing.T) {
	t.Parallel()
	cases := []string{
		"a..b@example.com",
		"first..last@example.com",
		"x...y@example.com",
		".alice@example.com",  // leading dot already covered, included for completeness
		"alice.@example.com",  // trailing dot
		"alice@x..y.com",      // consecutive dots in domain
		"alice@x.y..com",      // consecutive dots in domain (different position)
	}
	for _, email := range cases {
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    email,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("consecutive-dot %q accepted", email)
			}
			if status != http.StatusBadRequest {
				t.Errorf("%q: status=%d, want 400", email, status)
			}
		})
	}
}

// TestE2E_EmailHardening_RejectsControlCharacters covers NULL bytes,
// CR/LF (header-injection vector), and other control characters that
// should never appear in an email address.
func TestE2E_EmailHardening_RejectsControlCharacters(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		email string
	}{
		{name: "null_byte", email: "alice\x00@example.com"},
		{name: "carriage_return_in_local", email: "alice\r@example.com"},
		{name: "newline_in_local", email: "alice\n@example.com"},
		{name: "header_injection_attempt", email: "alice@example.com\r\nBcc: attacker@evil.com"},
		{name: "tab_in_domain", email: "alice@exam\tple.com"},
		{name: "backspace", email: "alice\x08@example.com"},
		{name: "del_char", email: "alice\x7f@example.com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    tc.email,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("control-char %s accepted", tc.name)
			}
			if status != http.StatusBadRequest {
				t.Errorf("%s: status=%d, want 400", tc.name, status)
			}
		})
	}
}

// TestE2E_EmailHardening_AcceptsCleanAddressesAfterAllChecks pins the
// positive side: legitimate emails make it through every guard.
// Catches a too-strict validator regression.
func TestE2E_EmailHardening_AcceptsCleanAddressesAfterAllChecks(t *testing.T) {
	t.Parallel()
	cases := []string{
		"alice@example.com",
		"alice.smith@example.com",
		"alice+work@gmail.com", // plus-tag is canonicalized away, signup still OK
		"alice@example.co.uk",
		"alice@subdomain.example.com",
		"a.b.c.d@gmail.com",
		"first-last@example.com",
		"first_last@example.com",
		"alice123@example.com",
	}
	for _, email := range cases {
		email := email
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    email,
				"password": goodPassword,
			}, "")
			if status != http.StatusOK {
				t.Fatalf("clean address %q rejected: status=%d", email, status)
			}
		})
	}
}
