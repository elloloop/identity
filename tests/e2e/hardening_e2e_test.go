//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestE2E_UpdateProfile_MemoryBackend_RoundTrip is the regression test
// for the "ProfileService talks to service.DB but the memory backend
// stubs DB out" bug. A deployer running identity with the in-memory
// repository — every dev/test environment, every embedded use — gets
// HTTP 500 from UpdateProfile because the call chain reaches
// service.DB.GetNode which the memory backend short-circuits with
// ErrServiceUnavailable. The fix is to route UpdateProfile through the
// Repository interface (which the memory backend implements fully).
//
// This test asserts the round trip: an authenticated UpdateProfile
// changes the user's name; a subsequent GetCurrentUser reflects the
// change.
func TestE2E_UpdateProfile_MemoryBackend_RoundTrip(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	at, _, _ := h.Signup(t, "upd@example.com", goodPassword)

	resp, status := h.rpcCall(t, "UpdateProfile", map[string]any{
		"name":      "Alice Updated",
		"avatarUrl": "https://example.com/avatar.png",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("UpdateProfile status=%d body=%v", status, resp)
	}

	cur, status := h.rpcCall(t, "GetCurrentUser", map[string]any{}, at)
	if status != http.StatusOK {
		t.Fatalf("GetCurrentUser status=%d body=%v", status, cur)
	}
	user, _ := cur["user"].(map[string]any)
	if user == nil {
		t.Fatalf("GetCurrentUser missing user: %v", cur)
	}
	if got := user["name"]; got != "Alice Updated" {
		t.Errorf("name = %v, want %q", got, "Alice Updated")
	}
	if got := user["avatarUrl"]; got != "https://example.com/avatar.png" {
		t.Errorf("avatarUrl = %v, want %q", got, "https://example.com/avatar.png")
	}
}

// TestE2E_UpdateProfile_PartialUpdates verifies that empty-string
// fields in UpdateProfile leave existing values unchanged (the
// documented "omit-to-skip" behaviour from the RPC proto). Driven over
// HTTP so it covers the JSON proto3 omission semantics too.
func TestE2E_UpdateProfile_PartialUpdates(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	at, _, _ := h.Signup(t, "partial@example.com", goodPassword)

	// First set both fields.
	if _, status := h.rpcCall(t, "UpdateProfile", map[string]any{
		"name":      "First Name",
		"avatarUrl": "https://example.com/first.png",
	}, at); status != http.StatusOK {
		t.Fatalf("initial UpdateProfile status=%d", status)
	}

	// Now update name only; avatar should remain unchanged.
	if _, status := h.rpcCall(t, "UpdateProfile", map[string]any{
		"name": "Second Name",
	}, at); status != http.StatusOK {
		t.Fatalf("partial UpdateProfile status=%d", status)
	}

	cur, _ := h.rpcCall(t, "GetCurrentUser", map[string]any{}, at)
	user, _ := cur["user"].(map[string]any)
	if got := user["name"]; got != "Second Name" {
		t.Errorf("name = %v, want updated", got)
	}
	if got := user["avatarUrl"]; got != "https://example.com/first.png" {
		t.Errorf("avatarUrl = %v, want preserved", got)
	}
}

// TestE2E_PasswordSignup_RejectsMalformedEmail is the regression test
// for the missing-email-validation hardening gap. PasswordSignup
// stores whatever the caller sends without checking it's a valid
// email shape, so `@`, `alice@`, `alice@example` (no TLD) all become
// stored User.email values. That breaks every downstream pathway that
// assumes the email is reachable: password reset emails to a domain
// that doesn't exist, OAuth linking against a never-deliverable
// address, audit trail with junk in the email column.
//
// The fix is a single validator (net/mail.ParseAddress + a require-
// dot-in-domain check) in AuthService.PasswordSignup before the
// dup-check.
func TestE2E_PasswordSignup_RejectsMalformedEmail(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		email string
	}{
		{name: "just_at_sign", email: "@"},
		{name: "local_part_only", email: "alice@"},
		{name: "domain_only", email: "@example.com"},
		{name: "no_at_sign", email: "alice.example.com"},
		{name: "no_tld_in_domain", email: "alice@example"},
		{name: "trailing_dot_only", email: "alice@example."},
		{name: "spaces_in_local", email: "ali ce@example.com"},
		{name: "spaces_in_domain", email: "alice@exam ple.com"},
		{name: "double_at", email: "alice@@example.com"},
		{name: "leading_dot", email: ".alice@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			resp, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    tc.email,
				"password": goodPassword,
			}, "")
			if status == http.StatusOK {
				t.Fatalf("malformed email %q accepted: status=200 body=%v", tc.email, resp)
			}
			if status != http.StatusBadRequest {
				t.Errorf("malformed email %q: status=%d, want 400", tc.email, status)
			}
		})
	}
}

// TestE2E_PasswordSignup_AcceptsValidEmails — the positive side of the
// validation gate. Every entry here is a legitimately-shaped email
// that prior tests verified identity already accepts; this test
// pins the behaviour so a too-strict validator doesn't regress.
func TestE2E_PasswordSignup_AcceptsValidEmails(t *testing.T) {
	t.Parallel()
	cases := []string{
		"alice@example.com",
		"alice.smith@example.com",
		"alice+tag@example.com",
		"alice@mail.example.com",
		"a@b.co",
		strings.Repeat("a", 60) + "@example.com",
		"alïce@example.com", // unicode local part — RFC-compliant
		"alice@example.co.uk",
	}
	for _, email := range cases {
		t.Run(strings.ReplaceAll(email, "@", "_at_"), func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    email,
				"password": goodPassword,
			}, "")
			if status != http.StatusOK {
				t.Fatalf("valid email %q rejected: status=%d", email, status)
			}
		})
	}
}
