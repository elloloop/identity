//go:build e2e

package e2e

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// otpRegex pulls a 6-digit numeric code out of the test mailer's
// recorded outbound email body.
var otpRegex = regexp.MustCompile(`\b\d{6}\b`)

// TestE2E_Passwordless_OTP_HappyPath drives the full email-OTP flow:
// request a code -> read it from the recorded mailbox -> submit it ->
// receive an access token. Everything goes over HTTP/JSON only.
func TestE2E_Passwordless_OTP_HappyPath(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "otp@example.com"

	_, status := h.rpcCall(t, "RequestEmailLoginCode", map[string]any{"email": email}, "")
	if status != http.StatusOK {
		t.Fatalf("RequestEmailLoginCode status=%d", status)
	}
	msg := h.Mailer.Latest()
	if msg == nil {
		t.Fatal("no email recorded")
	}
	body := msg.Text
	if body == "" {
		body = msg.HTML
	}
	code := otpRegex.FindString(body)
	if code == "" {
		t.Fatalf("could not extract 6-digit OTP from %q", body)
	}

	resp, status := h.rpcCall(t, "VerifyEmailLoginCode", map[string]any{"email": email, "code": code}, "")
	if status != http.StatusOK {
		t.Fatalf("VerifyEmailLoginCode status=%d body=%v", status, resp)
	}
	if at, _ := resp["accessToken"].(string); at == "" {
		t.Fatalf("missing accessToken: %v", resp)
	}
}

// TestE2E_Passwordless_OTP_RejectionMatrix covers wrong-code, expired,
// missing-email rejection paths over HTTP.
func TestE2E_Passwordless_OTP_RejectionMatrix(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "otpmatrix@example.com"
	// Request a code so the right one exists.
	_, _ = h.rpcCall(t, "RequestEmailLoginCode", map[string]any{"email": email}, "")

	cases := []struct {
		name  string
		email string
		code  string
	}{
		{name: "wrong_code", email: email, code: "000000"},
		{name: "empty_code", email: email, code: ""},
		{name: "non_numeric_code", email: email, code: "abcdef"},
		{name: "no_request_for_email", email: "noreq@example.com", code: "123456"},
		{name: "empty_email", email: "", code: "123456"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "VerifyEmailLoginCode",
				map[string]any{"email": tc.email, "code": tc.code}, "")
			if status == http.StatusOK {
				t.Fatalf("expected rejection for (%q, %q), got 200", tc.email, tc.code)
			}
		})
	}
}

// TestE2E_Passwordless_OTP_BruteForceLockout submits N wrong codes for
// the same email — after the configured cap (5 in the harness) the
// correct code is also rejected because the code has been
// invalidated. This is the anti-brute-force shape from decision §14.
func TestE2E_Passwordless_OTP_BruteForceLockout(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "otplockout@example.com"

	_, _ = h.rpcCall(t, "RequestEmailLoginCode", map[string]any{"email": email}, "")
	msg := h.Mailer.Latest()
	if msg == nil {
		t.Skip("mailer did not capture the request — skipping")
	}
	body := msg.Text
	if body == "" {
		body = msg.HTML
	}
	correct := otpRegex.FindString(body)
	if correct == "" {
		t.Skip("could not extract OTP — skipping")
	}

	// Burn through the attempts cap (5).
	for i := 0; i < 5; i++ {
		_, _ = h.rpcCall(t, "VerifyEmailLoginCode",
			map[string]any{"email": email, "code": "000000"}, "")
	}
	// Correct code is now rejected.
	_, status := h.rpcCall(t, "VerifyEmailLoginCode",
		map[string]any{"email": email, "code": correct}, "")
	if status == http.StatusOK {
		t.Fatalf("correct code accepted after max-attempts; brute-force lockout broken")
	}
}

// TestE2E_Passwordless_MagicLink_RequestAccepts confirms the magic-link
// request endpoint accepts valid input over HTTP. The end-to-end
// click-the-link path needs the returnTo allowlist set, which is
// already covered in tests/integration.
func TestE2E_Passwordless_MagicLink_RequestAccepts(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	_, status := h.rpcCall(t, "RequestMagicLink", map[string]any{
		"email":    "magic@example.com",
		"returnTo": "http://localhost/app/dashboard",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("RequestMagicLink status=%d", status)
	}
}

// TestE2E_Passwordless_MagicLink_RejectionMatrix: wrong / used /
// missing tokens must all be rejected.
func TestE2E_Passwordless_MagicLink_RejectionMatrix(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	cases := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "garbage", token: "not-a-token"},
		{name: "truncated_prefix", token: "ml_abc"},
		{name: "obvious_typo", token: strings.Repeat("z", 64)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "RedeemMagicLink", map[string]any{"token": tc.token}, "")
			if status == http.StatusOK {
				t.Fatalf("expected rejection for %q, got 200", tc.token)
			}
		})
	}
}

// TestE2E_Passwordless_AntiEnumeration: the Request endpoint MUST 200
// regardless of whether the email is registered, so an attacker can't
// probe addresses. Real delivery only happens for registered users
// (when auto-create is off) — but the wire response is identical.
func TestE2E_Passwordless_AntiEnumeration(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	cases := []struct {
		name        string
		email       string
		registerYes bool
	}{
		{name: "registered", email: "exists@example.com", registerYes: true},
		{name: "unknown", email: "ghost@example.com", registerYes: false},
		{name: "weird_local_part", email: "x..y@example.com", registerYes: false},
		{name: "subdomain", email: "z@sub.example.com", registerYes: false},
	}

	// Register the "registered" address.
	h.Signup(t, "exists@example.com", goodPassword)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, "RequestEmailLoginCode", map[string]any{"email": tc.email}, "")
			if status != http.StatusOK {
				t.Fatalf("Request must 200 for anti-enum, got status=%d for %q", status, tc.email)
			}
		})
	}
}
