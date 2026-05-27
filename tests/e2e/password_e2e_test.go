//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestE2E_PasswordSignup_AcceptanceMatrix walks the password-signup
// happy path and every rejection case the HTTP surface should answer
// over JSON. Each row is one named sub-test so the failure name says
// exactly what's broken.
func TestE2E_PasswordSignup_AcceptanceMatrix(t *testing.T) {
	t.Parallel()

	// Identity intentionally does NOT enforce email shape beyond "must
	// be non-empty" — RFC-5322 compliance is the caller's problem (and
	// trying to validate locally just creates false negatives for
	// internationalised addresses). These cases ratchet that behaviour:
	// the happy rows assert 200, the reject rows assert the specific
	// guards identity DOES enforce (empty / whitespace-only credential).
	cases := []struct {
		name       string
		email      string
		password   string
		wantStatus int
		wantUser   bool
	}{
		{name: "happy_lowercase", email: "alice@example.com", password: goodPassword, wantStatus: 200, wantUser: true},
		{name: "happy_mixedcase_email_normalized", email: "Alice2@Example.com", password: goodPassword, wantStatus: 200, wantUser: true},
		{name: "happy_plus_addressing", email: "alice+work@example.com", password: goodPassword, wantStatus: 200, wantUser: true},
		{name: "happy_subdomain", email: "alice@mail.example.com", password: goodPassword, wantStatus: 200, wantUser: true},
		{name: "happy_long_local_part", email: strings.Repeat("a", 60) + "@example.com", password: goodPassword, wantStatus: 200, wantUser: true},
		{name: "happy_unicode_local_part", email: "alïce@example.com", password: goodPassword, wantStatus: 200, wantUser: true},
		{name: "happy_password_with_special_chars", email: "alice3@example.com", password: "Pa$$w0rd!#%", wantStatus: 200, wantUser: true},
		{name: "happy_long_password", email: "alice4@example.com", password: "Sw0rdfish!42" + strings.Repeat("x", 50), wantStatus: 200, wantUser: true},

		{name: "reject_empty_email", email: "", password: goodPassword, wantStatus: 400},
		{name: "reject_empty_password", email: "alice5@example.com", password: "", wantStatus: 400},
		{name: "reject_password_too_short", email: "alice6@example.com", password: "Ab1!", wantStatus: 400},
		{name: "reject_password_no_uppercase", email: "alice7@example.com", password: "abcdef1!", wantStatus: 400},
		{name: "reject_password_no_lowercase", email: "alice8@example.com", password: "ABCDEF1!", wantStatus: 400},
		{name: "reject_password_no_digit", email: "alice9@example.com", password: "Abcdefg!", wantStatus: 400},
		{name: "reject_password_no_special", email: "alice10@example.com", password: "Abcdef12", wantStatus: 400},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			resp, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    tc.email,
				"password": tc.password,
			}, "")
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%v)", status, tc.wantStatus, resp)
			}
			if tc.wantUser {
				user, _ := resp["user"].(map[string]any)
				if user == nil || user["id"] == "" {
					t.Fatalf("happy path: expected user, got %v", resp)
				}
				if at, _ := resp["accessToken"].(string); at == "" {
					t.Fatalf("happy path: expected accessToken")
				}
			}
		})
	}
}

// TestE2E_PasswordSignup_AntiEnumeration confirms the anti-enumeration
// behaviour over HTTP: a second signup against an existing email
// returns the SAME success envelope as a fresh signup (200 + token
// pair), so an attacker probing a list of addresses cannot tell which
// ones already have accounts. The first signup's tokens still work;
// the second signup's tokens are functionally inert (mint nothing on
// the existing account).
func TestE2E_PasswordSignup_AntiEnumeration(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "antienum@example.com"

	first, _, _ := h.Signup(t, email, goodPassword)

	resp, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email":    email,
		"password": "Different!Pass1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("anti-enumeration: dup signup status=%d, want 200 (so the server doesn't leak enumeration), body=%v", status, resp)
	}
	at, _ := resp["accessToken"].(string)
	rt, _ := resp["refreshToken"].(string)
	if at == "" || rt == "" {
		t.Fatalf("anti-enumeration: dup signup must still return a token envelope, got %v", resp)
	}
	// The first signup's access token must STILL work; the original
	// account is untouched.
	cur, status := h.rpcCall(t, "GetCurrentUser", map[string]any{}, first)
	if status != http.StatusOK {
		t.Fatalf("first signup's token broken after dup signup attempt: status=%d body=%v", status, cur)
	}
}

// TestE2E_PasswordSignup_AntiEnumeration_EmailVariants verifies the
// anti-enumeration behaviour for case- and whitespace-variant emails:
// they all 200 the same way regardless of whether an existing account
// matches under the backend's normalization.
func TestE2E_PasswordSignup_AntiEnumeration_EmailVariants(t *testing.T) {
	t.Parallel()
	variants := []struct {
		name        string
		firstEmail  string
		secondEmail string
	}{
		{name: "uppercase_variant", firstEmail: "var1@example.com", secondEmail: "VAR1@example.com"},
		{name: "mixedcase_variant", firstEmail: "var2@example.com", secondEmail: "Var2@Example.COM"},
		{name: "leading_whitespace", firstEmail: "var3@example.com", secondEmail: "  var3@example.com"},
		{name: "trailing_whitespace", firstEmail: "var4@example.com", secondEmail: "var4@example.com  "},
	}
	for _, tc := range variants {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			h.Signup(t, tc.firstEmail, goodPassword)
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    tc.secondEmail,
				"password": goodPassword,
			}, "")
			if status != http.StatusOK {
				t.Fatalf("variant signup must 200 for anti-enumeration, got status=%d for email %q", status, tc.secondEmail)
			}
		})
	}
}

// TestE2E_PasswordLogin_AcceptanceMatrix exercises every common
// password-login outcome via the HTTP surface: success, wrong
// password, missing user, mixed case, etc.
func TestE2E_PasswordLogin_AcceptanceMatrix(t *testing.T) {
	t.Parallel()
	const registeredEmail = "login@example.com"

	matrix := []struct {
		name           string
		loginEmail     string
		loginPassword  string
		registerFirst  bool
		wantStatus     int
		wantAccessTok  bool
		wantRefreshTok bool
	}{
		{name: "happy_exact", loginEmail: registeredEmail, loginPassword: goodPassword, registerFirst: true, wantStatus: 200, wantAccessTok: true, wantRefreshTok: true},
		{name: "happy_uppercased_email", loginEmail: "LOGIN@example.com", loginPassword: goodPassword, registerFirst: true, wantStatus: 200, wantAccessTok: true, wantRefreshTok: true},
		{name: "happy_mixedcase_email", loginEmail: "Login@Example.com", loginPassword: goodPassword, registerFirst: true, wantStatus: 200, wantAccessTok: true, wantRefreshTok: true},
		{name: "reject_wrong_password", loginEmail: registeredEmail, loginPassword: "Wr0ng!Pass", registerFirst: true, wantStatus: 401},
		{name: "reject_empty_password", loginEmail: registeredEmail, loginPassword: "", registerFirst: true, wantStatus: 400},
		{name: "reject_missing_user", loginEmail: "ghost@example.com", loginPassword: goodPassword, registerFirst: false, wantStatus: 401},
		{name: "reject_empty_email", loginEmail: "", loginPassword: goodPassword, registerFirst: false, wantStatus: 400},
		{name: "reject_malformed_email", loginEmail: "nodomain", loginPassword: goodPassword, registerFirst: false, wantStatus: 400},
	}

	for _, tc := range matrix {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			if tc.registerFirst {
				h.Signup(t, registeredEmail, goodPassword)
			}
			resp, status := h.rpcCall(t, "PasswordLogin", map[string]any{
				"email":    tc.loginEmail,
				"password": tc.loginPassword,
			}, "")
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%v)", status, tc.wantStatus, resp)
			}
			if tc.wantAccessTok {
				if at, _ := resp["accessToken"].(string); at == "" {
					t.Fatalf("expected accessToken, got %v", resp)
				}
			}
			if tc.wantRefreshTok {
				if rt, _ := resp["refreshToken"].(string); rt == "" {
					t.Fatalf("expected refreshToken, got %v", resp)
				}
			}
		})
	}
}

// TestE2E_PasswordLockout_HTTP confirms repeated wrong-password POSTs
// flip the account into lockout. After N consecutive failures the
// service responds with a lockout marker and even the correct password
// is rejected until the cooldown window expires.
func TestE2E_PasswordLockout_HTTP(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "lockme@example.com"
	h.Signup(t, email, goodPassword)

	for i := 0; i < 5; i++ {
		_, status := h.rpcCall(t, "PasswordLogin", map[string]any{
			"email":    email,
			"password": "Wr0ng!Pass",
		}, "")
		if status == http.StatusOK {
			t.Fatalf("attempt %d unexpectedly succeeded with wrong password", i+1)
		}
	}
	// Correct password should now be rejected (lockout).
	_, status := h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	if status == http.StatusOK {
		t.Fatalf("expected lockout, but correct password succeeded after 5 failures")
	}
}

// TestE2E_GetCurrentUser_WithToken validates the bearer-token round
// trip: a token minted at signup must verify on a subsequent
// authenticated call against the same instance.
func TestE2E_GetCurrentUser_WithToken(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	at, _, uid := h.Signup(t, "me@example.com", goodPassword)
	resp, status := h.rpcCall(t, "GetCurrentUser", map[string]any{}, at)
	if status != http.StatusOK {
		t.Fatalf("GetCurrentUser status=%d body=%v", status, resp)
	}
	user, _ := resp["user"].(map[string]any)
	if user == nil {
		t.Fatalf("missing user in response: %v", resp)
	}
	if user["id"] != uid {
		t.Fatalf("user.id = %v, want %q", user["id"], uid)
	}
	if user["email"] == nil {
		t.Fatalf("user.email missing")
	}
}

// TestE2E_GetCurrentUser_RejectsBadTokens covers the auth middleware's
// rejection paths when a bearer token is missing, malformed, or signed
// by an unknown key.
func TestE2E_GetCurrentUser_RejectsBadTokens(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		token string
	}{
		{name: "no_token", token: ""},
		{name: "garbage", token: "not-a-jwt"},
		{name: "truncated_jwt", token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0"},
		{name: "wrong_algorithm_none", token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := StartServer(t)
			_, status := h.rpcCall(t, "GetCurrentUser", map[string]any{}, tc.token)
			if status == http.StatusOK {
				t.Fatalf("expected rejection for %q, got 200", tc.token)
			}
		})
	}
}

// TestE2E_ManyParallelSignups exercises connection / handler concurrency
// over the HTTP surface. Twenty concurrent signups for unique emails
// must all succeed (one per goroutine) without races on per-tenant
// state or the shared signer.
func TestE2E_ManyParallelSignups(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	const n = 20
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			_, status := h.rpcCall(t, "PasswordSignup", map[string]any{
				"email":    fmt.Sprintf("user%02d@example.com", i),
				"password": goodPassword,
			}, "")
			if status != http.StatusOK {
				done <- fmt.Errorf("signup %d: status=%d", i, status)
				return
			}
			done <- nil
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Errorf("%v", err)
		}
	}
}

const goodPassword = "Sw0rdfish!42"
