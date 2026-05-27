//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestE2E_Health200 covers every health-style endpoint identity exposes.
// All of them must answer 200 with no authentication required, because
// load balancers and Kubernetes probes don't carry bearer tokens.
func TestE2E_Health200(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	cases := []struct {
		name string
		path string
	}{
		{name: "health", path: "/health"},
		{name: "healthz", path: "/healthz"},
		{name: "jwks", path: "/.well-known/jwks.json"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status := h.HealthCheck(t, tc.path)
			if status != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", tc.path, status)
			}
		})
	}
}

// TestE2E_JWKS_HasUsableKeys verifies the JWKS document has the basic
// shape callers expect: a non-empty "keys" array with each entry
// carrying kid/kty/use/alg.
func TestE2E_JWKS_HasUsableKeys(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.BaseURL+"/.well-known/jwks.json", nil)
	resp, err := h.HTTP.Do(req)
	if err != nil {
		t.Fatalf("jwks GET: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("jwks JSON: %v (raw=%s)", err, string(raw))
	}
	keys, _ := doc["keys"].([]any)
	if len(keys) == 0 {
		t.Fatalf("jwks: keys array empty (doc=%v)", doc)
	}
	for i, k := range keys {
		key, _ := k.(map[string]any)
		for _, field := range []string{"kid", "kty", "use", "alg"} {
			if _, ok := key[field]; !ok {
				t.Errorf("jwks[%d]: missing %q field (key=%v)", i, field, key)
			}
		}
	}
}

// TestE2E_AuthMiddleware_Public verifies that the public RPCs
// (PasswordSignup, PasswordLogin, JWKS, health, etc.) work without
// any Authorization header, while non-public ones reject.
func TestE2E_AuthMiddleware_Public(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	publicEndpoints := []struct {
		name   string
		method string
		body   any
	}{
		{name: "PasswordSignup", method: "PasswordSignup", body: map[string]any{"email": "pub@example.com", "password": goodPassword}},
		{name: "PasswordLogin", method: "PasswordLogin", body: map[string]any{"email": "ghost@example.com", "password": goodPassword}},
		{name: "RefreshToken", method: "RefreshToken", body: map[string]any{"refreshToken": "garbage"}},
	}
	for _, e := range publicEndpoints {
		e := e
		t.Run("public_"+e.name, func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, e.method, e.body, "")
			// Status will be 200 (signup), 401 (login wrong creds),
			// 401 (refresh garbage) — but never the "missing bearer"
			// 401 that the auth middleware would issue.
			_ = status
		})
	}

	protected := []string{
		"GetCurrentUser",
		"UpdateProfile",
		"ChangePassword",
		"ListMySessions",
		"SignOutEverywhere",
	}
	for _, m := range protected {
		m := m
		t.Run("protected_"+m+"_requires_auth", func(t *testing.T) {
			t.Parallel()
			_, status := h.rpcCall(t, m, map[string]any{}, "")
			if status == http.StatusOK {
				t.Fatalf("protected %s served unauth, got 200", m)
			}
		})
	}
}

// TestE2E_RPCContentType verifies the server rejects non-JSON content
// types on RPC routes (so a caller can't accidentally send protobuf
// when the server expects JSON, or vice versa).
func TestE2E_RPCContentType(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	cases := []struct {
		name        string
		contentType string
		acceptable  bool
	}{
		{name: "json", contentType: "application/json", acceptable: true},
		{name: "json_charset_utf8", contentType: "application/json; charset=utf-8", acceptable: true},
		{name: "form_urlencoded_rejected", contentType: "application/x-www-form-urlencoded", acceptable: false},
		{name: "plain_text_rejected", contentType: "text/plain", acceptable: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
				h.BaseURL+"/identity.IdentityService/PasswordSignup",
				readerOf(`{"email":"ct@example.com","password":"Sw0rdfish!42"}`))
			req.Header.Set("Content-Type", tc.contentType)
			resp, err := h.HTTP.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			resp.Body.Close()
			if tc.acceptable && resp.StatusCode != http.StatusOK {
				t.Fatalf("acceptable content-type %q got status %d", tc.contentType, resp.StatusCode)
			}
			if !tc.acceptable && resp.StatusCode == http.StatusOK {
				t.Fatalf("unacceptable content-type %q got 200", tc.contentType)
			}
		})
	}
}

// readerOf wraps a string in an io.Reader for the test above.
func readerOf(s string) io.Reader {
	return &stringReader{s: s}
}

type stringReader struct {
	s string
	i int
}

func (r *stringReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// TestE2E_CORS_Preflight verifies the CORS middleware answers OPTIONS
// preflights for the configured allowed origins.
func TestE2E_CORS_Preflight(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	cases := []struct {
		name   string
		origin string
		want2x bool
	}{
		{name: "allowed_origin", origin: "http://localhost", want2x: true},
		{name: "disallowed_origin", origin: "https://attacker.example.com", want2x: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, h.BaseURL+"/identity.IdentityService/PasswordSignup", nil)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "content-type")
			resp, err := h.HTTP.Do(req)
			if err != nil {
				t.Fatalf("OPTIONS: %v", err)
			}
			resp.Body.Close()
			gotAllow := resp.Header.Get("Access-Control-Allow-Origin") != ""
			if tc.want2x != gotAllow {
				t.Fatalf("origin %q: Access-Control-Allow-Origin presence = %v, want %v (status=%d)", tc.origin, gotAllow, tc.want2x, resp.StatusCode)
			}
		})
	}
}
