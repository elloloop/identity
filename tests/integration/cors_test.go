//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// TestCORS_WildcardOriginPreflight verifies a one-label wildcard entry in
// GATEWAY_ALLOWED_ORIGINS end to end: a preflight from a matching origin is
// answered with that concrete origin and credentials, and a non-matching one
// gets no CORS grant.
func TestCORS_WildcardOriginPreflight(t *testing.T) {
	t.Parallel()

	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.AllowedOrigins = "http://localhost:9002,https://*.previews.example.app"
	}))

	assertPreflights(t, h, []preflightCase{
		{"https://feature-1.previews.example.app", true},
		{"https://feature-1.previews.example.net", false},
		{"https://a.feature-1.previews.example.app", false},
		{"https://previews.example.app", false},
	})
}

// TestCORS_AppSchemeOriginPreflight verifies an exact origin on an
// application's own scheme end to end: a preflight from exactly that origin is
// answered with it and credentials, and every look-alike gets no CORS grant.
func TestCORS_AppSchemeOriginPreflight(t *testing.T) {
	t.Parallel()

	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.AllowedOrigins = "http://localhost:9002,app://example-desktop"
	}))

	assertPreflights(t, h, []preflightCase{
		{"app://example-desktop", true},
		{"http://localhost:9002", true},
		{"app://other-desktop", false},
		{"web://example-desktop", false},
		{"APP://example-desktop", false},
		{"app://Example-Desktop", false},
		{"app://example-desktop/", false},
		{"app://example-desktop/index.html", false},
		{"null", false},
		{"file://", false},
	})
}

type preflightCase struct {
	origin  string
	allowed bool
}

// assertPreflights sends a CORS preflight from each case's Origin and checks
// that an allowed one is echoed with credentials and the rest get no grant.
func assertPreflights(t *testing.T, h *Harness, cases []preflightCase) {
	t.Helper()
	for _, tc := range cases {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions,
			h.BaseURL+"/identity.v1.IdentityService/RedeemOAuthCode", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "content-type")
		resp, err := h.HTTP.Do(req)
		if err != nil {
			t.Fatalf("OPTIONS: %v", err)
		}
		_ = resp.Body.Close()

		gotOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		gotCreds := resp.Header.Get("Access-Control-Allow-Credentials")
		if !tc.allowed {
			if gotOrigin != "" || gotCreds != "" {
				t.Errorf("origin %q: got Allow-Origin=%q Allow-Credentials=%q, want none", tc.origin, gotOrigin, gotCreds)
			}
			continue
		}
		if gotOrigin != tc.origin || gotCreds != "true" {
			t.Errorf("origin %q: got Allow-Origin=%q Allow-Credentials=%q, want the origin with credentials",
				tc.origin, gotOrigin, gotCreds)
		}
		if vary := resp.Header.Values("Vary"); len(vary) != 1 || vary[0] != "Origin" {
			t.Errorf("origin %q: Vary = %v, want [Origin]", tc.origin, vary)
		}
	}
}
