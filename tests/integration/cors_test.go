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

	cases := []struct {
		origin  string
		allowed bool
	}{
		{"https://feature-1.previews.example.app", true},
		{"https://feature-1.previews.example.net", false},
		{"https://a.feature-1.previews.example.app", false},
		{"https://previews.example.app", false},
	}
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
