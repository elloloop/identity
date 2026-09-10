package service

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// TestAppBaseURL_BrandedFromProjectScope covers the one base every mailed
// link is built on: a request resolved to a project with a primary
// auth-domain builds links on that branded https host — where identity
// serves the hosted pages — otherwise it falls back to the configured
// GATEWAY_APP_BASE_URL, then to the localhost dev default.
func TestAppBaseURL_BrandedFromProjectScope(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{AppBaseURL: "https://fallback.example/"}

	// No project scope → configured fallback (trailing slash trimmed).
	if got := appBaseURL(context.Background(), cfg); got != "https://fallback.example" {
		t.Errorf("no scope: got %q, want https://fallback.example", got)
	}

	// Scope with a primary auth-domain → branded https host.
	branded := WithProjectScope(context.Background(),
		&ProjectScope{ProjectID: "p", PrimaryAuthDomain: "auth.acme.com"})
	if got := appBaseURL(branded, cfg); got != "https://auth.acme.com" {
		t.Errorf("branded: got %q, want https://auth.acme.com", got)
	}

	// Scope without a primary auth-domain → fallback.
	noDomain := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "p"})
	if got := appBaseURL(noDomain, cfg); got != "https://fallback.example" {
		t.Errorf("scope without domain: got %q, want https://fallback.example", got)
	}

	// Empty or nil config → localhost dev default.
	if got := appBaseURL(context.Background(), &config.Config{}); got != devAppBaseURL {
		t.Errorf("empty cfg: got %q, want %q", got, devAppBaseURL)
	}
	if got := appBaseURL(context.Background(), nil); got != devAppBaseURL {
		t.Errorf("nil cfg: got %q, want %q", got, devAppBaseURL)
	}
}
