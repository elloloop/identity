package service

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// TestAppBaseURL_BrandedFromProjectScope covers appBaseURL's branched
// resolution: a request resolved to a project with a primary auth-domain
// builds links on that branded https host; otherwise it falls back to the
// configured GATEWAY_APP_BASE_URL, then to the localhost dev default.
func TestAppBaseURL_BrandedFromProjectScope(t *testing.T) {
	t.Parallel()

	s := &AuthService{cfg: &config.Config{AppBaseURL: "https://fallback.example/"}}

	// No project scope → configured fallback (trailing slash trimmed).
	if got := s.appBaseURL(context.Background()); got != "https://fallback.example" {
		t.Errorf("no scope: got %q, want https://fallback.example", got)
	}

	// Scope with a primary auth-domain → branded https host.
	branded := WithProjectScope(context.Background(),
		&ProjectScope{ProjectID: "p", PrimaryAuthDomain: "auth.acme.com"})
	if got := s.appBaseURL(branded); got != "https://auth.acme.com" {
		t.Errorf("branded: got %q, want https://auth.acme.com", got)
	}

	// Scope without a primary auth-domain → fallback.
	noDomain := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "p"})
	if got := s.appBaseURL(noDomain); got != "https://fallback.example" {
		t.Errorf("scope without domain: got %q, want https://fallback.example", got)
	}

	// Empty config → localhost dev default.
	dev := &AuthService{cfg: &config.Config{}}
	if got := dev.appBaseURL(context.Background()); got != "http://localhost:9002" {
		t.Errorf("empty cfg: got %q, want http://localhost:9002", got)
	}
}
