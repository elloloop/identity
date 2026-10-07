package service

import (
	"context"
	"strings"
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

// TestRequestPasswordReset_EmailLinkBaseBeatsBrandedDomain is the production
// shape the setting exists for: the request resolves to a project whose
// primary auth domain is identity's own host, which serves no reset page.
// With GATEWAY_EMAIL_LINK_BASE_URL set the link goes to the hub instead;
// without it, to the branded domain as before.
func TestRequestPasswordReset_EmailLinkBaseBeatsBrandedDomain(t *testing.T) {
	branded := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "hub", PrimaryAuthDomain: "auth.acme.example",
		Access: ProjectAccessConfig{Mode: AccessModeOpen},
	})
	for _, tc := range []struct {
		name, base, wantPrefix string
	}{
		{"no base", "", "https://auth.acme.example/auth/reset-password?token="},
		{"hub base", "https://signin.acme.example", "https://signin.acme.example/reset-password?token="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, rec := newAuthSvcWithMailer(t)
			svc.cfg.EmailLinkBaseURL = tc.base
			seedUser(repo, "alice@test.com", "x", "active")

			if err := svc.RequestPasswordReset(branded, "alice@test.com", EmailLinkParams{}); err != nil {
				t.Fatalf("RequestPasswordReset: %v", err)
			}
			sent := rec.Sent()
			if len(sent) != 1 {
				t.Fatalf("expected 1 email, got %d", len(sent))
			}
			text := sent[0].Text
			if got, want := linkInBody(t, text, "https://"), tc.wantPrefix+extractTokenFromLink(t, text); got != want {
				t.Fatalf("reset link = %q, want %q", got, want)
			}
		})
	}
}

// TestEmails_BrandedByNamedProduct: each email that takes link params — the
// reset, the verification resend, and the verification sent at signup —
// carries the named product's branding from the project's products block;
// the same request without a product carries the project's.
func TestEmails_BrandedByNamedProduct(t *testing.T) {
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "hub",
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		Branding:  ProjectBrandingConfig{ProductName: "Acme", EmailFromName: "Acme"},
		Products: ProjectProductsConfig{"kids": {Branding: ProjectBrandingConfig{
			ProductName: "Acme Kids", EmailFrom: "no-reply@kids.acme.example", EmailFromName: "Acme Kids",
		}}},
	})
	senders := []struct {
		name string
		send func(svc *AuthService, repo *fakeRepo, params EmailLinkParams) error
	}{
		{"RequestPasswordReset", func(svc *AuthService, repo *fakeRepo, params EmailLinkParams) error {
			seedUser(repo, "alice@test.com", "x", "active")
			return svc.RequestPasswordReset(ctx, "alice@test.com", params)
		}},
		{"SendEmailVerification", func(svc *AuthService, repo *fakeRepo, params EmailLinkParams) error {
			user := seedUser(repo, "alice@test.com", "x", "active")
			return svc.SendEmailVerification(ctx, user.ID, params)
		}},
		{"PasswordSignup", func(svc *AuthService, _ *fakeRepo, params EmailLinkParams) error {
			_, err := svc.PasswordSignup(ctx, "alice@test.com", "Str0ng!Pass1", "Alice", "", 0, "", params)
			return err
		}},
	}
	for _, sender := range senders {
		for _, tc := range []struct {
			name, product, wantFrom, wantName string
		}{
			{"named product", "Kids", `"Acme Kids" <no-reply@kids.acme.example>`, "Acme Kids"},
			{"no product", "", `"Acme" <no-reply@test.local>`, "Acme"},
		} {
			t.Run(sender.name+"/"+tc.name, func(t *testing.T) {
				svc, repo, rec := newAuthSvcWithMailer(t)

				if err := sender.send(svc, repo, EmailLinkParams{Product: tc.product}); err != nil {
					t.Fatalf("%s: %v", sender.name, err)
				}
				sent := rec.Sent()
				if len(sent) != 1 {
					t.Fatalf("expected 1 email, got %d", len(sent))
				}
				if sent[0].From != tc.wantFrom {
					t.Errorf("From = %q, want %q", sent[0].From, tc.wantFrom)
				}
				if !strings.HasPrefix(sent[0].Text, tc.wantName+"\n") {
					t.Errorf("text body should open with %q: %q", tc.wantName, sent[0].Text)
				}
			})
		}
	}
}
