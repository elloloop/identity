package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// stubService is a canned Service for handler tests. Sign-in options and
// branding are fixed; every action call panics unless the test supplies it,
// so a sign-in page test cannot consume a token by accident and an action
// test asserts exactly which call the page made.
type stubService struct {
	opts   service.HostedUIOptions
	optsFn func(ctx context.Context) service.HostedUIOptions
	brand  service.HostedUIBranding

	peek   func(ctx context.Context, token string) (service.ActionLinkPreview, error)
	verify func(ctx context.Context, token string) (*service.User, error)
	reset  func(ctx context.Context, token, newPassword string) error
	change func(ctx context.Context, token string) (*service.User, error)
	magic  func(ctx context.Context, token, ipAddr, userAgent string) (*service.MagicLinkHandover, error)
	invite func(ctx context.Context, token, password, name string) (*service.User, error)
}

func (s stubService) HostedUIOptions(ctx context.Context) service.HostedUIOptions {
	if s.optsFn != nil {
		return s.optsFn(ctx)
	}
	return s.opts
}

func (s stubService) HostedUIBranding(context.Context) service.HostedUIBranding { return s.brand }

func (s stubService) doPeek(ctx context.Context, token string) (service.ActionLinkPreview, error) {
	if s.peek == nil {
		panic("unexpected peek")
	}
	return s.peek(ctx, token)
}

func (s stubService) PeekEmailVerification(ctx context.Context, token string) (service.ActionLinkPreview, error) {
	return s.doPeek(ctx, token)
}

func (s stubService) PeekPasswordReset(ctx context.Context, token string) (service.ActionLinkPreview, error) {
	return s.doPeek(ctx, token)
}

func (s stubService) PeekEmailChange(ctx context.Context, token string) (service.ActionLinkPreview, error) {
	return s.doPeek(ctx, token)
}

func (s stubService) PeekMagicLink(ctx context.Context, token string) (service.ActionLinkPreview, error) {
	return s.doPeek(ctx, token)
}

func (s stubService) PeekInvitation(ctx context.Context, token string) (service.ActionLinkPreview, error) {
	return s.doPeek(ctx, token)
}

func (s stubService) VerifyEmail(ctx context.Context, token string) (*service.User, error) {
	if s.verify == nil {
		panic("unexpected VerifyEmail")
	}
	return s.verify(ctx, token)
}

func (s stubService) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	if s.reset == nil {
		panic("unexpected ConfirmPasswordReset")
	}
	return s.reset(ctx, token, newPassword)
}

func (s stubService) ConfirmEmailChange(ctx context.Context, token string) (*service.User, error) {
	if s.change == nil {
		panic("unexpected ConfirmEmailChange")
	}
	return s.change(ctx, token)
}

func (s stubService) RedeemMagicLinkForHandover(ctx context.Context, token, ipAddr, userAgent string) (*service.MagicLinkHandover, error) {
	if s.magic == nil {
		panic("unexpected RedeemMagicLinkForHandover")
	}
	return s.magic(ctx, token, ipAddr, userAgent)
}

func (s stubService) RedeemInvitation(ctx context.Context, token, password, name string) (*service.User, error) {
	if s.invite == nil {
		panic("unexpected RedeemInvitation")
	}
	return s.invite(ctx, token, password, name)
}

// allEnabled is the zero-friction default most sign-in page tests use:
// password login + signup on, no providers.
func allEnabled() Service {
	return stubService{opts: service.HostedUIOptions{PasswordLoginEnabled: true, PasswordSignupEnabled: true}}
}

func serveIndex(t *testing.T, h http.Handler, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/", nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestHandler_ServesLoginPage exercises the sign-in page: a GET of /auth/
// renders the embedded login template.
func TestHandler_ServesLoginPage(t *testing.T) {
	rec := serveIndex(t, Handler(&config.Config{}, Sources{Auth: allEnabled()}, false, nil), nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/: status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("GET /auth/: empty body, want the rendered sign-in page")
	}
}

// The dynamic page carries per-project options that can change at runtime,
// so it must never be cached.
func TestHandler_LoginPageIsUncacheable(t *testing.T) {
	rec := serveIndex(t, Handler(&config.Config{}, Sources{Auth: allEnabled()}, false, nil), nil)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestHandler_InjectsServerConfig confirms the handler renders the resolved
// sign-in options into the page so the page renders exactly what the server
// enables (hide signup, hide the password form, list providers).
func TestHandler_InjectsServerConfig(t *testing.T) {
	cases := []struct {
		name   string
		opts   service.HostedUIOptions
		hosted bool
		want   []string
	}{
		{
			name: "password only",
			opts: service.HostedUIOptions{PasswordLoginEnabled: true, PasswordSignupEnabled: true},
			want: []string{
				`"passwordLoginEnabled":true`,
				`"passwordSignupEnabled":true`,
				`"oauthProviders":[]`,
				`"hostedOAuthEnabled":false`,
			},
		},
		{
			name: "signup disabled",
			opts: service.HostedUIOptions{PasswordLoginEnabled: true},
			want: []string{`"passwordSignupEnabled":false`},
		},
		{
			name: "providers with hosted flow on",
			opts: service.HostedUIOptions{OAuthProviders: []service.HostedUIProvider{
				{Key: "github"},
				{Key: "google", StartOrigin: "https://auth.hub.test", NeedsProjectKey: true},
			}},
			hosted: true,
			want: []string{
				`"passwordLoginEnabled":false`,
				`{"key":"github","startOrigin":"","needsProjectKey":false}`,
				`{"key":"google","startOrigin":"https://auth.hub.test","needsProjectKey":true}`,
				`"hostedOAuthEnabled":true`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := Handler(&config.Config{}, Sources{Auth: stubService{opts: tc.opts}}, tc.hosted, nil)
			body := serveIndex(t, h, nil).Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("rendered page missing injected %q", want)
				}
			}
		})
	}
}

// scopeService proves the page is rendered PER REQUEST: the options depend
// on the project scope the middleware injected into the request context.
func scopeService() Service {
	return stubService{optsFn: func(ctx context.Context) service.HostedUIOptions {
		if sc := service.ProjectScopeFromContext(ctx); sc != nil && sc.ProjectID == "proj-google" {
			return service.HostedUIOptions{OAuthProviders: []service.HostedUIProvider{{Key: "google"}}}
		}
		return service.HostedUIOptions{PasswordLoginEnabled: true, PasswordSignupEnabled: true}
	}}
}

func TestHandler_RendersPerRequestProjectOptions(t *testing.T) {
	h := Handler(&config.Config{}, Sources{Auth: scopeService()}, true, nil)

	withScope := serveIndex(t, h, func(r *http.Request) {
		ctx := service.WithProjectScope(r.Context(), &service.ProjectScope{ProjectID: "proj-google"})
		*r = *r.WithContext(ctx)
	}).Body.String()
	if !strings.Contains(withScope, `"key":"google"`) {
		t.Error("scoped request must render the project's provider list")
	}
	if !strings.Contains(withScope, `"passwordLoginEnabled":false`) {
		t.Error("scoped request must render the project's password policy")
	}

	unscoped := serveIndex(t, h, nil).Body.String()
	if !strings.Contains(unscoped, `"oauthProviders":[]`) {
		t.Error("unscoped request must not inherit another request's providers")
	}
	if !strings.Contains(unscoped, `"passwordLoginEnabled":true`) {
		t.Error("unscoped request must render the default options")
	}
}

// TestHandler_InjectsCaptchaConfig confirms the public CAPTCHA provider + site
// key reach the page only when CAPTCHA is enabled with a Turnstile site key —
// so the sign-up widget renders exactly when it should and never leaks a key
// while CAPTCHA is off.
func TestHandler_InjectsCaptchaConfig(t *testing.T) {
	t.Run("enabled with turnstile site key", func(t *testing.T) {
		h := Handler(&config.Config{
			AssuranceEnabled:               true,
			AssuranceWebProvider:           config.AssuranceWebProviderTurnstile,
			AssuranceTurnstileSiteKey:      "0xSITEKEY",
			AssuranceEnforcePasswordLogin:  true,
			AssuranceEnforcePasswordSignup: true,
		}, Sources{Auth: allEnabled()}, false, nil)
		body := serveIndex(t, h, nil).Body.String()

		for _, want := range []string{
			`"captchaProvider":"turnstile"`,
			`"captchaSiteKey":"0xSITEKEY"`,
			`"captchaEnforceLogin":true`,
			`"captchaEnforceSignup":true`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("rendered page missing injected %q", want)
			}
		}
	})

	t.Run("enforce flags mirror per-flow config", func(t *testing.T) {
		h := Handler(&config.Config{
			AssuranceEnabled:               true,
			AssuranceWebProvider:           config.AssuranceWebProviderTurnstile,
			AssuranceTurnstileSiteKey:      "0xSITEKEY",
			AssuranceEnforcePasswordLogin:  false,
			AssuranceEnforcePasswordSignup: true,
		}, Sources{Auth: allEnabled()}, false, nil)
		body := serveIndex(t, h, nil).Body.String()

		for _, want := range []string{`"captchaEnforceLogin":false`, `"captchaEnforceSignup":true`} {
			if !strings.Contains(body, want) {
				t.Errorf("rendered page missing injected %q", want)
			}
		}
	})

	t.Run("disabled injects empty captcha config", func(t *testing.T) {
		h := Handler(&config.Config{
			AssuranceEnabled:               false,
			AssuranceWebProvider:           config.AssuranceWebProviderTurnstile,
			AssuranceTurnstileSiteKey:      "0xSITEKEY",
			AssuranceEnforcePasswordLogin:  true,
			AssuranceEnforcePasswordSignup: true,
		}, Sources{Auth: allEnabled()}, false, nil)
		body := serveIndex(t, h, nil).Body.String()

		if strings.Contains(body, "0xSITEKEY") {
			t.Error("site key leaked into the page while CAPTCHA is disabled")
		}
		if !strings.Contains(body, `"captchaProvider":""`) {
			t.Error("expected empty captchaProvider while CAPTCHA is disabled")
		}
		for _, want := range []string{`"captchaEnforceLogin":false`, `"captchaEnforceSignup":false`} {
			if !strings.Contains(body, want) {
				t.Errorf("enforce flag should be off with no renderable widget: missing %q", want)
			}
		}
	})

	t.Run("non-turnstile provider injects empty captcha config", func(t *testing.T) {
		// recaptcha_v3 has no hosted-UI widget support; the page must not
		// advertise a provider (or enforcement) it cannot render.
		h := Handler(&config.Config{
			AssuranceEnabled:               true,
			AssuranceWebProvider:           config.AssuranceWebProviderRecaptchaV3,
			AssuranceTurnstileSiteKey:      "0xSITEKEY",
			AssuranceEnforcePasswordLogin:  true,
			AssuranceEnforcePasswordSignup: true,
		}, Sources{Auth: allEnabled()}, false, nil)
		body := serveIndex(t, h, nil).Body.String()

		for _, want := range []string{
			`"captchaProvider":""`,
			`"captchaSiteKey":""`,
			`"captchaEnforceLogin":false`,
			`"captchaEnforceSignup":false`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("rendered page missing %q for a non-turnstile provider", want)
			}
		}
	})
}
