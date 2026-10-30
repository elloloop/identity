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

// stubOptions is a fixed OptionsSource for handler tests.
type stubOptions struct{ opts service.HostedUIOptions }

func (s stubOptions) HostedUIOptions(context.Context, string) service.HostedUIOptions { return s.opts }

// allEnabled is the zero-friction default most tests use: password login +
// signup on, no providers.
func allEnabled() OptionsSource {
	return stubOptions{opts: service.HostedUIOptions{PasswordLoginEnabled: true, PasswordSignupEnabled: true}}
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

// TestHandler_ServesEmbeddedIndex exercises the static UI handler: a GET
// under /auth/ resolves the embedded index.html and returns it. This is the
// only reachable path — the fs.Sub error branch cannot trigger because the
// static tree is embedded at build time.
func TestHandler_ServesEmbeddedIndex(t *testing.T) {
	rec := serveIndex(t, Handler(&config.Config{}, allEnabled(), false), nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/: status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("GET /auth/: empty body, want embedded index.html content")
	}
}

// The dynamic page carries per-project options that can change at runtime,
// so it must never be cached.
func TestHandler_IndexIsUncacheable(t *testing.T) {
	rec := serveIndex(t, Handler(&config.Config{}, allEnabled(), false), nil)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestHandler_InjectsServerConfig confirms the handler renders the resolved
// sign-in options into the page so the SPA renders exactly what the server
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
			want: []string{`"passwordSignupEnabled":false`, `"usernameSignupEnabled":false`, `"usernameLoginEnabled":false`},
		},
		{
			name: "username accounts",
			opts: service.HostedUIOptions{PasswordLoginEnabled: true, UsernameSignupEnabled: true, UsernameLoginEnabled: true},
			want: []string{`"passwordSignupEnabled":false`, `"usernameSignupEnabled":true`, `"usernameLoginEnabled":true`},
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
			h := Handler(&config.Config{}, stubOptions{opts: tc.opts}, tc.hosted)
			body := serveIndex(t, h, nil).Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("rendered page missing injected %q", want)
				}
			}
		})
	}
}

// scopeOptions proves the page is rendered PER REQUEST: the options depend
// on the project scope the middleware injected into the request context.
type scopeOptions struct{}

func (scopeOptions) HostedUIOptions(ctx context.Context, _ string) service.HostedUIOptions {
	if sc := service.ProjectScopeFromContext(ctx); sc != nil && sc.ProjectID == "proj-google" {
		return service.HostedUIOptions{OAuthProviders: []service.HostedUIProvider{{Key: "google"}}}
	}
	return service.HostedUIOptions{PasswordLoginEnabled: true, PasswordSignupEnabled: true}
}

func TestHandler_RendersPerRequestProjectOptions(t *testing.T) {
	h := Handler(&config.Config{}, scopeOptions{}, true)

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
// key reach the SPA only when CAPTCHA is enabled with a Turnstile site key —
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
		}, allEnabled(), false)
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
		}, allEnabled(), false)
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
		}, allEnabled(), false)
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
		}, allEnabled(), false)
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

// originRecorder records the page origin each render asks the options for.
type originRecorder struct{ origins *[]string }

func (o originRecorder) HostedUIOptions(_ context.Context, pageOrigin string) service.HostedUIOptions {
	*o.origins = append(*o.origins, pageOrigin)
	return service.HostedUIOptions{PasswordLoginEnabled: true}
}

// The sign-in page and the agent consent page ask for the options of the
// origin they are served on, so a host's own OAuth client (ADR-0019) starts
// on that host: the request's Host, or the forwarded host and scheme a proxy
// in front of the server reports.
func TestHandlers_PassThePageOrigin(t *testing.T) {
	var origins []string
	rec := originRecorder{origins: &origins}
	pages := map[string]http.Handler{
		"/auth/":              Handler(&config.Config{}, rec, true),
		"/auth/agent-consent": AgentConsentHandler(&config.Config{}, rec, service.ReturnAllowlist{}),
	}
	for path, h := range pages {
		origins = origins[:0]
		plain := httptest.NewRequest(http.MethodGet, path, nil)
		plain.Host = "auth.b.example"
		h.ServeHTTP(httptest.NewRecorder(), plain)

		proxied := httptest.NewRequest(http.MethodGet, path, nil)
		proxied.Host = "internal.example:8080"
		proxied.Header.Set("X-Forwarded-Host", "auth.a.example")
		proxied.Header.Set("X-Forwarded-Proto", "https")
		h.ServeHTTP(httptest.NewRecorder(), proxied)

		if want := []string{"http://auth.b.example", "https://auth.a.example"}; strings.Join(origins, " ") != strings.Join(want, " ") {
			t.Errorf("%s: page origins = %v, want %v", path, origins, want)
		}
	}
}
