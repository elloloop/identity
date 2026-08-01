package ui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

//go:embed static/*
var staticFS embed.FS

// OptionsSource resolves the per-request sign-in capabilities the page may
// offer. Implemented by service.AuthService; the indirection keeps this
// package free of the service's construction graph in tests.
type OptionsSource interface {
	HostedUIOptions(ctx context.Context) service.HostedUIOptions
}

// configData holds the serialized configuration injected into the template.
// It is computed PER REQUEST: the sign-in options depend on the project the
// request resolved to (auth-domain Host or ?project_key=), not on boot-time
// env alone.
type configData struct {
	// PasswordLoginEnabled / PasswordSignupEnabled gate the password form
	// and its sign-up toggle to what the server enforces for the project.
	PasswordLoginEnabled  bool `json:"passwordLoginEnabled"`
	PasswordSignupEnabled bool `json:"passwordSignupEnabled"`
	// OAuthProviders are the providers the page renders buttons for — the
	// providers a login attempt through this request's project would
	// resolve (own config, or the hub's under hub sharing), each with the
	// origin its flow must start on.
	OAuthProviders []service.HostedUIProvider `json:"oauthProviders"`
	// HostedOAuthEnabled reports whether the /oauth/start routes are
	// registered (GATEWAY_OAUTH_ALLOWED_RETURN_URLS non-empty); without
	// them provider buttons would 404 and are not rendered.
	HostedOAuthEnabled bool `json:"hostedOAuthEnabled"`
	// CaptchaProvider is the CAPTCHA provider the hosted auth UI should render
	// a widget for. Only "turnstile" has widget support, so the injected value
	// is "turnstile" or "" (CAPTCHA off / non-renderable provider).
	CaptchaProvider string `json:"captchaProvider"`
	// CaptchaSiteKey is the provider's PUBLIC site key for the widget.
	CaptchaSiteKey string `json:"captchaSiteKey"`
	// CaptchaEnforceLogin and CaptchaEnforceSignup mirror the server's per-flow
	// enforcement (GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN / _SIGNUP) so the SPA
	// renders the widget exactly where the server will require a token. Both
	// are false whenever no widget can render.
	CaptchaEnforceLogin  bool `json:"captchaEnforceLogin"`
	CaptchaEnforceSignup bool `json:"captchaEnforceSignup"`
}

// Handler returns an http.Handler serving the hosted auth UI. Static assets
// come from the embedded FS; index.html is a template re-rendered per
// request so the injected server config reflects the request's resolved
// project (the project middleware runs before this handler). options
// resolves those per-project capabilities; hostedOAuthEnabled reports
// whether the hosted OAuth routes are mounted at all.
func Handler(cfg *config.Config, options OptionsSource, hostedOAuthEnabled bool) http.Handler {
	tmpl, err := template.ParseFS(staticFS, "static/index.html")
	if err != nil {
		panic(err)
	}

	siteKey := captchaUISiteKey(cfg)
	captchaProvider := captchaUIProvider(cfg)

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fsHandler := http.StripPrefix("/auth/", http.FileServer(http.FS(sub)))

	renderIndex := func(w http.ResponseWriter, r *http.Request) {
		opts := options.HostedUIOptions(r.Context())
		providers := opts.OAuthProviders
		if providers == nil {
			providers = []service.HostedUIProvider{}
		}
		data := configData{
			PasswordLoginEnabled:  opts.PasswordLoginEnabled,
			PasswordSignupEnabled: opts.PasswordSignupEnabled,
			OAuthProviders:        providers,
			HostedOAuthEnabled:    hostedOAuthEnabled,
			CaptchaProvider:       captchaProvider,
			CaptchaSiteKey:        siteKey,
			CaptchaEnforceLogin:   siteKey != "" && cfg.AssuranceEnforcePasswordLogin,
			CaptchaEnforceSignup:  siteKey != "" && cfg.AssuranceEnforcePasswordSignup,
		}
		b, err := json.Marshal(data)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, map[string]any{
			// b is json.Marshal of a configData struct (bools, operator-set
			// strings from server env config, and server-side provider keys),
			// with no user-controlled input, so injecting it unescaped is safe.
			"JSONConfig": template.JS("window.serverConfig = " + string(b) + ";"), //nolint:gosec // G203: static server-generated config, no user input
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// The page embeds per-project options that can change at runtime
		// (config_json edits, provider changes), so it must never be served
		// from a stale browser/proxy cache.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/auth/" || path == "/auth/index.html" {
			renderIndex(w, r)
			return
		}
		fsHandler.ServeHTTP(w, r)
	})
}

// captchaUISiteKey returns the PUBLIC site key for the active provider, or ""
// when assurance is disabled or no site key is configured — in which case the
// hosted auth UI (login + sign-up) renders no widget.
func captchaUISiteKey(cfg *config.Config) string {
	if !cfg.AssuranceEnabled {
		return ""
	}
	if cfg.AssuranceWebProvider == config.AssuranceWebProviderTurnstile {
		return cfg.AssuranceTurnstileSiteKey
	}
	return ""
}

// captchaUIProvider names the provider the hosted auth UI should render, or
// "" when there is no public site key to render a widget for.
func captchaUIProvider(cfg *config.Config) string {
	if captchaUISiteKey(cfg) == "" {
		return ""
	}
	return cfg.AssuranceWebProvider
}
