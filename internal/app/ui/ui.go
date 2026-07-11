package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/elloloop/identity/internal/config"
)

//go:embed static/*
var staticFS embed.FS

// configData holds the serialized configuration injected into the template.
type configData struct {
	PasswordSignupEnabled bool `json:"passwordSignupEnabled"`
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

// Handler returns an http.Handler that serves the embedded static files.
// It parses index.html as a template and injects the server configuration
// into it. The result is cached in memory on startup.
func Handler(cfg *config.Config) http.Handler {
	tmpl, err := template.ParseFS(staticFS, "static/index.html")
	if err != nil {
		panic(err)
	}

	siteKey := captchaUISiteKey(cfg)
	data := configData{
		PasswordSignupEnabled: cfg.PasswordSignupEnabled,
		CaptchaProvider:       captchaUIProvider(cfg),
		CaptchaSiteKey:        siteKey,
		CaptchaEnforceLogin:   siteKey != "" && cfg.CaptchaEnforcePasswordLogin,
		CaptchaEnforceSignup:  siteKey != "" && cfg.CaptchaEnforcePasswordSignup,
	}

	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{
		// b is json.Marshal of a static configData struct (bools plus
		// operator-set strings from server env config), with no
		// user-controlled input, so injecting it unescaped is safe.
		"JSONConfig": template.JS("window.serverConfig = " + string(b) + ";"), //nolint:gosec // G203: static server-generated config, no user input
	}); err != nil {
		panic(err)
	}

	indexBytes := buf.Bytes()
	indexTime := time.Now() // Use startup time for caching

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fsHandler := http.StripPrefix("/auth/", http.FileServer(http.FS(sub)))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/auth/" || path == "/auth/index.html" {
			// Do not cache the dynamic HTML heavily, but use If-Modified-Since locally
			http.ServeContent(w, r, "index.html", indexTime, bytes.NewReader(indexBytes))
			return
		}
		fsHandler.ServeHTTP(w, r)
	})
}

// captchaUISiteKey returns the PUBLIC site key for the active provider, or ""
// when CAPTCHA is disabled or no site key is configured — in which case the
// hosted auth UI (login + sign-up) renders no widget.
func captchaUISiteKey(cfg *config.Config) string {
	if !cfg.CaptchaEnabled {
		return ""
	}
	if cfg.CaptchaProvider == config.CaptchaProviderTurnstile {
		return cfg.CaptchaTurnstileSiteKey
	}
	return ""
}

// captchaUIProvider names the provider the hosted auth UI should render, or
// "" when there is no public site key to render a widget for.
func captchaUIProvider(cfg *config.Config) string {
	if captchaUISiteKey(cfg) == "" {
		return ""
	}
	return cfg.CaptchaProvider
}
