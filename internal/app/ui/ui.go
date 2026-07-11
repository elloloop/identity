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
	// CaptchaProvider is the active CAPTCHA provider ("turnstile", "recaptcha_v3"),
	// or empty when CAPTCHA is off — the sign-up UI renders a widget only when set.
	CaptchaProvider string `json:"captchaProvider"`
	// CaptchaSiteKey is the provider's PUBLIC site key for the widget.
	CaptchaSiteKey string `json:"captchaSiteKey"`
}

// Handler returns an http.Handler that serves the embedded static files.
// It parses index.html as a template and injects the server configuration
// into it. The result is cached in memory on startup.
func Handler(cfg *config.Config) http.Handler {
	tmpl, err := template.ParseFS(staticFS, "static/index.html")
	if err != nil {
		panic(err)
	}

	data := configData{
		PasswordSignupEnabled: cfg.PasswordSignupEnabled,
		CaptchaProvider:       captchaUIProvider(cfg),
		CaptchaSiteKey:        captchaUISiteKey(cfg),
	}

	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{
		// b is json.Marshal of a static configData struct (a single bool),
		// with no user-controlled input, so injecting it unescaped is safe.
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
// hosted sign-up UI renders no widget.
func captchaUISiteKey(cfg *config.Config) string {
	if !cfg.CaptchaEnabled {
		return ""
	}
	if cfg.CaptchaProvider == config.CaptchaProviderTurnstile {
		return cfg.CaptchaTurnstileSiteKey
	}
	return ""
}

// captchaUIProvider names the provider the sign-up UI should render, or ""
// when there is no public site key to render a widget for.
func captchaUIProvider(cfg *config.Config) string {
	if captchaUISiteKey(cfg) == "" {
		return ""
	}
	return cfg.CaptchaProvider
}
