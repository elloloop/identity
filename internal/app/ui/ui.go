// Package ui serves the hosted pages under /auth/: the sign-in page and the
// five pages an emailed action link lands on (verify email, reset password,
// confirm email change, magic link, accept invitation). Every page is
// rendered per request from embedded templates so the sign-in options,
// branding and Content-Security-Policy nonce reflect that request's
// resolved project; nothing is served from a static file.
package ui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	loginPath      = "/auth/"
	loginIndexPath = "/auth/index.html"

	// turnstileScriptURL is the Turnstile loader the login page injects when
	// a Turnstile site key is configured. Its origin is the only third-party
	// host the login page's CSP admits, for the script and the widget frame,
	// so the page and the policy share this one definition.
	turnstileScriptURL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
	turnstileOrigin    = "https://challenges.cloudflare.com"
)

// Service is what the hosted pages need from the auth service: the login
// page's per-project options, the branding every page renders, and the five
// emailed-link actions, each as a read-only preview (what the GET shows) and
// the consuming step (what the POST does). Implemented by
// service.AuthService; the indirection keeps this package free of the
// service's construction graph in tests.
type Service interface {
	HostedUIOptions(ctx context.Context) service.HostedUIOptions
	HostedUIBranding(ctx context.Context) service.HostedUIBranding

	PeekEmailVerification(ctx context.Context, token string) (service.ActionLinkPreview, error)
	VerifyEmail(ctx context.Context, token string) (*service.User, error)

	PeekPasswordReset(ctx context.Context, token string) (service.ActionLinkPreview, error)
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) error

	PeekEmailChange(ctx context.Context, token string) (service.ActionLinkPreview, error)
	ConfirmEmailChange(ctx context.Context, token string) (*service.User, error)

	PeekMagicLink(ctx context.Context, token string) (service.ActionLinkPreview, error)
	RedeemMagicLinkForHandover(ctx context.Context, token, ipAddr, userAgent string) (*service.MagicLinkHandover, error)

	PeekInvitation(ctx context.Context, token string) (service.ActionLinkPreview, error)
	RedeemInvitation(ctx context.Context, token, password, name string) (*service.User, error)
}

// configData holds the serialized configuration injected into the login
// page. It is computed PER REQUEST: the sign-in options depend on the
// project the request resolved to (auth-domain Host or ?project_key=), not
// on boot-time env alone.
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
	// CaptchaProvider is the CAPTCHA provider the login page should render
	// a widget for. Only "turnstile" has widget support, so the injected
	// value is "turnstile" or "" (CAPTCHA off / non-renderable provider).
	CaptchaProvider string `json:"captchaProvider"`
	// CaptchaSiteKey is the provider's PUBLIC site key for the widget.
	CaptchaSiteKey string `json:"captchaSiteKey"`
	// CaptchaScriptURL is the widget loader the page injects, set only when
	// a widget can render; the same origin is admitted by the page's CSP.
	CaptchaScriptURL string `json:"captchaScriptURL"`
	// CaptchaEnforceLogin and CaptchaEnforceSignup mirror the server's
	// per-flow enforcement (GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN /
	// _SIGNUP) so the page renders the widget exactly where the server will
	// require a token. Both are false whenever no widget can render.
	CaptchaEnforceLogin  bool `json:"captchaEnforceLogin"`
	CaptchaEnforceSignup bool `json:"captchaEnforceSignup"`
}

// loginPage is the template data for the sign-in page.
type loginPage struct {
	Nonce      string
	JSONConfig template.JS
}

type handler struct {
	cfg                *config.Config
	svc                Service
	logger             *zap.Logger
	hostedOAuthEnabled bool
	login              *template.Template
	action             *template.Template
	// crossOrigin rejects unsafe requests a browser marks as coming from
	// another site, so a page on some other origin cannot submit an action
	// form here (login CSRF against the magic-link page most of all). It
	// reads Fetch metadata, so it needs no cookie and never fails a user
	// whose browser blocks them.
	crossOrigin *http.CrossOriginProtection
	actions     map[string]actionKind
}

// Handler returns the http.Handler for everything under /auth/: the sign-in
// page at /auth/ and the five emailed-link action pages. hostedOAuthEnabled
// reports whether the hosted OAuth routes are mounted at all; without them
// the sign-in page renders no provider buttons.
func Handler(cfg *config.Config, svc Service, hostedOAuthEnabled bool, logger *zap.Logger) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	base := template.Must(template.ParseFS(templateFS, "templates/layout.html"))
	login := template.Must(template.Must(base.Clone()).ParseFS(templateFS, "templates/login.html"))
	action := template.Must(template.Must(base.Clone()).ParseFS(templateFS, "templates/action.html"))

	h := &handler{
		cfg:                cfg,
		svc:                svc,
		logger:             logger,
		hostedOAuthEnabled: hostedOAuthEnabled,
		login:              login,
		action:             action,
		crossOrigin:        http.NewCrossOriginProtection(),
		actions:            map[string]actionKind{},
	}
	for _, kind := range actionKinds() {
		h.actions[kind.path] = kind
	}
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case loginPath, loginIndexPath:
		h.serveLogin(w, r)
		return
	}
	if kind, ok := h.actions[r.URL.Path]; ok {
		h.serveAction(w, r, kind)
		return
	}
	http.NotFound(w, r)
}

func (h *handler) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nonce, err := newNonce()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	opts := h.svc.HostedUIOptions(r.Context())
	providers := opts.OAuthProviders
	if providers == nil {
		providers = []service.HostedUIProvider{}
	}
	siteKey := captchaUISiteKey(h.cfg)
	data := configData{
		PasswordLoginEnabled:  opts.PasswordLoginEnabled,
		PasswordSignupEnabled: opts.PasswordSignupEnabled,
		OAuthProviders:        providers,
		HostedOAuthEnabled:    h.hostedOAuthEnabled,
		CaptchaProvider:       captchaUIProvider(h.cfg),
		CaptchaSiteKey:        siteKey,
		CaptchaEnforceLogin:   siteKey != "" && h.cfg.AssuranceEnforcePasswordLogin,
		CaptchaEnforceSignup:  siteKey != "" && h.cfg.AssuranceEnforcePasswordSignup,
	}
	if data.CaptchaProvider != "" {
		data.CaptchaScriptURL = turnstileScriptURL
	}
	b, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := h.login.ExecuteTemplate(&buf, "layout.html", loginPage{
		Nonce: nonce,
		// b is json.Marshal of a configData struct (bools, operator-set
		// strings from server env config, and server-side provider keys),
		// with no user-controlled input, so injecting it unescaped is safe.
		JSONConfig: template.JS("window.serverConfig = " + string(b) + ";"), //nolint:gosec // G203: static server-generated config, no user input
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w.Header(), pagePolicy{
		nonce:      nonce,
		scripts:    true,
		captcha:    data.CaptchaProvider != "",
		formAction: true,
	})
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// captchaUISiteKey returns the PUBLIC site key for the active provider, or ""
// when assurance is disabled or no site key is configured — in which case the
// sign-in page renders no widget.
func captchaUISiteKey(cfg *config.Config) string {
	if !cfg.AssuranceEnabled {
		return ""
	}
	if cfg.AssuranceWebProvider == config.AssuranceWebProviderTurnstile {
		return cfg.AssuranceTurnstileSiteKey
	}
	return ""
}

// captchaUIProvider names the provider the sign-in page should render, or
// "" when there is no public site key to render a widget for.
func captchaUIProvider(cfg *config.Config) string {
	if captchaUISiteKey(cfg) == "" {
		return ""
	}
	return cfg.AssuranceWebProvider
}
