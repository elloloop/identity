package app

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// ssoHandler serves the browser-facing cross-product continue-as endpoint:
//
//	GET  /sso/continue?return_to=<app-url>
//	POST /sso/continue            (one_tap confirmation)
//
// It is a plain HTTP route (not a Connect RPC) because the browser is
// 302-redirected through it. The handler is a thin wrapper over
// AuthService.ContinueWithSSO — every authorization gate lives in the
// service.
type ssoHandler struct {
	auth         *service.AuthService
	allowlist    service.ReturnAllowlist
	logger       *zap.Logger
	enabled      bool
	continueMode string
	sessionTTL   int // seconds; cookie MaxAge
}

// ssoSessionCookieName is __Host--prefixed so the browser itself pins the
// cookie to the auth origin host (no Domain attribute, Secure, Path=/).
const ssoSessionCookieName = "__Host-sso_session"

// register wires the continue-as route onto mux. It is a no-op when SSO is
// disabled, leaving the route unregistered so it 404s — a default-off
// deployment exposes no SSO surface at all.
func (h *ssoHandler) register(mux *http.ServeMux) {
	if !h.enabled {
		return
	}
	mux.HandleFunc("/sso/continue", h.handleContinue)
}

func (h *ssoHandler) handleContinue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, middleware.OAuthFormMaxBytes)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	returnTo := r.FormValue("return_to")
	if !h.allowlist.Allows(returnTo) {
		// Fail closed before any session lookup, and do not echo the value
		// back (attacker-controlled).
		h.logger.Info("sso_return_to_rejected")
		http.Error(w, "return_to is not allowed", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(ssoSessionCookieName)
	if err != nil || cookie.Value == "" {
		// No SSO session: fall back to a full interactive login at the auth
		// origin, carrying the destination so the user lands back here.
		h.redirectToLogin(w, r, returnTo)
		return
	}

	if r.Method == http.MethodGet && h.continueMode == config.SSOContinueModeOneTap {
		// One-tap: confirm before minting. The page is validated only on
		// POST, so it carries no account details — it cannot leak who is
		// signed in.
		h.renderConfirm(w, r, returnTo)
		return
	}

	result, err := h.auth.ContinueWithSSO(r.Context(), cookie.Value, returnTo, clientIPFromRequest(r), r.UserAgent())
	if err != nil {
		h.logger.Info("sso_continue_failed", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrSSODisabled):
			http.Error(w, "sso is not enabled", http.StatusServiceUnavailable)
		case errors.Is(err, service.ErrInvalidArgument):
			http.Error(w, "return_to is not allowed", http.StatusBadRequest)
		default:
			// Every other failure — unknown/expired session, wrong project,
			// suspended account, policy denial, a second factor now
			// required — falls back to a full interactive login, where the
			// user sees the real error. The specific reason is logged
			// above, never echoed to the browser.
			h.redirectToLogin(w, r, returnTo)
		}
		return
	}
	// #nosec G710 -- result.ReturnTo was validated against the
	// GATEWAY_OAUTH_ALLOWED_RETURN_URLS allowlist inside ContinueWithSSO.
	http.Redirect(w, r, appendQueryParam(result.ReturnTo, "code", result.Code), http.StatusFound)
}

// redirectToLogin sends the browser to the auth origin's hosted sign-in
// page, preserving the destination (and the project key, when the request
// carried one) so a completed login returns the user to the product.
func (h *ssoHandler) redirectToLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	q := url.Values{}
	q.Set("return_to", returnTo)
	if pk := r.FormValue(middleware.ProjectKeyParam); pk != "" {
		q.Set(middleware.ProjectKeyParam, pk)
	}
	http.Redirect(w, r, "/auth/?"+q.Encode(), http.StatusFound)
}

var ssoConfirmTemplate = template.Must(template.New("sso-confirm").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Continue</title>
</head>
<body>
<main>
<h1>Continue to {{.Destination}}</h1>
<p>You are signed in. Continue to {{.Destination}} with that account?</p>
<form method="post" action="/sso/continue">
<input type="hidden" name="return_to" value="{{.ReturnTo}}">
{{if .ProjectKey}}<input type="hidden" name="project_key" value="{{.ProjectKey}}">{{end}}
<button type="submit">Continue</button>
</form>
</main>
</body>
</html>`))

// renderConfirm serves the one-tap confirmation page. Destination is the
// allowlisted return_to's host — the only value shown, so the page reveals
// nothing about the signed-in account.
func (h *ssoHandler) renderConfirm(w http.ResponseWriter, r *http.Request, returnTo string) {
	destination := ""
	if u, err := url.Parse(returnTo); err == nil {
		destination = u.Host
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ssoConfirmTemplate.Execute(w, map[string]string{
		"Destination": destination,
		"ReturnTo":    returnTo,
		"ProjectKey":  r.FormValue(middleware.ProjectKeyParam),
	}); err != nil {
		h.logger.Warn("sso_confirm_render_failed", zap.Error(err))
	}
}

// ssoSessionCookie builds the auth origin's SSO cookie. The __Host- prefix
// contract is met by construction: Secure, Path=/, and NO Domain attribute,
// so the browser binds it to the exact auth origin host and never shares it
// with subdomains. SameSite=Lax lets top-level navigations (the product's
// continue-as link) carry it while cross-site POSTs cannot.
func ssoSessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure and HttpOnly are fixed; the __Host- rules are the point.
		Name:     ssoSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
