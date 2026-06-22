package app

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
)

// hostedOAuthHandler serves the browser-facing hosted OAuth endpoints:
//
//	GET /oauth/start/{provider}?return_to=<app-url>
//	GET/POST /oauth/callback/{provider}
//
// These are plain HTTP routes (not Connect RPCs) because the browser is
// 302-redirected through them. They are thin wrappers over the existing
// AuthService internals — BeginHostedOAuth / CompleteHostedOAuth — and
// add no parallel exchange path.
//
// The single redirect URI registered with each provider is
// <this-origin>/oauth/callback/{provider}; it is derived from the
// incoming request so the same value is produced at /start and
// /callback time.
type hostedOAuthHandler struct {
	auth      *service.AuthService
	allowlist service.ReturnAllowlist
	logger    *zap.Logger
}

const (
	hostedOAuthCSRFCookiePrefix = "__Host-oauth_csrf_"
	hostedOAuthCSRFMaxTokens    = 16
)

// register wires the hosted routes onto mux. It is a no-op when the
// allowlist is empty (hosted flow disabled), leaving the routes
// unregistered so they 404 — the headless RPCs are unaffected.
func (h *hostedOAuthHandler) register(mux *http.ServeMux) {
	if !h.allowlist.Enabled() {
		return
	}
	mux.HandleFunc("/oauth/start/", h.handleStart)
	mux.HandleFunc("/oauth/callback/", h.handleCallback)
}

func (h *hostedOAuthHandler) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provider := pathProvider(r.URL.Path, "/oauth/start/")
	if provider == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if !h.allowlist.Allows(returnTo) {
		// Fail closed: a disallowed return_to is rejected before any
		// provider round-trip. We do not echo the value back to avoid
		// reflecting attacker-controlled content.
		h.logger.Info("hosted_oauth_return_to_rejected", zap.String("provider", provider))
		http.Error(w, "return_to is not allowed", http.StatusBadRequest)
		return
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrfToken := base64.RawURLEncoding.EncodeToString(b[:])
	csrfTokens, ok := hostedOAuthCSRFTokens(r, provider)
	if !ok {
		csrfTokens = nil
	}

	redirectURI := h.callbackURL(r, provider)
	result, err := h.auth.BeginHostedOAuth(r.Context(), provider, redirectURI, returnTo, csrfToken)
	if err != nil {
		h.logger.Info("hosted_oauth_start_failed", zap.String("provider", provider), zap.Error(err))
		status := http.StatusBadRequest
		if isOAuthDisabled(err) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "could not start oauth", status)
		return
	}
	// #nosec G710 -- the redirect target is the provider authorization
	// URL built server-side by BeginHostedOAuth from the registered
	// provider config, not from request input.
	http.SetCookie(w, hostedOAuthCSRFCookie(provider, appendHostedOAuthCSRFToken(csrfTokens, csrfToken), 900))
	http.Redirect(w, r, result.AuthorizationURL, http.StatusFound)
}

func (h *hostedOAuthHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB limit
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	provider := pathProvider(r.URL.Path, "/oauth/callback/")
	if provider == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")

	// Provider-side error (user denied consent, etc). We cannot recover
	// return_to without a valid state token, so there is nowhere safe to
	// redirect — surface a generic 400 and log server-side.
	if provErr := r.FormValue("error"); provErr != "" {
		h.logger.Info("hosted_oauth_provider_error",
			zap.String("provider", provider), zap.String("error", provErr))
		http.Error(w, "oauth failed", http.StatusBadRequest)
		return
	}

	csrfTokens, ok := hostedOAuthCSRFTokens(r, provider)
	if !ok {
		h.logger.Info("hosted_oauth_csrf_cookie_invalid", zap.String("provider", provider))
		http.Error(w, "oauth failed", http.StatusBadRequest)
		return
	}

	result, err := h.auth.CompleteHostedOAuth(
		r.Context(), provider, r.FormValue("code"), state, r.FormValue("user"),
		clientIPFromRequest(r), r.UserAgent(), csrfTokens,
	)
	if err != nil {
		// We do not have a verified return_to here (the state token failed
		// to verify or the exchange failed), so we cannot safely redirect
		// to an attacker-suppliable URL. Surface a generic 400.
		h.logger.Info("hosted_oauth_callback_failed",
			zap.String("provider", provider), zap.Error(err))
		http.Error(w, "oauth failed", http.StatusBadRequest)
		return
	}

	// #nosec G710 -- result.ReturnTo is recovered from the signed,
	// tamper-proof hosted state token whose return_to was validated
	// against the GATEWAY_OAUTH_ALLOWED_RETURN_URLS allowlist at /start
	// time. It is not raw request input.
	remainingCSRFTokens := removeHostedOAuthCSRFToken(csrfTokens, result.CSRFToken)
	maxAge := 900
	if len(remainingCSRFTokens) == 0 {
		maxAge = -1
	}
	http.SetCookie(w, hostedOAuthCSRFCookie(provider, remainingCSRFTokens, maxAge))
	http.Redirect(w, r, appendQueryParam(result.ReturnTo, "code", result.Code), http.StatusFound)
}

func hostedOAuthCSRFCookie(provider string, tokens []string, maxAge int) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	if provider == "apple" {
		sameSite = http.SameSiteNoneMode
	}
	return &http.Cookie{ // #nosec G124 -- Secure and HttpOnly are fixed; SameSite is Lax or None for Apple's cross-site form POST.
		Name:     hostedOAuthCSRFCookieName(provider),
		Value:    strings.Join(tokens, "."),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: sameSite,
	}
}

func hostedOAuthCSRFCookieName(provider string) string {
	return hostedOAuthCSRFCookiePrefix + provider
}

func hostedOAuthCSRFTokens(r *http.Request, provider string) ([]string, bool) {
	var value string
	found := false
	for _, cookie := range r.Cookies() {
		if cookie.Name != hostedOAuthCSRFCookieName(provider) {
			continue
		}
		if found {
			return nil, false
		}
		found = true
		value = cookie.Value
	}
	if !found {
		return nil, false
	}
	tokens := strings.Split(value, ".")
	if len(tokens) > hostedOAuthCSRFMaxTokens {
		return nil, false
	}
	for _, token := range tokens {
		if token == "" {
			return nil, false
		}
	}
	return tokens, true
}

func appendHostedOAuthCSRFToken(tokens []string, token string) []string {
	if len(tokens) == hostedOAuthCSRFMaxTokens {
		tokens = tokens[1:]
	}
	return append(tokens, token)
}

func removeHostedOAuthCSRFToken(tokens []string, token string) []string {
	remaining := make([]string, 0, len(tokens))
	for _, candidate := range tokens {
		if candidate != token {
			remaining = append(remaining, candidate)
		}
	}
	return remaining
}

// callbackURL reconstructs this server's single redirect URI for the
// provider from the incoming request, honoring X-Forwarded-Proto /
// X-Forwarded-Host when present (set by a trusted reverse proxy). The
// value must be identical at /start and /callback time and must match
// the URI registered with the provider exactly.
func (h *hostedOAuthHandler) callbackURL(r *http.Request, provider string) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host + "/oauth/callback/" + provider
}

// pathProvider extracts the {provider} path segment after prefix and
// rejects any extra path elements (e.g. /oauth/start/google/extra).
func pathProvider(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return strings.ToLower(rest)
}

// appendQueryParam adds key=value to base's query string, preserving any
// existing query. On a malformed base URL it falls back to a simple
// concatenation so the user still lands somewhere on the app origin.
func appendQueryParam(base, key, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		sep := "?"
		if strings.Contains(base, "?") {
			sep = "&"
		}
		return base + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func isOAuthDisabled(err error) bool {
	return err != nil && strings.Contains(err.Error(), service.ErrOAuthDisabled.Error())
}

// clientIPFromRequest returns the best-effort client IP for audit
// logging on the hosted callback. It prefers the first X-Forwarded-For
// hop, falling back to the request RemoteAddr. The hosted handler runs
// outside the Connect client-IP middleware (which keys on RPC headers),
// so it resolves the address itself.
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, ok := strings.Cut(r.RemoteAddr, ":"); ok {
		return host
	}
	return r.RemoteAddr
}
