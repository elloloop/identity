package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/app/ui"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// hostedOAuthHandler serves the browser-facing hosted OAuth endpoints:
//
//	GET /oauth/start/{provider}?return_to=<app-url>[&code_challenge=<S256>&code_challenge_method=S256]
//	GET/POST /oauth/callback/{provider}
//	GET /auth/code (ui.CodePageHandler)
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
	mux.Handle(ui.CodePagePath, ui.CodePageHandler(h.allowlist))
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

	// Trimmed as the allowlist and the state token trim it, so every check
	// below judges the value the state token will carry.
	returnTo := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if !h.allowlist.Allows(returnTo) {
		// Fail closed: a disallowed return_to is rejected before any
		// provider round-trip. We do not echo the value back to avoid
		// reflecting attacker-controlled content.
		h.logger.Info("hosted_oauth_return_to_rejected", zap.String("provider", provider))
		http.Error(w, "return_to is not allowed", http.StatusBadRequest)
		return
	}
	appCodeChallenge, ok := hostedAppCodeChallenge(r.URL.Query())
	if !ok {
		h.logger.Info("hosted_oauth_code_challenge_rejected", zap.String("provider", provider))
		http.Error(w, "code_challenge must be an S256 challenge sent with code_challenge_method=S256", http.StatusBadRequest)
		return
	}
	if refusal := h.codePageReturnRefusal(r, returnTo, appCodeChallenge); refusal != nil {
		h.logger.Info("hosted_oauth_code_page_return_rejected",
			zap.String("provider", provider), zap.String("reason", refusal.reason))
		http.Error(w, refusal.message, http.StatusBadRequest)
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

	// The key that scoped this request (already validated by the project
	// middleware) is threaded into BeginHostedOAuth so it can prefix the
	// OAuth state — that prefix is how the callback, arriving on the hub
	// host with no header, re-scopes to the same project. Header first,
	// matching the middleware's resolution precedence, so the prefixed key
	// always names the project the request actually resolved to.
	projectKey := r.Header.Get(middleware.ProjectKeyHeader)
	if projectKey == "" {
		projectKey = r.URL.Query().Get(middleware.ProjectKeyParam)
	}

	redirectURI := h.callbackURL(r, provider)
	result, err := h.auth.BeginHostedOAuth(r.Context(), provider, redirectURI, returnTo, csrfToken, appCodeChallenge, projectKey)
	if err != nil {
		h.logger.Info("hosted_oauth_start_failed", zap.String("provider", provider), zap.Error(err))
		status := http.StatusBadRequest
		if isOAuthDisabled(err) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "could not start oauth", status)
		return
	}
	http.SetCookie(w, hostedOAuthCSRFCookie(provider, appendHostedOAuthCSRFToken(csrfTokens, csrfToken), 900))
	// #nosec G710 -- the redirect target is the provider authorization
	// URL built server-side by BeginHostedOAuth from the registered
	// provider config, not from request input.
	http.Redirect(w, r, result.AuthorizationURL, http.StatusFound)
}

func (h *hostedOAuthHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
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

	provider := pathProvider(r.URL.Path, "/oauth/callback/")
	if provider == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")

	csrfTokens, ok := hostedOAuthCSRFTokens(r, provider)
	if !ok {
		h.logger.Info("hosted_oauth_csrf_cookie_invalid", zap.String("provider", provider))
		http.Error(w, "oauth failed", http.StatusBadRequest)
		return
	}

	if r.FormValue("error") != "" {
		refusal, err := h.auth.CancelHostedOAuth(r.Context(), provider, state, csrfTokens)
		if err != nil {
			http.Error(w, "oauth failed", http.StatusBadRequest)
			return
		}
		h.finishCallback(w, r, provider, csrfTokens, refusal.CSRFToken,
			appendQueryParam(refusal.ReturnTo, "error", refusal.Code))
		return
	}

	result, err := h.auth.CompleteHostedOAuth(
		r.Context(), provider, r.FormValue("code"), state, r.FormValue("user"),
		clientIPFromRequest(r), r.UserAgent(), csrfTokens,
	)
	if err != nil {
		h.logger.Info("hosted_oauth_callback_failed",
			zap.String("provider", provider), zap.Error(err))
		var refusal *service.HostedOAuthRefusalError
		if !errors.As(err, &refusal) {
			// No verified return_to (the state token or its CSRF binding
			// failed), so there is nowhere safe to send the browser.
			http.Error(w, "oauth failed", http.StatusBadRequest)
			return
		}
		h.finishCallback(w, r, provider, csrfTokens, refusal.CSRFToken,
			appendQueryParam(refusal.ReturnTo, "error", refusal.Code))
		return
	}
	h.finishCallback(w, r, provider, csrfTokens, result.CSRFToken,
		appendQueryParam(result.ReturnTo, "code", result.Code))
}

// hostedAppCodeChallenge returns the app's own PKCE challenge from a /start
// query, or "" when it sent neither code_challenge nor code_challenge_method.
// ok=false refuses any other pair: the method must be S256 (RFC 7636's plain
// would put the verifier itself in the browser's address bar) and the
// challenge an S256 challenge.
func hostedAppCodeChallenge(q url.Values) (challenge string, ok bool) {
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	if challenge == "" && method == "" {
		return "", true
	}
	return challenge, method == "S256" && service.ValidS256Challenge(challenge)
}

// finishCallback spends the flow's CSRF token and redirects to target, a
// return_to recovered from the signed, tamper-proof hosted state token whose
// value was validated against GATEWAY_OAUTH_ALLOWED_RETURN_URLS at /start.
func (h *hostedOAuthHandler) finishCallback(w http.ResponseWriter, r *http.Request, provider string, csrfTokens []string, spent, target string) {
	remainingCSRFTokens := removeHostedOAuthCSRFToken(csrfTokens, spent)
	maxAge := 900
	if len(remainingCSRFTokens) == 0 {
		maxAge = -1
	}
	http.SetCookie(w, hostedOAuthCSRFCookie(provider, remainingCSRFTokens, maxAge))
	// #nosec G710 -- target is built on the state token's allowlisted
	// return_to, not raw request input.
	http.Redirect(w, r, target, http.StatusFound)
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
	origin := ui.RequestOrigin(r)
	return origin.Scheme + "://" + origin.Host + "/oauth/callback/" + provider
}

// codePageRefusal is why a sign-in may not return to this server's code
// page: a fixed reason for the log, and the message the 400 answers with.
type codePageRefusal struct {
	reason  string
	message string
}

// codePageReturnRefusal says why a sign-in may not return to this server's
// code page, or nil when it may, or when returnTo names another page. The
// code page is ui.CodePagePath on the hostname the request reached, on any
// port. The page shows the code for a person to copy, so the sign-in must be
// bound to the app with an S256 challenge, and any state must be one the
// page shows. And only an allowlist entry naming the page exactly admits it:
// an origin, path-prefix or wildcard entry that happens to cover it does not
// opt a deployment into a page whose code a person is asked to hand over.
// The page enforces that last rule itself, on every host; refusing here
// tells the app before the person signs in.
func (h *hostedOAuthHandler) codePageReturnRefusal(r *http.Request, returnTo, appCodeChallenge string) *codePageRefusal {
	u, err := url.Parse(returnTo)
	if err != nil {
		// Allows admitted this value, so this cannot happen; refuse rather
		// than skip the checks if it ever does.
		return &codePageRefusal{reason: "unparsable", message: "return_to is not allowed"}
	}
	if !strings.EqualFold(u.Hostname(), ui.RequestOrigin(r).Hostname()) || path.Clean(u.Path) != ui.CodePagePath {
		return nil
	}
	query := u.Query()
	switch {
	case u.Path != ui.CodePagePath:
		return &codePageRefusal{reason: "path_not_exact", message: "a code page return_to must name the page as exactly " + ui.CodePagePath}
	case !h.allowlist.AllowsExactly(returnTo):
		return &codePageRefusal{reason: "not_listed_exactly", message: "return_to is not allowed: the code page must be listed exactly"}
	case appCodeChallenge == "":
		return &codePageRefusal{
			reason:  "no_code_challenge",
			message: "a sign-in that returns to the code page needs code_challenge with code_challenge_method=S256",
		}
	case query.Has("state") && !ui.ValidCodePageState(query.Get("state")):
		return &codePageRefusal{
			reason: "state_not_hex",
			message: fmt.Sprintf("the state of a code page return_to must be %d to %d lowercase hex characters",
				ui.CodePageStateMinLen, ui.CodePageStateMaxLen),
		}
	}
	return nil
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
