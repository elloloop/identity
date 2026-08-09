package app

import (
	"encoding/json"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
)

// ssoSessionCookieName is the browser's SSO session cookie (ADR-0014).
//
// The `__Host-` prefix is not decoration: it makes the browser REFUSE the
// cookie unless it is Secure, Path=/, and carries no Domain attribute. That
// last one is the property the whole design rests on — the cookie is locked
// to the auth origin and can never be widened to a parent domain where
// product origins would receive it. A misconfiguration fails visibly (no
// cookie) instead of quietly leaking the session to every subdomain.
const ssoSessionCookieName = "__Host-sso_session"

// ssoHandler serves the two browser-facing SSO endpoints:
//
//	GET /oauth/continue?return_to=<app-url>[&fallback_to=<hub-url>]
//	GET /sso/session
//
// The split is deliberate. The CARD ("Continue as <email>") is drawn by the
// sign-in hub, which is a different origin from this API; it learns who to
// name from /sso/session, a credentialed same-site read restricted to the
// configured hub origins. The MINT happens through /oauth/continue as a
// top-level navigation, because that is the context a SameSite=Lax cookie is
// sent in — and because the result is a 302 carrying a single-use code,
// exactly like a completed provider round trip.
type ssoHandler struct {
	auth       *service.AuthService
	allowlist  service.ReturnAllowlist
	hubOrigins []string
	enabled    bool
	logger     *zap.Logger
}

// register wires the SSO routes. Each is registered only when the thing it
// depends on is configured, so an unconfigured deployment 404s rather than
// serving a half-working endpoint: /oauth/continue needs both SSO and the
// return allowlist (it validates return_to exactly as /oauth/start does), and
// /sso/session needs at least one hub origin allowed to read it.
func (h *ssoHandler) register(mux *http.ServeMux) {
	if !h.enabled {
		return
	}
	if h.allowlist.Enabled() {
		mux.HandleFunc("/oauth/continue", h.handleContinue)
	}
	if len(h.hubOrigins) > 0 {
		mux.HandleFunc("/sso/session", h.handleSession)
	}
}

// handleContinue spends a valid SSO cookie on a fresh session for the
// requesting product: it mints the same single-use code a provider round trip
// would have produced and 302s to return_to?code=…
//
// return_to runs the same allowlist check /oauth/start runs, before anything
// else happens. Optional fallback_to — checked against the SAME allowlist —
// is where a browser goes when the fast path does not apply (session expired,
// revoked between the card and the tap, or an account that owes a second
// factor); it receives ?session=expired so the hub can say something true
// instead of showing a dead end. Without a usable fallback_to the request
// fails closed with a 400 rather than redirecting somewhere unvetted.
func (h *ssoHandler) handleContinue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if !h.allowlist.Allows(returnTo) {
		// Fail closed without echoing the value, matching /oauth/start.
		h.logger.Info("sso_continue_return_to_rejected")
		http.Error(w, "return_to is not allowed", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(ssoSessionCookieName)
	if err != nil {
		h.fallback(w, r, "no_cookie")
		return
	}

	result, err := h.auth.ContinueSSOSession(
		r.Context(), cookie.Value, returnTo, clientIPFromRequest(r), r.UserAgent(),
	)
	if err != nil {
		// An unusable cookie is cleared on the way out: leaving it in place
		// would make every later visit repeat this failed round trip.
		if errors.Is(err, service.ErrSSOSessionInvalid) {
			http.SetCookie(w, clearSSOSessionCookie())
			h.fallback(w, r, "invalid_session")
			return
		}
		if errors.Is(err, service.ErrSSOSecondFactorRequired) {
			// The cookie stays: the session is real, it just cannot skip the
			// factor. The user completes a full sign-in and keeps SSO for
			// products that come after.
			h.fallback(w, r, "second_factor_required")
			return
		}
		// Everything else — a refused product age gate, an off-allowlist
		// account, a deactivated user — is a real denial, not a fallback.
		// Sending the browser back to a sign-in page would loop it forever
		// against a door that will keep saying no.
		h.logger.Info("sso_continue_denied", zap.Error(err))
		http.Error(w, "sign-in is not available for this account", http.StatusForbidden)
		return
	}

	// #nosec G710 -- returnTo passed the GATEWAY_OAUTH_ALLOWED_RETURN_URLS
	// allowlist above; it is not raw request input.
	http.Redirect(w, r, appendQueryParam(result.ReturnTo, "code", result.Code), http.StatusFound)
}

// fallback sends the browser back to the sign-in hub with an honest marker,
// or 400s when no allowlisted fallback was supplied.
func (h *ssoHandler) fallback(w http.ResponseWriter, r *http.Request, reason string) {
	h.logger.Info("sso_continue_fallback", zap.String("reason", reason))
	fallbackTo := r.URL.Query().Get("fallback_to")
	if !h.allowlist.Allows(fallbackTo) {
		http.Error(w, "no sso session", http.StatusBadRequest)
		return
	}
	// #nosec G710 -- fallbackTo passed the same allowlist return_to does.
	http.Redirect(w, r, appendQueryParam(fallbackTo, "session", "expired"), http.StatusFound)
}

// ssoSessionResponse is what the hub learns: whether there is a session, whose
// it is, and whether this deployment wants a visible tap before minting.
//
// Nothing else is exposed — no session id, no timestamps, no login method —
// because the payload crosses an origin boundary. Email is present only when
// authenticated, so the "no" answer carries no data at all.
type ssoSessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Email         string `json:"email,omitempty"`
	ContinueMode  string `json:"continueMode,omitempty"`
}

// handleSession answers "is this browser signed in, and as whom" for the
// sign-in hub, which is a separate origin and so must ask with credentials.
//
// Access is restricted to GATEWAY_SSO_HUB_ORIGINS, echoed back exactly (never
// `*`, which browsers refuse alongside credentials anyway) with Vary: Origin
// so a shared cache can never serve one origin's CORS headers to another. An
// origin that is not on the list gets no CORS headers at all, which is what
// stops any other site from reading who you are signed in as.
//
// The answer is never cached: it changes on every sign-in and sign-out, and a
// stale "authenticated" would have the hub name the wrong account.
func (h *ssoHandler) handleSession(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := h.allowsOrigin(origin)
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Add("Vary", "Origin")

	if r.Method == http.MethodOptions {
		if !allowed {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !allowed {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	resp := ssoSessionResponse{}
	if cookie, err := r.Cookie(ssoSessionCookieName); err == nil {
		view, viewErr := h.auth.IntrospectSSOSession(r.Context(), cookie.Value)
		switch {
		case viewErr == nil:
			resp = ssoSessionResponse{Authenticated: true, Email: view.Email, ContinueMode: view.ContinueMode}
		case errors.Is(viewErr, service.ErrSSOSessionInvalid):
			// Indistinguishable from "no cookie" on purpose.
		default:
			h.logger.Warn("sso_session_introspect_failed", zap.Error(viewErr))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Warn("sso_session_encode_failed", zap.Error(err))
	}
}

// allowsOrigin matches the request Origin against the configured hub list.
// The comparison is exact — no suffix or prefix matching, which is the class
// of bug that turns `https://accounts.example.com` into a match for
// `https://accounts.example.com.attacker.test`.
func (h *ssoHandler) allowsOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	for _, allowed := range h.hubOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// newSSOSessionCookie builds the Set-Cookie for a freshly established
// session. Every attribute here is load-bearing:
//
//   - HttpOnly: script on the auth origin cannot read it.
//   - Secure + no Domain (enforced by the __Host- prefix): the cookie is
//     locked to the auth origin and never travels to a product origin.
//   - SameSite=Lax: sent on the top-level navigations the flow is built from,
//     withheld from cross-site subrequests, so a third-party page cannot spend
//     the session by embedding a request to /oauth/continue.
func newSSOSessionCookie(value string, maxAgeSeconds int) *http.Cookie {
	return &http.Cookie{
		Name:     ssoSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearSSOSessionCookie expires the cookie. The attributes must match the
// ones it was set with or the browser will keep the original.
func clearSSOSessionCookie() *http.Cookie {
	return newSSOSessionCookie("", -1)
}
