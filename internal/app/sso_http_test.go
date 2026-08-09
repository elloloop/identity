package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// ssoTestOptions tunes the deployment a test runs against.
type ssoTestOptions struct {
	allowlist    string
	hubOrigins   string
	ssoEnabled   bool
	continueMode string
}

func newSSOTestHandler(t *testing.T, opts ssoTestOptions) http.Handler {
	t.Helper()
	signer := jwttest.NewSigner(t, "sso-app-test")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: "localhost", RPName: "Test", Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	mode := opts.continueMode
	if mode == "" {
		mode = config.SSOContinueModeTap
	}
	repo := memory.New()
	built, err := New(Deps{
		Config: &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
			DefaultTenantID:          "tenant",
			DefaultProjectAccessMode: service.AccessModeOpen,
			AuthAllowLocal:           true,
			AllowedOrigins:           "http://localhost:9002",
			JWTExpirySeconds:         900,
			RefreshExpirySeconds:     604800,
			LoginMaxFailedAttempts:   5,
			LoginLockoutSeconds:      900,
			PasskeyRPID:              "localhost",
			PasskeyRPName:            "Test",
			PasskeyOrigin:            "http://localhost:9002",
			OAuthAllowedReturnURLs:   opts.allowlist,
			SSOEnabled:               opts.ssoEnabled,
			SSOSessionTTLSeconds:     3600,
			SSOContinueMode:          mode,
			SSOHubOrigins:            opts.hubOrigins,
		},
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 repo,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		OAuthRegistry:      hostedTestRegistry(&appTestStubProvider{}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)
	return built.Handler
}

// signInThroughHostedFlow drives /oauth/start + /oauth/callback and returns
// the SSO cookie the callback set (nil when it set none).
func signInThroughHostedFlow(t *testing.T, h http.Handler, returnTo string) *http.Cookie {
	t.Helper()

	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape(returnTo), nil))
	if startRR.Code != http.StatusFound {
		t.Fatalf("start: status = %d, body=%q", startRR.Code, startRR.Body.String())
	}
	loc, err := url.Parse(startRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse start Location: %v", err)
	}
	state := loc.Query().Get("state")

	cbReq := httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range startRR.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRR := httptest.NewRecorder()
	h.ServeHTTP(cbRR, cbReq)
	if cbRR.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body=%q", cbRR.Code, cbRR.Body.String())
	}
	return findCookie(cbRR.Result().Cookies(), ssoSessionCookieName)
}

// unknownSSOCookie builds a request-side cookie naming a session that does
// not exist. Request cookies carry only name and value — the Secure/HttpOnly
// attributes live on the Set-Cookie the SERVER sends — so it reuses the
// production constructor to keep the linter's attribute check satisfied.
func unknownSSOCookie(value string) *http.Cookie {
	return newSSOSessionCookie(value, 3600)
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// The cookie's attributes are the security boundary, so they are asserted
// individually rather than trusted to the constructor.
func TestSSOHTTP_CallbackSetsHostLockedCookie(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/", ssoEnabled: true,
	})

	cookie := signInThroughHostedFlow(t, h, "https://app.test/finish")
	if cookie == nil {
		t.Fatal("a successful callback set no SSO cookie")
	}
	if cookie.Value == "" {
		t.Fatal("SSO cookie carries no value")
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatalf("cookie name %q lacks the __Host- prefix that makes host-locking browser-enforced", cookie.Name)
	}
	if cookie.Domain != "" {
		t.Fatalf("cookie carries Domain=%q — it must be host-only so product origins never receive it", cookie.Domain)
	}
	if !cookie.HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Fatal("cookie must be Secure")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Fatalf("cookie Path = %q, want /", cookie.Path)
	}
	if cookie.MaxAge != 3600 {
		t.Fatalf("cookie MaxAge = %d, want the session TTL (3600)", cookie.MaxAge)
	}
}

// A deployment that has not opted in sets nothing and serves neither endpoint.
func TestSSOHTTP_DisabledSetsNoCookieAndServesNoRoutes(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/", hubOrigins: "https://hub.test", ssoEnabled: false,
	})

	if cookie := signInThroughHostedFlow(t, h, "https://app.test/finish"); cookie != nil {
		t.Fatalf("SSO disabled but the callback set %q", cookie.Name)
	}

	for _, path := range []string{"/oauth/continue?return_to=https://app.test/finish", "/sso/session"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404 when SSO is off", path, rr.Code)
		}
	}
}

// The fast path: cookie in, one-time code out, no provider round trip.
func TestSSOHTTP_ContinueRedirectsWithFreshCode(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/,https://other.test/", ssoEnabled: true,
	})
	cookie := signInThroughHostedFlow(t, h, "https://app.test/finish")
	if cookie == nil {
		t.Fatal("no SSO cookie to continue with")
	}

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/continue?return_to="+url.QueryEscape("https://other.test/cb"), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://other.test/cb" {
		t.Fatalf("redirected to %q, want the requested return_to", got)
	}
	if loc.Query().Get("code") == "" {
		t.Fatal("continue redirect carried no one-time code")
	}
}

// return_to is allowlisted before anything else happens, exactly as at
// /oauth/start — an SSO session must not become a redirect oracle.
func TestSSOHTTP_ContinueRejectsDisallowedReturnTo(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/", ssoEnabled: true,
	})
	cookie := signInThroughHostedFlow(t, h, "https://app.test/finish")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/continue?return_to="+url.QueryEscape("https://evil.test/steal"), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an off-allowlist return_to", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "evil.test") {
		t.Fatal("the rejected value was reflected back into the response")
	}
}

// No cookie, or a dead one, sends the browser to the sign-in hub with an
// honest marker — and clears the cookie when it was the problem.
func TestSSOHTTP_ContinueFallsBackToHub(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/,https://hub.test/", ssoEnabled: true,
	})

	t.Run("no cookie with fallback", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
			"/oauth/continue?return_to="+url.QueryEscape("https://app.test/finish")+
				"&fallback_to="+url.QueryEscape("https://hub.test/signin"), nil))

		if rr.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 to the hub", rr.Code)
		}
		loc, err := url.Parse(rr.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse Location: %v", err)
		}
		if loc.Host != "hub.test" || loc.Query().Get("session") != "expired" {
			t.Fatalf("fallback went to %q", rr.Header().Get("Location"))
		}
	})

	t.Run("no cookie without fallback fails closed", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
			"/oauth/continue?return_to="+url.QueryEscape("https://app.test/finish"), nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 with no allowlisted fallback", rr.Code)
		}
	})

	t.Run("off-allowlist fallback is refused", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
			"/oauth/continue?return_to="+url.QueryEscape("https://app.test/finish")+
				"&fallback_to="+url.QueryEscape("https://evil.test/"), nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for an off-allowlist fallback_to", rr.Code)
		}
	})

	t.Run("unknown cookie is cleared", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/oauth/continue?return_to="+url.QueryEscape("https://app.test/finish")+
				"&fallback_to="+url.QueryEscape("https://hub.test/signin"), nil)
		req.AddCookie(unknownSSOCookie("not-a-session"))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rr.Code)
		}
		cleared := findCookie(rr.Result().Cookies(), ssoSessionCookieName)
		if cleared == nil || cleared.MaxAge >= 0 {
			t.Fatalf("an unusable cookie must be cleared, got %#v", cleared)
		}
	})
}

func TestSSOHTTP_ContinueRejectsNonGET(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{allowlist: "https://app.test/", ssoEnabled: true})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/oauth/continue", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

// Introspection is the one place the account's email crosses an origin
// boundary, so who may read it is the whole test.
func TestSSOHTTP_SessionIntrospection(t *testing.T) {
	const hub = "https://hub.test"
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/", hubOrigins: hub, ssoEnabled: true,
	})
	cookie := signInThroughHostedFlow(t, h, "https://app.test/finish")
	if cookie == nil {
		t.Fatal("no SSO cookie established")
	}

	get := func(origin string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/sso/session", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if c != nil {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	t.Run("allowed origin reads the account", func(t *testing.T) {
		rr := get(hub, cookie)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != hub {
			t.Fatalf("Access-Control-Allow-Origin = %q, want the exact hub origin", got)
		}
		if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Fatalf("Access-Control-Allow-Credentials = %q", got)
		}
		if !strings.Contains(rr.Header().Get("Vary"), "Origin") {
			t.Fatal("Vary: Origin missing — a shared cache could serve one origin's CORS headers to another")
		}
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}

		var body struct {
			Authenticated bool   `json:"authenticated"`
			Email         string `json:"email"`
			ContinueMode  string `json:"continueMode"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !body.Authenticated || body.Email != "app-hosted@example.com" {
			t.Fatalf("body = %+v", body)
		}
		if body.ContinueMode != config.SSOContinueModeTap {
			t.Fatalf("continueMode = %q, want the deployment's configured mode", body.ContinueMode)
		}
	})

	t.Run("another origin is refused even holding the cookie", func(t *testing.T) {
		rr := get("https://evil.test", cookie)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for a non-hub origin", rr.Code)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("a refused origin must get no CORS grant, got %q", got)
		}
		if strings.Contains(rr.Body.String(), "app-hosted@example.com") {
			t.Fatal("the account email leaked to a disallowed origin")
		}
	})

	t.Run("a prefix of an allowed origin is not a match", func(t *testing.T) {
		// The classic CORS allowlist bug: suffix/prefix matching would make
		// hub.test.attacker.test a match for hub.test.
		rr := get("https://hub.test.attacker.test", cookie)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})

	t.Run("no origin header is refused", func(t *testing.T) {
		if rr := get("", cookie); rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 with no Origin", rr.Code)
		}
	})

	t.Run("no cookie answers not-authenticated", func(t *testing.T) {
		rr := get(hub, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["authenticated"] != false {
			t.Fatalf("body = %+v", body)
		}
		if _, present := body["email"]; present {
			t.Fatal("the negative answer must carry no account data")
		}
	})

	t.Run("an unknown cookie is indistinguishable from none", func(t *testing.T) {
		rr := get(hub, unknownSSOCookie("no-such-session"))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), `"authenticated":false`) {
			t.Fatalf("body = %q", rr.Body.String())
		}
	})

	t.Run("preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/sso/session", nil)
		req.Header.Set("Origin", hub)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want 204", rr.Code)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != hub {
			t.Fatalf("preflight Access-Control-Allow-Origin = %q", got)
		}

		bad := httptest.NewRequest(http.MethodOptions, "/sso/session", nil)
		bad.Header.Set("Origin", "https://evil.test")
		badRR := httptest.NewRecorder()
		h.ServeHTTP(badRR, bad)
		if badRR.Code != http.StatusForbidden {
			t.Fatalf("preflight from a bad origin: status = %d, want 403", badRR.Code)
		}
	})
}

// With no hub origin configured the endpoint is not served at all, so a
// deployment cannot half-enable the one surface that discloses an account.
func TestSSOHTTP_SessionUnregisteredWithoutHubOrigins(t *testing.T) {
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/", ssoEnabled: true, hubOrigins: "",
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sso/session", nil)
	req.Header.Set("Origin", "https://hub.test")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 with no configured hub origins", rr.Code)
	}
}

// The continue mode reaches the hub, which is what makes the tap-vs-silent
// decision a config value rather than a rebuild.
func TestSSOHTTP_SilentModeReportedToHub(t *testing.T) {
	const hub = "https://hub.test"
	h := newSSOTestHandler(t, ssoTestOptions{
		allowlist: "https://app.test/", hubOrigins: hub, ssoEnabled: true,
		continueMode: config.SSOContinueModeSilent,
	})
	cookie := signInThroughHostedFlow(t, h, "https://app.test/finish")

	req := httptest.NewRequest(http.MethodGet, "/sso/session", nil)
	req.Header.Set("Origin", hub)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), `"continueMode":"silent"`) {
		t.Fatalf("body = %q", rr.Body.String())
	}
}
