package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// newSSOTestHandler builds the full app handler with SSO enabled in the
// given continue mode.
func newSSOTestHandler(t *testing.T, continueMode string) http.Handler {
	t.Helper()
	return newHostedTestHandlerWithConfig(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}),
		func(c *config.Config) {
			c.SSOEnabled = true
			c.SSOSessionTTLSeconds = 3600
			c.SSOContinueMode = continueMode
		})
}

// completeHostedLogin drives the hosted start→callback flow and returns
// the SSO session cookie the callback sets.
func completeHostedLogin(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil))
	if startRR.Code != http.StatusFound {
		t.Fatalf("start status = %d, want 302", startRR.Code)
	}
	loc, _ := url.Parse(startRR.Header().Get("Location"))
	stateToken := loc.Query().Get("state")

	cbRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?state="+url.QueryEscape(stateToken)+"&code=auth-xyz", nil)
	for _, c := range startRR.Result().Cookies() {
		req.AddCookie(c)
	}
	h.ServeHTTP(cbRR, req)
	if cbRR.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body=%q", cbRR.Code, cbRR.Body.String())
	}
	for _, c := range cbRR.Result().Cookies() {
		if c.Name == ssoSessionCookieName {
			return c
		}
	}
	t.Fatal("callback set no SSO session cookie")
	return nil
}

func TestSSOSessionCookie_Attributes(t *testing.T) {
	c := ssoSessionCookie("opaque-token", 3600)
	if c.Name != "__Host-sso_session" {
		t.Errorf("name = %q, want __Host- prefixed", c.Name)
	}
	if !c.HttpOnly || !c.Secure {
		t.Errorf("HttpOnly=%v Secure=%v, both must be true", c.HttpOnly, c.Secure)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q, must be empty so the browser pins the cookie to the auth origin host", c.Domain)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want / (a __Host- cookie requirement)", c.Path)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge != 3600 {
		t.Errorf("MaxAge = %d, want 3600", c.MaxAge)
	}
}

func TestSSOHTTP_DisabledByDefaultRouteNotRegistered(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/sso/continue?return_to="+url.QueryEscape("https://app.test/finish"), nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (SSO is default-off)", rr.Code)
	}
}

func TestSSOHTTP_CallbackSetsSSOCookieAndContinueAsMintsCode(t *testing.T) {
	h := newSSOTestHandler(t, config.SSOContinueModeSilent)

	cookie := completeHostedLogin(t, h)
	if !cookie.HttpOnly || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" {
		t.Fatalf("SSO cookie attributes wrong: %+v", cookie)
	}
	if cookie.MaxAge != 3600 {
		t.Fatalf("SSO cookie MaxAge = %d, want 3600 (GATEWAY_SSO_SESSION_TTL_SECONDS)", cookie.MaxAge)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/sso/continue?return_to="+url.QueryEscape("https://app.test/finish"), nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("continue status = %d, want 302; body=%q", rr.Code, rr.Body.String())
	}
	redir := rr.Header().Get("Location")
	if !strings.HasPrefix(redir, "https://app.test/finish") {
		t.Fatalf("continue redirect = %q", redir)
	}
	cb, _ := url.Parse(redir)
	if cb.Query().Get("code") == "" {
		t.Fatal("continue redirect carried no one-time code")
	}
}

func TestSSOHTTP_ContinueWithoutCookieRedirectsToLogin(t *testing.T) {
	h := newSSOTestHandler(t, config.SSOContinueModeSilent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/sso/continue?return_to="+url.QueryEscape("https://app.test/finish"), nil))

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/auth/" {
		t.Fatalf("redirect = %q, want the hosted sign-in page", loc)
	}
	if got := loc.Query().Get("return_to"); got != "https://app.test/finish" {
		t.Fatalf("return_to = %q, want the original destination preserved", got)
	}
}

func TestSSOHTTP_ContinueWithForgedCookieRedirectsToLogin(t *testing.T) {
	h := newSSOTestHandler(t, config.SSOContinueModeSilent)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/sso/continue?return_to="+url.QueryEscape("https://app.test/finish"), nil)
	req.AddCookie(&http.Cookie{ // #nosec G124 -- test fixture; attributes are irrelevant for a forged value.
		Name:     ssoSessionCookieName,
		Value:    "forged",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/") {
		t.Fatalf("redirect = %q, want the hosted sign-in page", loc)
	}
}

func TestSSOHTTP_ContinueRejectsDisallowedReturnTo(t *testing.T) {
	h := newSSOTestHandler(t, config.SSOContinueModeSilent)
	cookie := completeHostedLogin(t, h)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/sso/continue?return_to="+url.QueryEscape("https://evil.example.com/steal"), nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestSSOHTTP_OneTapConfirmsBeforeMinting(t *testing.T) {
	h := newSSOTestHandler(t, config.SSOContinueModeOneTap)
	cookie := completeHostedLogin(t, h)

	// GET renders the confirmation page instead of minting.
	getRR := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet,
		"/sso/continue?return_to="+url.QueryEscape("https://app.test/finish"), nil)
	getReq.AddCookie(cookie)
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("one-tap GET status = %d, want 200; body=%q", getRR.Code, getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), "app.test") {
		t.Fatal("confirmation page does not name the destination host")
	}

	// The confirming POST mints the code and redirects.
	postRR := httptest.NewRecorder()
	form := url.Values{}
	form.Set("return_to", "https://app.test/finish")
	postReq := httptest.NewRequest(http.MethodPost, "/sso/continue", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(cookie)
	h.ServeHTTP(postRR, postReq)

	if postRR.Code != http.StatusFound {
		t.Fatalf("one-tap POST status = %d, want 302; body=%q", postRR.Code, postRR.Body.String())
	}
	cb, _ := url.Parse(postRR.Header().Get("Location"))
	if cb.Query().Get("code") == "" {
		t.Fatal("one-tap POST redirect carried no one-time code")
	}
}
