package app

import (
	"context"
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
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// appTestStubProvider is both an Exchanger and an Authorizer so the
// app-package handler tests can drive the full hosted flow without a
// live provider.
type appTestStubProvider struct {
	err   error
	email string
}

func (p *appTestStubProvider) AuthorizationURL(_ context.Context, redirectURI, state, _ string) (string, error) {
	u, _ := url.Parse("https://provider.test/authorize")
	q := u.Query()
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *appTestStubProvider) Exchange(_ context.Context, _ oauth.ExchangeParams) (*oauth.Identity, error) {
	if p.err != nil {
		return nil, p.err
	}
	email := p.email
	if email == "" {
		email = "app-hosted@example.com"
	}
	return &oauth.Identity{
		Provider:       "google",
		ProviderUserID: "app-hosted-user",
		Email:          email,
		EmailVerified:  true,
		Name:           "App Hosted",
	}, nil
}

func newHostedTestHandler(t *testing.T, allowlist string, reg *oauth.Registry) http.Handler {
	t.Helper()
	return newHostedTestHandlerWith(t, allowlist, reg, func(*config.Config) {})
}

func newHostedTestHandlerWith(t *testing.T, allowlist string, reg *oauth.Registry, configure func(*config.Config)) http.Handler {
	t.Helper()
	signer := jwttest.NewSigner(t, "hosted-app-test")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: "localhost", RPName: "Test", Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	cfg := &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
		DefaultTenantID: "tenant",
		// Open the env default project so the hosted-OAuth flow exercises the
		// handler chain rather than the access gate (default-DENY without this).
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
		OAuthAllowedReturnURLs:   allowlist,
	}
	configure(cfg)
	built, err := New(Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 repo,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		OAuthRegistry:      reg,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built.Start()
	handler := built.Handler
	t.Cleanup(built.Stop)
	return handler
}

func hostedTestRegistry(p oauth.Exchanger) *oauth.Registry {
	return hostedTestRegistryFor("google", p)
}

func hostedTestRegistryFor(provider string, p oauth.Exchanger) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register(provider, p)
	return reg
}

func TestHostedHTTP_StartHappyPath(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Query().Get("state") == "" {
		t.Fatal("provider redirect carried no state token")
	}
	if got := loc.Query().Get("redirect_uri"); !strings.HasSuffix(got, "/oauth/callback/google") {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestHostedHTTP_StartSetsCSRFCookie(t *testing.T) {
	for _, tt := range []struct {
		provider string
		sameSite http.SameSite
	}{
		{provider: "google", sameSite: http.SameSiteLaxMode},
		{provider: "apple", sameSite: http.SameSiteNoneMode},
	} {
		t.Run(tt.provider, func(t *testing.T) {
			h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistryFor(tt.provider, &appTestStubProvider{}))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
				"/oauth/start/"+tt.provider+"?return_to="+url.QueryEscape("https://app.test/finish"), nil))

			if rr.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", rr.Code)
			}
			cookies := rr.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookie count = %d, want 1", len(cookies))
			}
			cookie := cookies[0]
			if cookie.Name != hostedOAuthCSRFCookieName(tt.provider) || cookie.Path != "/" || cookie.Domain != "" ||
				!cookie.HttpOnly || !cookie.Secure || cookie.SameSite != tt.sameSite {
				t.Fatalf("csrf cookie = %#v", cookie)
			}
		})
	}
}

func TestHostedHTTP_StartRejectsReturnTo(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/start/google?return_to=https://evil.test/", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHostedHTTP_StartMissingProvider(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/start/?return_to=https://app.test/", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHostedHTTP_StartMethodNotAllowed(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/start/google", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestHostedHTTP_StartUnknownProviderBadRequest(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/start/github?return_to=https://app.test/", nil)
	h.ServeHTTP(rr, req)
	// github is not registered -> ErrInvalidArgument -> 400.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHostedHTTP_FullStartCallback(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))

	// Start to obtain a valid state token.
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil))
	loc, _ := url.Parse(startRR.Header().Get("Location"))
	stateToken := loc.Query().Get("state")

	// Callback with the state token + a code.
	cbRR := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth/callback/google?state="+url.QueryEscape(stateToken)+"&code=auth-xyz", nil)
	for _, c := range startRR.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	h.ServeHTTP(cbRR, cbReq)
	if cbRR.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body=%q", cbRR.Code, cbRR.Body.String())
	}
	redir := cbRR.Header().Get("Location")
	if !strings.HasPrefix(redir, "https://app.test/finish") {
		t.Fatalf("callback redirect = %q", redir)
	}
	cb, _ := url.Parse(redir)
	if cb.Query().Get("code") == "" {
		t.Fatal("callback redirect carried no one-time code")
	}
}

func TestHostedHTTP_ConcurrentStartsCompleteIndependently(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))

	firstStartRR := httptest.NewRecorder()
	h.ServeHTTP(firstStartRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil))
	firstLocation, _ := url.Parse(firstStartRR.Header().Get("Location"))
	firstState := firstLocation.Query().Get("state")
	firstCookie := firstStartRR.Result().Cookies()[0]

	secondStartRR := httptest.NewRecorder()
	secondStartReq := httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil)
	secondStartReq.AddCookie(firstCookie)
	h.ServeHTTP(secondStartRR, secondStartReq)
	secondLocation, _ := url.Parse(secondStartRR.Header().Get("Location"))
	secondState := secondLocation.Query().Get("state")
	secondCookie := secondStartRR.Result().Cookies()[0]
	if got := len(strings.Split(secondCookie.Value, ".")); got != 2 {
		t.Fatalf("csrf token count = %d, want 2", got)
	}

	firstCallbackRR := httptest.NewRecorder()
	firstCallbackReq := httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?state="+url.QueryEscape(firstState)+"&code=auth-first", nil)
	firstCallbackReq.AddCookie(secondCookie)
	h.ServeHTTP(firstCallbackRR, firstCallbackReq)
	if firstCallbackRR.Code != http.StatusFound {
		t.Fatalf("first callback status = %d, want 302; body=%q", firstCallbackRR.Code, firstCallbackRR.Body.String())
	}
	remainingCookie := firstCallbackRR.Result().Cookies()[0]
	if got := len(strings.Split(remainingCookie.Value, ".")); got != 1 {
		t.Fatalf("remaining csrf token count = %d, want 1", got)
	}

	secondCallbackRR := httptest.NewRecorder()
	secondCallbackReq := httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?state="+url.QueryEscape(secondState)+"&code=auth-second", nil)
	secondCallbackReq.AddCookie(remainingCookie)
	h.ServeHTTP(secondCallbackRR, secondCallbackReq)
	if secondCallbackRR.Code != http.StatusFound {
		t.Fatalf("second callback status = %d, want 302; body=%q", secondCallbackRR.Code, secondCallbackRR.Body.String())
	}
}

func TestHostedHTTP_FullStartCallback_FormPost(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))

	// Start to obtain a valid state token.
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil))
	loc, _ := url.Parse(startRR.Header().Get("Location"))
	stateToken := loc.Query().Get("state")

	// Callback with the state token + a code via POST form body.
	cbRR := httptest.NewRecorder()
	form := url.Values{}
	form.Set("state", stateToken)
	form.Set("code", "auth-xyz-form")
	req := httptest.NewRequest(http.MethodPost, "/oauth/callback/google", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range startRR.Result().Cookies() {
		req.AddCookie(c)
	}
	h.ServeHTTP(cbRR, req)

	if cbRR.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body=%q", cbRR.Code, cbRR.Body.String())
	}
	redir := cbRR.Header().Get("Location")
	if !strings.HasPrefix(redir, "https://app.test/finish") {
		t.Fatalf("callback redirect = %q", redir)
	}
	cb, _ := url.Parse(redir)
	if cb.Query().Get("code") == "" {
		t.Fatal("callback redirect carried no one-time code")
	}
}

// hostedCallback runs /start then the callback for provider google and
// returns the callback's response.
func hostedCallback(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish?step=2"), nil))
	loc, _ := url.Parse(startRR.Header().Get("Location"))
	cbReq := httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=auth-xyz", nil)
	for _, c := range startRR.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRR := httptest.NewRecorder()
	h.ServeHTTP(cbRR, cbReq)
	return cbRR
}

// A sign-in refused after the state token verified goes back to the app's
// return_to with error=<code> and no one-time code, and spends the flow's
// CSRF token as a completed one does.
func TestHostedHTTP_CallbackRefusalRedirectsWithErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		provider  *appTestStubProvider
		configure func(*config.Config)
		want      string
	}{
		{
			name:     "unverified address",
			provider: &appTestStubProvider{email: "app-hosted+tag@example.com"},
			configure: func(c *config.Config) {
				c.AuthRequireVerifiedEmail = true
			},
			want: service.HostedOAuthErrorEmailNotVerified,
		},
		{
			name:      "failed exchange",
			provider:  &appTestStubProvider{err: oauth.ErrCodeExchangeFailed},
			configure: func(*config.Config) {},
			want:      service.HostedOAuthErrorAccessDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostedTestHandlerWith(t, "https://app.test/", hostedTestRegistry(tc.provider), tc.configure)
			rr := hostedCallback(t, h)
			if rr.Code != http.StatusFound {
				t.Fatalf("callback status = %d, want 302; body=%q", rr.Code, rr.Body.String())
			}
			redir, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if redir.Scheme != "https" || redir.Host != "app.test" || redir.Path != "/finish" {
				t.Fatalf("callback redirect = %q", redir)
			}
			q := redir.Query()
			if got := q.Get("error"); got != tc.want {
				t.Fatalf("error = %q, want %q", got, tc.want)
			}
			if q.Get("code") != "" {
				t.Fatal("a refused callback carried a one-time code")
			}
			if q.Get("step") != "2" {
				t.Fatalf("return_to query lost: %q", redir)
			}
			cookies := rr.Result().Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
				t.Fatalf("csrf cookie not cleared: %#v", cookies)
			}
		})
	}
}

func TestHostedHTTP_CallbackRejectsInvalidCSRFCookie(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to="+url.QueryEscape("https://app.test/finish"), nil))
	loc, _ := url.Parse(startRR.Header().Get("Location"))
	stateToken := loc.Query().Get("state")

	for _, tt := range []struct {
		name       string
		addCookies func(*http.Request)
	}{
		{name: "missing"},
		{name: "mismatched", addCookies: func(req *http.Request) {
			req.AddCookie(&http.Cookie{
				Name:     hostedOAuthCSRFCookieName("google"),
				Value:    "wrong",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}},
		{name: "duplicate", addCookies: func(req *http.Request) {
			req.AddCookie(&http.Cookie{
				Name:     hostedOAuthCSRFCookieName("google"),
				Value:    "first",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			req.AddCookie(&http.Cookie{
				Name:     hostedOAuthCSRFCookieName("google"),
				Value:    "second",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet,
				"/oauth/callback/google?state="+url.QueryEscape(stateToken)+"&code=auth-xyz", nil)
			if tt.addCookies != nil {
				tt.addCookies(req)
			}
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
		})
	}
}

func TestHostedHTTP_CallbackProviderError(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?error=access_denied", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHostedHTTP_CallbackBadState(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?state=not-a-real-token&code=xyz", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHostedHTTP_CallbackMethodNotAllowed(t *testing.T) {
	h := newHostedTestHandler(t, "https://app.test/", hostedTestRegistry(&appTestStubProvider{}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/oauth/callback/google", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestHostedHTTP_DisabledRoutes404(t *testing.T) {
	h := newHostedTestHandler(t, "", hostedTestRegistry(&appTestStubProvider{}))
	for _, p := range []string{"/oauth/start/google?return_to=https://app.test/", "/oauth/callback/google?state=x&code=y"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", p, rr.Code)
		}
	}
}

func TestHostedHTTP_StartOAuthDisabledServiceUnavailable(t *testing.T) {
	// Hosted routes registered (allowlist set) but no providers
	// configured -> BeginHostedOAuth returns ErrOAuthDisabled -> 503.
	h := newHostedTestHandler(t, "https://app.test/", oauth.NewRegistry())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/oauth/start/google?return_to=https://app.test/", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rr.Code, rr.Body.String())
	}
}

func TestIsOAuthDisabled(t *testing.T) {
	if !isOAuthDisabled(service.ErrOAuthDisabled) {
		t.Error("isOAuthDisabled(ErrOAuthDisabled) = false")
	}
	if isOAuthDisabled(nil) {
		t.Error("isOAuthDisabled(nil) = true")
	}
	if isOAuthDisabled(errOther) {
		t.Error("isOAuthDisabled(other) = true")
	}
}

var errOther = otherError("some other error")

type otherError string

func (e otherError) Error() string { return string(e) }

func TestPathProvider(t *testing.T) {
	tests := []struct {
		path, prefix, want string
	}{
		{"/oauth/start/google", "/oauth/start/", "google"},
		{"/oauth/start/GOOGLE", "/oauth/start/", "google"},
		{"/oauth/start/", "/oauth/start/", ""},
		{"/oauth/start/google/extra", "/oauth/start/", ""},
		{"/oauth/callback/microsoft", "/oauth/callback/", "microsoft"},
	}
	for _, tt := range tests {
		if got := pathProvider(tt.path, tt.prefix); got != tt.want {
			t.Errorf("pathProvider(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestAppendQueryParam(t *testing.T) {
	tests := []struct {
		base, key, value, wantContains string
	}{
		{"https://app.test/finish", "code", "abc", "code=abc"},
		{"https://app.test/finish?next=/home", "code", "abc", "next=%2Fhome"},
		{"https://app.test/finish?next=/home", "code", "abc", "code=abc"},
		{"://bad url", "code", "abc", "code=abc"},
	}
	for _, tt := range tests {
		got := appendQueryParam(tt.base, tt.key, tt.value)
		if !strings.Contains(got, tt.wantContains) {
			t.Errorf("appendQueryParam(%q) = %q, want substring %q", tt.base, got, tt.wantContains)
		}
	}
}

func TestCallbackURL(t *testing.T) {
	hh := &hostedOAuthHandler{}

	// Plain HTTP request.
	r := httptest.NewRequest(http.MethodGet, "/oauth/start/google", nil)
	r.Host = "id.test"
	if got := hh.callbackURL(r, "google"); got != "http://id.test/oauth/callback/google" {
		t.Errorf("callbackURL = %q", got)
	}

	// Forwarded headers from a trusted proxy take precedence.
	r2 := httptest.NewRequest(http.MethodGet, "/oauth/start/google", nil)
	r2.Host = "internal:8080"
	r2.Header.Set("X-Forwarded-Proto", "https")
	r2.Header.Set("X-Forwarded-Host", "id.example.com")
	if got := hh.callbackURL(r2, "google"); got != "https://id.example.com/oauth/callback/google" {
		t.Errorf("callbackURL forwarded = %q", got)
	}
}

func TestClientIPFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:5555"
	if got := clientIPFromRequest(r); got != "203.0.113.5" {
		t.Errorf("RemoteAddr IP = %q", got)
	}

	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := clientIPFromRequest(r); got != "198.51.100.7" {
		t.Errorf("XFF IP = %q", got)
	}
}
