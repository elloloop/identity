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
	err error
}

func (p *appTestStubProvider) AuthorizationURL(_ context.Context, redirectURI, state, _ string) (string, error) {
	u, _ := url.Parse("https://provider.test/authorize")
	q := u.Query()
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *appTestStubProvider) Exchange(_ context.Context, _, _ string) (*oauth.Identity, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &oauth.Identity{
		Provider:       "google",
		ProviderUserID: "app-hosted-user",
		Email:          "app-hosted@example.com",
		EmailVerified:  true,
		Name:           "App Hosted",
	}, nil
}

func newHostedTestHandler(t *testing.T, allowlist string, reg *oauth.Registry) http.Handler {
	t.Helper()
	signer := jwttest.NewSigner(t, "hosted-app-test")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: "localhost", RPName: "Test", Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	handler, stop, err := New(Deps{
		Config: &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
			DefaultTenantID:        "tenant",
			IdentityMode:           config.IdentityModeSingle,
			AuthAllowLocal:         true,
			AllowedOrigins:         "http://localhost:9002",
			JWTExpirySeconds:       900,
			RefreshExpirySeconds:   604800,
			LoginMaxFailedAttempts: 5,
			LoginLockoutSeconds:    900,
			PasskeyRPID:            "localhost",
			PasskeyRPName:          "Test",
			PasskeyOrigin:          "http://localhost:9002",
			OAuthAllowedReturnURLs: allowlist,
		},
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
	t.Cleanup(stop)
	return handler
}

func hostedTestRegistry(p oauth.Exchanger) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register("google", p)
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
	h.ServeHTTP(cbRR, httptest.NewRequest(http.MethodGet,
		"/oauth/callback/google?state="+url.QueryEscape(stateToken)+"&code=auth-xyz", nil))
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
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/oauth/callback/google", nil))
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
