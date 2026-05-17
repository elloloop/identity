package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityjwt "github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

func newOAuthStateSigner(t *testing.T) *jwttest.Signer {
	t.Helper()
	return jwttest.NewSigner(t, "oauth-state-test")
}

func newOAuthStateSignerWithKID(t *testing.T, kid string) *jwttest.Signer {
	t.Helper()
	return jwttest.NewSigner(t, kid)
}

func TestCodeVerifierContext(t *testing.T) {
	t.Parallel()

	var nilContext context.Context
	if got := codeVerifierFromContext(nilContext); got != "" {
		t.Fatalf("nil context verifier = %q", got)
	}
	if got := codeVerifierFromContext(WithCodeVerifier(context.Background(), "   ")); got != "" {
		t.Fatalf("blank verifier = %q", got)
	}
	if got := codeVerifierFromContext(WithCodeVerifier(context.Background(), " verifier-123 ")); got != "verifier-123" {
		t.Fatalf("verifier = %q", got)
	}
}

func TestStateToken_RoundTripAndMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 15, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)
	ctx := context.Background()

	token, err := IssueStateToken(
		ctx,
		ring,
		"google",
		"https://app.example.com/oauth/callback",
		"state-123",
		"verifier-123",
		5*time.Minute,
		now,
	)
	if err != nil {
		t.Fatalf("IssueStateToken: %v", err)
	}

	claims, err := VerifyStateToken(
		token,
		ring,
		"google",
		"https://app.example.com/oauth/callback",
		"state-123",
		"verifier-123",
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("VerifyStateToken: %v", err)
	}
	if claims.CodeVerifier != "verifier-123" {
		t.Fatalf("code verifier = %q, want verifier-123", claims.CodeVerifier)
	}

	if _, err := VerifyStateToken(
		token,
		ring,
		"google",
		"https://app.example.com/oauth/callback",
		"wrong-state",
		"verifier-123",
		now.Add(time.Minute),
	); err == nil {
		t.Fatal("VerifyStateToken should reject callback state mismatch")
	}
}

func TestStateToken_ValidationFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 15, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)
	ctx := context.Background()

	if _, err := IssueStateToken(ctx, nil, "google", "https://app.example.com/oauth/callback", "state-123", "verifier-123", 5*time.Minute, now); !errors.Is(err, ErrStateValidation) {
		t.Fatalf("nil signer error = %v", err)
	}

	required := []struct {
		name         string
		provider     string
		redirectURI  string
		state        string
		codeVerifier string
	}{
		{"provider", "", "https://app.example.com/oauth/callback", "state-123", "verifier-123"},
		{"redirect", "google", "", "state-123", "verifier-123"},
		{"state", "google", "https://app.example.com/oauth/callback", "", "verifier-123"},
		{"verifier", "google", "https://app.example.com/oauth/callback", "state-123", ""},
	}
	for _, tc := range required {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := IssueStateToken(ctx, ring, tc.provider, tc.redirectURI, tc.state, tc.codeVerifier, 5*time.Minute, now); !errors.Is(err, ErrStateValidation) {
				t.Fatalf("IssueStateToken error = %v", err)
			}
		})
	}

	token, err := IssueStateToken(
		ctx,
		ring,
		"google",
		"https://app.example.com/oauth/callback",
		"state-123",
		"verifier-123",
		5*time.Minute,
		now,
	)
	if err != nil {
		t.Fatalf("IssueStateToken: %v", err)
	}

	verifyCases := []struct {
		name        string
		ring        identityjwt.KeyProvider
		token       string
		provider    string
		redirectURI string
		state       string
		verifier    string
		now         time.Time
	}{
		{"nil ring", nil, token, "google", "https://app.example.com/oauth/callback", "state-123", "verifier-123", now.Add(time.Minute)},
		{"bad token", ring, "not-a-jws", "google", "https://app.example.com/oauth/callback", "state-123", "verifier-123", now.Add(time.Minute)},
		{"unknown kid", newOAuthStateSignerWithKID(t, "oauth-state-other"), token, "google", "https://app.example.com/oauth/callback", "state-123", "verifier-123", now.Add(time.Minute)},
		{"expired", ring, token, "google", "https://app.example.com/oauth/callback", "state-123", "verifier-123", now.Add(6 * time.Minute)},
		{"provider mismatch", ring, token, "github", "https://app.example.com/oauth/callback", "state-123", "verifier-123", now.Add(time.Minute)},
		{"redirect mismatch", ring, token, "google", "https://app.example.com/other", "state-123", "verifier-123", now.Add(time.Minute)},
		{"state mismatch", ring, token, "google", "https://app.example.com/oauth/callback", "state-456", "verifier-123", now.Add(time.Minute)},
		{"verifier mismatch", ring, token, "google", "https://app.example.com/oauth/callback", "state-123", "verifier-456", now.Add(time.Minute)},
	}
	for _, tc := range verifyCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyStateToken(tc.token, tc.ring, tc.provider, tc.redirectURI, tc.state, tc.verifier, tc.now); !errors.Is(err, ErrStateValidation) {
				t.Fatalf("VerifyStateToken error = %v", err)
			}
		})
	}

	futureToken, err := IssueStateToken(
		ctx,
		ring,
		"google",
		"https://app.example.com/oauth/callback",
		"state-123",
		"verifier-123",
		5*time.Minute,
		now.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("IssueStateToken future: %v", err)
	}
	if _, err := VerifyStateToken(futureToken, ring, "google", "https://app.example.com/oauth/callback", "state-123", "verifier-123", now); !errors.Is(err, ErrStateValidation) {
		t.Fatalf("future iat error = %v", err)
	}
}

func TestOIDCDiscovery(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("path = %q", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
			http.Error(w, "wrong accept", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{ // #nosec G101 -- OAuth endpoint fields are not credentials.
			Issuer:           "https://accounts.example.com",
			TokenEndpoint:    "https://accounts.example.com/token",
			UserinfoEndpoint: "https://accounts.example.com/userinfo",
			JWKSURI:          "https://accounts.example.com/jwks",
		})
	}))
	t.Cleanup(srv.Close)

	doc, err := fetchOIDCDiscovery(context.Background(), srv.Client(), srv.URL+"/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("fetchOIDCDiscovery: %v", err)
	}
	if doc.TokenEndpoint != "https://accounts.example.com/token" {
		t.Fatalf("token endpoint = %q", doc.TokenEndpoint)
	}
	if doc.JWKSURI != "https://accounts.example.com/jwks" {
		t.Fatalf("jwks uri = %q", doc.JWKSURI)
	}
}

func TestOIDCDiscoveryFailures(t *testing.T) {
	t.Parallel()

	if _, err := fetchOIDCDiscovery(context.Background(), http.DefaultClient, " "); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("blank discovery URL error = %v", err)
	}

	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"http status", http.StatusInternalServerError, `{}`},
		{"bad json", http.StatusOK, `not json`},
		{"missing token", http.StatusOK, `{"jwks_uri":"https://accounts.example.com/jwks"}`},
		{"missing jwks", http.StatusOK, `{"token_endpoint":"https://accounts.example.com/token"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			if _, err := fetchOIDCDiscovery(context.Background(), srv.Client(), srv.URL); !errors.Is(err, ErrCodeExchangeFailed) {
				t.Fatalf("fetchOIDCDiscovery error = %v", err)
			}
		})
	}
}

func TestOIDCUserInfo(t *testing.T) {
	t.Parallel()

	if info, err := fetchOIDCUserInfo(context.Background(), http.DefaultClient, "", "access-token"); err != nil || info != nil {
		t.Fatalf("blank URL info=%v err=%v", info, err)
	}
	if info, err := fetchOIDCUserInfo(context.Background(), http.DefaultClient, "https://accounts.example.com/userinfo", " "); err != nil || info != nil {
		t.Fatalf("blank token info=%v err=%v", info, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Errorf("Authorization = %q", got)
			http.Error(w, "wrong authorization", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
			http.Error(w, "wrong accept", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":                "subject-123",
			"email":              "user@example.com",
			"email_verified":     true,
			"name":               "OAuth User",
			"picture":            "https://accounts.example.com/avatar.png",
			"preferred_username": "oauth-user",
		})
	}))
	t.Cleanup(srv.Close)

	info, err := fetchOIDCUserInfo(context.Background(), srv.Client(), srv.URL, "access-token")
	if err != nil {
		t.Fatalf("fetchOIDCUserInfo: %v", err)
	}
	if info.Sub != "subject-123" {
		t.Fatalf("sub = %q", info.Sub)
	}
	if info.EmailVerified == nil || !*info.EmailVerified {
		t.Fatalf("email_verified = %v", info.EmailVerified)
	}
	if info.PreferredUsername != "oauth-user" {
		t.Fatalf("preferred username = %q", info.PreferredUsername)
	}
}

func TestOIDCUserInfoFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"http status", http.StatusForbidden, `{}`},
		{"bad json", http.StatusOK, `not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			if _, err := fetchOIDCUserInfo(context.Background(), srv.Client(), srv.URL, "access-token"); !errors.Is(err, ErrIdentityVerification) {
				t.Fatalf("fetchOIDCUserInfo error = %v", err)
			}
		})
	}
}

func TestGoogle_AuthorizationURL_UsesDiscoveryDocument(t *testing.T) {
	t.Parallel()

	const authPath = "/authorize"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": srv.URL + authPath,
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)

	exchanger := NewGoogle(GoogleConfig{
		ClientID:     "google-client",
		ClientSecret: "google-secret",
		DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
		HTTPClient:   srv.Client(),
	}).(*googleExchanger)

	got, err := exchanger.AuthorizationURL(
		context.Background(),
		"https://app.example.com/oauth/callback",
		"state-google",
		"challenge-google",
	)
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsed.Path != authPath {
		t.Fatalf("path = %q, want %q", parsed.Path, authPath)
	}
	if parsed.Query().Get("code_challenge") != "challenge-google" {
		t.Fatalf("code_challenge = %q", parsed.Query().Get("code_challenge"))
	}
}

func TestMicrosoft_AuthorizationURL_UsesTenant(t *testing.T) {
	t.Parallel()

	exchanger := NewMicrosoft(MicrosoftConfig{
		ClientID:     "ms-client",
		ClientSecret: "ms-secret",
		TenantID:     "tenant-123",
	}).(*microsoftExchanger)

	got, err := exchanger.AuthorizationURL(
		context.Background(),
		"https://app.example.com/oauth/callback",
		"state-ms",
		"challenge-ms",
	)
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	if !strings.Contains(got, "/tenant-123/oauth2/v2.0/authorize") {
		t.Fatalf("AuthorizationURL = %q, want tenant-specific authorize path", got)
	}
}

func TestGitHub_AuthorizationURL_IncludesPKCE(t *testing.T) {
	t.Parallel()

	exchanger := NewGitHub(GitHubConfig{
		ClientID:     "gh-client",
		ClientSecret: "gh-secret",
	}).(*githubExchanger)

	got, err := exchanger.AuthorizationURL(
		context.Background(),
		"https://app.example.com/oauth/callback",
		"state-gh",
		"challenge-gh",
	)
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsed.Query().Get("state") != "state-gh" {
		t.Fatalf("state = %q", parsed.Query().Get("state"))
	}
	if parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q", parsed.Query().Get("code_challenge_method"))
	}
}
