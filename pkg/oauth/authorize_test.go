package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityjwt "github.com/elloloop/identity/pkg/jwt"
)

func newOAuthStateKeyRing(t *testing.T) *identityjwt.KeyRing {
	t.Helper()
	key, err := identityjwt.GenerateKey("oauth-state-test")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key.Active = true
	ring, err := identityjwt.NewKeyRing([]identityjwt.SigningKey{key})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	return ring
}

func TestStateToken_RoundTripAndMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 15, 0, 0, 0, time.UTC)
	ring := newOAuthStateKeyRing(t)

	token, err := IssueStateToken(
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
