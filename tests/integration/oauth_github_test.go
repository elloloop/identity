//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/pkg/oauth"
)

// githubMockServer is an httptest.Server that emulates the GitHub
// REST surface the real oauth.NewGitHub exchanger drives: the token
// endpoint, GET /user, and GET /user/emails. GitHub is NOT OIDC, so we
// cannot reuse the OIDC discovery/JWKS mock — these are plain REST
// responses. Each handler is overridable per-test so the three GitHub
// login paths (verified-primary, profile-email fallback, rejection)
// can be exercised against the real provider code.
//
// The endpoints are injected into the provider via the URL-override
// fields on oauth.GitHubConfig (TokenURL/UserURL/UserMailURL) — the
// same override mechanism pkg/oauth/github_test.go uses to point the
// provider at its fake server.
type githubMockServer struct {
	srv *httptest.Server

	tokenHandler http.HandlerFunc
	userHandler  http.HandlerFunc
	emailHandler http.HandlerFunc
}

// newGithubMockServer wires a mux with the three GitHub REST routes and
// registers it for cleanup. Tests assign the *Handler fields before the
// first OAuthLogin call.
func newGithubMockServer(t *testing.T) *githubMockServer {
	t.Helper()
	m := &githubMockServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if m.tokenHandler != nil {
			m.tokenHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if m.userHandler != nil {
			m.userHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if m.emailHandler != nil {
			m.emailHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *githubMockServer) url(path string) string { return m.srv.URL + path }

// githubConfig returns a GitHubConfig whose endpoint URLs point at the
// mock server, so the real exchanger talks to us instead of github.com.
func (m *githubMockServer) githubConfig() oauth.GitHubConfig {
	return oauth.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TokenURL:     m.url("/login/oauth/access_token"),
		UserURL:      m.url("/user"),
		UserMailURL:  m.url("/user/emails"),
	}
}

// githubJSONHandler responds 200 with the given value JSON-encoded.
func githubJSONHandler(body any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

// githubRegistry builds a one-provider registry wired to the mock
// server's real GitHub exchanger, ready for WithOAuthRegistry.
func githubRegistry(m *githubMockServer) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register("github", oauth.NewGitHub(m.githubConfig()))
	return reg
}

// TestOAuthLogin_GitHub_VerifiedPrimaryEmail drives the full Connect
// path against the real GitHub provider and the mock REST server:
// BeginOAuthLogin yields an authorization URL, then OAuthLogin exchanges
// a code, the provider reads a verified primary email from /user/emails,
// and the service auto-provisions the user (verified) and mints tokens
// that GetCurrentUser accepts.
func TestOAuthLogin_GitHub_VerifiedPrimaryEmail(t *testing.T) {
	t.Parallel()

	m := newGithubMockServer(t)
	m.tokenHandler = githubJSONHandler(map[string]any{
		"access_token": "gho_verified",
		"token_type":   "bearer",
		"scope":        "read:user,user:email",
	})
	m.userHandler = githubJSONHandler(map[string]any{
		"id":         424242,
		"login":      "octoverified",
		"name":       "Octo Verified",
		"avatar_url": "https://gh/avatar/verified.png",
		// Public profile email differs from the primary; the primary
		// verified address from /user/emails must win.
		"email": "public@github.example",
	})
	m.emailHandler = githubJSONHandler([]map[string]any{
		{"email": "secondary@example.com", "primary": false, "verified": true},
		{"email": "octo.primary@example.com", "primary": true, "verified": true},
		{"email": "unverified@example.com", "primary": false, "verified": false},
	})

	h := StartServer(t, WithOAuthRegistry(githubRegistry(m)))
	ctx := context.Background()

	// BeginOAuthLogin should produce an authorization URL for github.
	begin, err := h.Client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "github",
		RedirectUri: "https://app/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	if begin.Msg.GetAuthorizationUrl() == "" {
		t.Fatal("BeginOAuthLogin returned empty authorization_url")
	}

	resp, err := h.Client.OAuthLogin(ctx, connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "code-from-github",
		Provider:    "github",
		RedirectUri: "https://app/callback",
	}))
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("OAuthLogin returned empty access_token")
	}
	if resp.Msg.RefreshToken == "" {
		t.Fatal("OAuthLogin returned empty refresh_token")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "octo.primary@example.com" {
		t.Errorf("user email = %q, want octo.primary@example.com", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Error("user email_verified should be true")
	}

	// The minted access token should authenticate GetCurrentUser.
	authed := h.AuthedClient(resp.Msg.AccessToken)
	cur, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "octo.primary@example.com" {
		t.Errorf("GetCurrentUser email = %q", got)
	}
}

// TestOAuthLogin_GitHub_PrimaryUnverifiedFallsBackToProfileEmail mirrors
// pkg/oauth's FallsBackToProfileEmail through the full RPC stack: when
// /user/emails is unavailable (e.g. user:email scope missing → 403), the
// provider degrades to the verified public profile email, and the user is
// provisioned with that address.
func TestOAuthLogin_GitHub_PrimaryUnverifiedFallsBackToProfileEmail(t *testing.T) {
	t.Parallel()

	m := newGithubMockServer(t)
	m.tokenHandler = githubJSONHandler(map[string]any{
		"access_token": "gho_fallback",
	})
	m.userHandler = githubJSONHandler(map[string]any{
		"id":    13,
		"login": "fallbackuser",
		"email": "profile.fallback@example.com",
	})
	m.emailHandler = func(w http.ResponseWriter, _ *http.Request) {
		// No verified primary available via the emails API.
		w.WriteHeader(http.StatusForbidden)
	}

	h := StartServer(t, WithOAuthRegistry(githubRegistry(m)))
	ctx := context.Background()

	resp, err := h.Client.OAuthLogin(ctx, connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "code-fallback",
		Provider:    "github",
		RedirectUri: "https://app/callback",
	}))
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "profile.fallback@example.com" {
		t.Errorf("user email = %q, want profile.fallback@example.com", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Error("user email_verified should be true")
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("OAuthLogin returned empty access_token")
	}
}

// TestOAuthLogin_GitHub_NoVerifiedEmailRejected mirrors pkg/oauth's
// NoVerifiedEmailRejected through the RPC stack: with no verified email
// anywhere (unverified primary, no profile email), the provider returns
// ErrEmailNotVerified, which the service maps to Unauthenticated.
func TestOAuthLogin_GitHub_NoVerifiedEmailRejected(t *testing.T) {
	t.Parallel()

	m := newGithubMockServer(t)
	m.tokenHandler = githubJSONHandler(map[string]any{
		"access_token": "gho_noemail",
	})
	m.userHandler = githubJSONHandler(map[string]any{
		"id":    99,
		"login": "ghostuser",
		// No public profile email set.
	})
	m.emailHandler = githubJSONHandler([]map[string]any{
		{"email": "ghost@example.com", "primary": true, "verified": false},
	})

	h := StartServer(t, WithOAuthRegistry(githubRegistry(m)))

	_, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "code-noemail",
		Provider:    "github",
		RedirectUri: "https://app/callback",
	}))
	if err == nil {
		t.Fatal("expected error when no verified email is available")
	}
	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want Unauthenticated", connErr.Code())
	}
}
