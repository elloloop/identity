package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passkeys"
)

// perProjectOAuthService builds a service whose default project is
// "default" and whose env registry serves a single Google provider with the
// given client id, with per-project secret decryption wired.
func perProjectOAuthService(t *testing.T, repo *fakeRepo, envGoogleClientID string) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.DefaultProjectID = "default"
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, testKeyRing(t), passkeysSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
		envGoogleRegistry(envGoogleClientID),
	).WithProjectOAuthSecrets(resolverSecretsKey(), nil)
}

func TestBeginOAuthLogin_PerProjectIsolation(t *testing.T) {
	svc := perProjectOAuthService(t, newFakeRepo(), "env-google")

	// Default project → env provider.
	defRes, err := svc.BeginOAuthLogin(
		WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default"}),
		"google", "https://app/cb",
	)
	if err != nil {
		t.Fatalf("default project BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(defRes.AuthorizationURL, "client_id=env-google") {
		t.Errorf("default project must use env client_id, got %q", defRes.AuthorizationURL)
	}

	// A second project with its OWN google client_id → that client_id.
	projRes, err := svc.BeginOAuthLogin(projectGoogleScope(t, "proj-2", "proj2-google"), "google", "https://app/cb")
	if err != nil {
		t.Fatalf("project BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(projRes.AuthorizationURL, "client_id=proj2-google") {
		t.Errorf("second project must use its own client_id, got %q", projRes.AuthorizationURL)
	}

	// A non-default project without a google config cannot use google.
	_, err = svc.BeginOAuthLogin(
		WithProjectScope(context.Background(), &ProjectScope{ProjectID: "proj-3"}),
		"google", "https://app/cb",
	)
	if !errors.Is(err, ErrOAuthDisabled) {
		t.Errorf("non-default project without google must be disabled, got %v", err)
	}
}

// startGitHubMock stands up an httptest server emulating the three GitHub REST
// endpoints the exchanger drives (token, /user, /user/emails), so a per-project
// GitHub login can be driven end-to-end without touching github.com.
func startGitHubMock(t *testing.T) *httptest.Server {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "gho_project", "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"id": 4242, "login": "octoproj", "name": "Octo Proj", "email": "public@gh.example"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, []map[string]any{{"email": "octo.primary@example.com", "primary": true, "verified": true}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestOAuthLogin_PerProjectGitHub_EndToEnd proves a project's own config_json
// GitHub provider drives the full hosted login: BeginOAuthLogin carries the
// project's client id, and OAuthLogin exchanges a code against the project's
// (mock) GitHub endpoints, reads the verified primary email, and provisions the
// user with tokens. A non-default project without a GitHub block cannot use it.
func TestOAuthLogin_PerProjectGitHub_EndToEnd(t *testing.T) {
	svc := perProjectOAuthService(t, newFakeRepo(), "env-google")
	srv := startGitHubMock(t)

	scope := &ProjectScope{
		ProjectID: "gh-proj",
		// Open access: this test exercises per-project GitHub OAuth, not the
		// access gate, which under default-DENY must be opened explicitly.
		Access: ProjectAccessConfig{Mode: AccessModeOpen},
		OAuth: ProjectOAuthConfig{GitHub: &ProjectOAuthGitHub{
			ClientID:        "proj-github",
			ClientSecretEnc: encForProject(t, "gh-secret"),
			TokenURL:        srv.URL + "/login/oauth/access_token",
			UserURL:         srv.URL + "/user",
			UserMailURL:     srv.URL + "/user/emails",
		}},
	}
	ctx := WithProjectScope(context.Background(), scope)

	begin, err := svc.BeginOAuthLogin(ctx, "github", "https://app/cb")
	if err != nil {
		t.Fatalf("BeginOAuthLogin github: %v", err)
	}
	if !strings.Contains(begin.AuthorizationURL, "client_id=proj-github") {
		t.Errorf("github begin must use the project client_id, got %q", begin.AuthorizationURL)
	}

	res, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code:        "code-from-github",
		Provider:    "github",
		RedirectURI: "https://app/cb",
		IPAddr:      "1.2.3.4",
		UserAgent:   "test-agent",
	})
	if err != nil {
		t.Fatalf("OAuthLogin github: %v", err)
	}
	if res.User == nil || res.User.Email != "octo.primary@example.com" {
		t.Fatalf("user = %+v, want verified primary email", res.User)
	}
	if !res.User.EmailVerified {
		t.Error("github-provisioned user must be email-verified")
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("OAuthLogin github returned empty tokens")
	}

	// A non-default project without a github block cannot begin github login.
	if _, err := svc.BeginOAuthLogin(
		WithProjectScope(context.Background(), &ProjectScope{ProjectID: "no-gh"}),
		"github", "https://app/cb",
	); !errors.Is(err, ErrOAuthDisabled) {
		t.Errorf("non-default project without github must be disabled, got %v", err)
	}
}
