package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenRequest is what a GitHub token endpoint was asked by one exchange.
type tokenRequest struct{ clientID, clientSecret, redirectURI string }

// startRecordingGitHubMock is startGitHubMock that also records each token
// request, so a test can tell which client completed a sign-in.
func startRecordingGitHubMock(t *testing.T) (*httptest.Server, func() []tokenRequest) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []tokenRequest
	)
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		seen = append(seen, tokenRequest{r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), r.PostForm.Get("redirect_uri")})
		mu.Unlock()
		writeJSON(w, map[string]any{"access_token": "gho_host", "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"id": 4343, "login": "octohost", "name": "Octo Host"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, []map[string]any{{"email": "octo.host@example.com", "primary": true, "verified": true}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() []tokenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]tokenRequest(nil), seen...)
	}
}

// A hosted sign-in whose callback is on a host with its own client starts and
// completes through that client, from the redirect URI the state token carries;
// the same project on another host starts and completes through its base.
func TestHostedOAuth_HostClient_StartAndCallbackUseTheSameClient(t *testing.T) {
	svc := perProjectOAuthService(t, newFakeRepo(), "env-google")
	srv, tokenRequests := startRecordingGitHubMock(t)
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "gh-proj",
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		OAuth: ProjectOAuthConfig{
			GitHub: &ProjectOAuthGitHub{
				ClientID:        "base-github",
				ClientSecretEnc: encForProject(t, "base-secret"),
				TokenURL:        srv.URL + "/login/oauth/access_token",
				UserURL:         srv.URL + "/user",
				UserMailURL:     srv.URL + "/user/emails",
			},
			Hosts: map[string]map[string]ProjectOAuthHostClient{
				hostB: {oauthProviderGitHub: {ClientID: "host-b-github", ClientSecretEnc: encForProject(t, "host-b-secret")}},
			},
		},
	})

	for _, tc := range []struct{ callback, clientID, secret string }{
		{"https://auth.b.example/oauth/callback/github", "host-b-github", "host-b-secret"},
		{"https://auth.a.example/oauth/callback/github", "base-github", "base-secret"},
	} {
		begin, err := svc.BeginHostedOAuth(ctx, oauthProviderGitHub, tc.callback, "https://app.test/finish", "csrf-123", "", "")
		require.NoError(t, err, tc.callback)
		assert.Contains(t, begin.AuthorizationURL, "client_id="+tc.clientID, tc.callback)

		cb, err := svc.CompleteHostedOAuth(ctx, oauthProviderGitHub, "code-from-github",
			stateTokenFromAuthURL(t, begin.AuthorizationURL), "", "1.2.3.4", "test-agent", []string{"csrf-123"})
		require.NoError(t, err, tc.callback)
		require.NotEmpty(t, cb.Code)

		seen := tokenRequests()
		require.NotEmpty(t, seen)
		assert.Equal(t, tokenRequest{tc.clientID, tc.secret, tc.callback}, seen[len(seen)-1],
			"the callback must exchange the code with the client the start used")
	}
}

// The headless flow keys the host client on the app's own redirect URI.
func TestOAuthLogin_HostClient_HeadlessRedirectURI(t *testing.T) {
	svc := perProjectOAuthService(t, newFakeRepo(), "env-google")
	svc.oauthResolver.envProvider = envGoogleBuilder
	ctx := hostClientScope("default", ProjectOAuthConfig{}, encForProject(t, "host-secret"))

	onB, err := svc.BeginOAuthLogin(ctx, oauthProviderGoogle, "https://auth.b.example/app/callback")
	require.NoError(t, err)
	assert.Contains(t, onB.AuthorizationURL, "client_id="+hostBGoogle)

	onApp, err := svc.BeginOAuthLogin(ctx, oauthProviderGoogle, "https://app.example/callback")
	require.NoError(t, err)
	assert.Contains(t, onApp.AuthorizationURL, "client_id=env-google")
}

// The hosted page starts a provider with a client for the page's own host on
// that host, needing no project key; every other provider starts where its
// base client is registered, as before.
func TestHostedUIOptions_HostClientStartsOnThePageHost(t *testing.T) {
	svc := hubSharingService(t, newFakeRepo(), true)
	svc.cfg.DefaultProjectAuthDomains = "auth.hub.test"
	scope := &ProjectScope{
		ProjectID:         "proj-own",
		PrimaryAuthDomain: hostA,
		OAuth: ProjectOAuthConfig{
			Google: &ProjectOAuthGoogle{ClientID: "own-google"},
			Hosts: map[string]map[string]ProjectOAuthHostClient{
				hostB: {
					oauthProviderGoogle:    {ClientID: "b-google", ClientSecretEnc: "enc"},
					oauthProviderMicrosoft: {ClientID: "b-microsoft", ClientSecretEnc: "enc"},
				},
			},
		},
	}
	ctx := WithProjectScope(context.Background(), scope)
	starts := func(pageOrigin string) map[string]HostedUIProvider {
		byKey := map[string]HostedUIProvider{}
		for _, p := range svc.HostedUIOptions(ctx, pageOrigin).OAuthProviders {
			byKey[p.Key] = p
		}
		return byKey
	}

	onB := starts("https://auth.b.example")
	assert.Equal(t, HostedUIProvider{Key: "google"}, onB["google"], "own provider with a host client starts on the page host")
	assert.Equal(t, HostedUIProvider{Key: "microsoft"}, onB["microsoft"], "borrowed provider with a host client starts on the page host, no key")
	assert.Equal(t, HostedUIProvider{Key: "github", StartOrigin: "https://auth.hub.test", NeedsProjectKey: true}, onB["github"],
		"a provider without a host client still starts on the hub")

	onA := starts("https://auth.a.example")
	assert.Equal(t, HostedUIProvider{Key: "google", StartOrigin: "https://auth.a.example"}, onA["google"])
	assert.Equal(t, HostedUIProvider{Key: "microsoft", StartOrigin: "https://auth.hub.test", NeedsProjectKey: true}, onA["microsoft"])

	// Only a provider the precedence already offers is listed: a host client
	// adds none.
	strict := hubSharingService(t, newFakeRepo(), false)
	assert.Equal(t, []string{"google"}, providerKeys(strict.HostedUIOptions(ctx, "https://auth.b.example").OAuthProviders),
		"without hub sharing microsoft has no base, and its host client must not list it")
}
