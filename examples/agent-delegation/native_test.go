package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCallbackRequiresExactStateIssuerAndOneCode(t *testing.T) {
	for _, query := range []string{"state=wrong&iss=https://auth.example.test&code=abc", "state=expected&iss=https://other.example.test&code=abc", "state=expected&iss=https://auth.example.test&code=abc&code=second", "state=expected&state=expected&iss=https://auth.example.test&code=abc", "state=expected&iss=https://auth.example.test"} {
		result := make(chan string, 1)
		rec := httptest.NewRecorder()
		callbackHandler("expected", "https://auth.example.test", result).ServeHTTP(rec, httptest.NewRequest("GET", "http://127.0.0.1/callback?"+query, nil))
		require.Equal(t, 400, rec.Code)
		require.Empty(t, result)
	}
	result := make(chan string, 1)
	handler := callbackHandler("expected", "https://auth.example.test", result)
	for i, want := range []int{200, 409} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "http://127.0.0.1/callback?state=expected&iss=https://auth.example.test&code=abc", nil))
		require.Equal(t, want, rec.Code)
		if i == 0 {
			require.Equal(t, "abc", <-result)
		}
	}
}

func TestNativeConfigurationFailsClosed(t *testing.T) {
	t.Setenv("DEMO_IDENTITY_ISSUER", "http://auth.example.test")
	t.Setenv("DEMO_RESOURCE", "https://files.example.test")
	t.Setenv("DEMO_PROJECT_ID", "project")
	t.Setenv("DEMO_CLIENT_ID", "desktop")
	_, err := loadSettings()
	require.Error(t, err)
	t.Setenv("DEMO_IDENTITY_ISSUER", "https://auth.example.test")
	_, err = loadSettings()
	require.NoError(t, err)
	t.Setenv("DEMO_IDENTITY_ISSUER", "https://auth.example.test?redirect=other")
	_, err = loadSettings()
	require.Error(t, err)
}

func TestResourceIntrospectsEveryRequestAndRejectsStaleAuthority(t *testing.T) {
	var active atomic.Bool
	active.Store(true)
	var calls atomic.Int32
	var issuer string
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "/oauth/introspect", r.URL.Path)
		user, secret, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "resource", user)
		require.Equal(t, "test-resource-only", secret)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "agent-token", r.Form.Get("token"))
		principal := introspection{Active: active.Load(), Subject: "agent", Kind: "agent", Issuer: issuer, Project: "project", Audience: []string{"https://files.example.test"}, ClientID: "desktop", Scope: "files:read", GrantID: "grant", SID: "session", ExpiresAt: 4102444800}
		principal.Actor.Subject = "owner"
		require.NoError(t, json.NewEncoder(w).Encode(principal))
	}))
	defer identity.Close()
	issuer = identity.URL
	s := settings{issuer: issuer, project: "project", clientID: "desktop", resource: "https://files.example.test", resourceID: "resource", resourceSecret: "test-resource-only"}
	handler := resourceHandler(s, identity.Client())
	for _, want := range []int{200, 401} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://resource.example.test/agent-demo", nil)
		req.Header.Set("Authorization", "Bearer agent-token")
		handler.ServeHTTP(rec, req)
		require.Equal(t, want, rec.Code)
		active.Store(false)
	}
	require.EqualValues(t, 2, calls.Load(), "a resource must check current authority for every request")
}

type authorizationURLWriter struct{ urls chan string }

func (w authorizationURLWriter) Write(data []byte) (int, error) {
	value := strings.TrimSpace(string(data))
	if strings.HasPrefix(value, "https://") {
		w.urls <- value
	}
	return len(data), nil
}

func TestNativeUsesPrivateVerifierThenRotatesAndRevokes(t *testing.T) {
	var challenge string
	var refreshed, revoked atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			require.NoError(t, r.ParseForm())
			require.Empty(t, r.Header.Get("Authorization"))
			if r.Form.Get("grant_type") == "authorization_code" {
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				require.Equal(t, challenge, base64.RawURLEncoding.EncodeToString(sum[:]))
				require.Equal(t, "one-time-code", r.Form.Get("code"))
				// #nosec G117 -- Isolated test issuer returns fake OAuth tokens, never real credentials.
				require.NoError(t, json.NewEncoder(w).Encode(tokenResponse{AccessToken: "agent-access", RefreshToken: "initial-refresh", TokenType: "Bearer"}))
			} else {
				require.Equal(t, "initial-refresh", r.Form.Get("refresh_token"))
				refreshed.Store(true)
				// #nosec G117 -- Isolated test issuer returns fake OAuth tokens, never real credentials.
				require.NoError(t, json.NewEncoder(w).Encode(tokenResponse{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", TokenType: "Bearer"}))
			}
		case "/oauth/revoke":
			require.NoError(t, r.ParseForm())
			require.Equal(t, "rotated-refresh", r.Form.Get("token"))
			revoked.Store(true)
			require.NoError(t, json.NewEncoder(w).Encode(struct{}{}))
		case "/agent-demo":
			require.Equal(t, "Bearer agent-access", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	urls := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := settings{issuer: server.URL, project: "project", clientID: "desktop", resource: server.URL}
	go func() { done <- runNative(ctx, s, server.Client(), authorizationURLWriter{urls: urls}) }()
	var raw string
	select {
	case raw = <-urls:
	case <-ctx.Done():
		t.Fatal("native URL missing")
	}
	request, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "S256", request.Query().Get("code_challenge_method"))
	require.Empty(t, request.Query().Get("code_verifier"))
	challenge = request.Query().Get("code_challenge")
	callback, err := url.Parse(request.Query().Get("redirect_uri"))
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", callback.Hostname())
	query := url.Values{"state": {request.Query().Get("state")}, "iss": {server.URL}, "code": {"one-time-code"}}
	callback.RawQuery = query.Encode()
	response, err := http.Get(callback.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_ = response.Body.Close()
	require.NoError(t, <-done)
	require.True(t, refreshed.Load())
	require.True(t, revoked.Load())
}
