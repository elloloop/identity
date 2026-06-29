//go:build integration && oauthlive

// Package integration's OPT-IN LIVE OAuth smoke suite.
//
// This file is excluded from the normal `-tags integration` run by the
// extra `oauthlive` build constraint. It compiles and runs only under:
//
//	go test -tags 'integration oauthlive' ./tests/integration/
//
// Even then, every test SKIPS unless real provider credentials are
// present in the environment, so a credential-less run is always green
// and never affects normal CI.
//
// Purpose: when real creds exist, verify each provider actually
// INITIALIZES from real config and can reach its live discovery / JWKS
// (or API) endpoint. This is a lightweight liveness check — it does NOT
// perform an interactive login or a real token exchange (those require
// human consent and cannot be automated).
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/elloloop/identity/pkg/oauth"
)

// liveTimeout bounds each provider's network liveness check so a flaky
// endpoint can't stall the suite indefinitely.
const liveTimeout = 10 * time.Second

// Public, well-known provider endpoints the live smoke probes. These
// mirror the (unexported) defaults baked into pkg/oauth's provider
// constructors; the suite asserts the same endpoints the real providers
// would talk to are reachable.
const (
	liveGoogleDiscoveryURL = "https://accounts.google.com/.well-known/openid-configuration"
	// %s is the tenant segment ("common" unless GATEWAY_MICROSOFT_TENANT_ID is set).
	liveMicrosoftDiscoveryURLFormat = "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration"
	liveMicrosoftDefaultTenant      = "common"
	liveAppleDiscoveryURL           = "https://appleid.apple.com/.well-known/openid-configuration"
	liveGitHubAPIBaseURL            = "https://api.github.com"
)

// Env var names (identical to internal/config/config.go) the smoke
// reads to decide whether to run for a given provider.
const (
	envGoogleClientID     = "GATEWAY_OAUTH_GOOGLE_CLIENT_ID"
	envGoogleClientSecret = "GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET"

	envMicrosoftClientID     = "GATEWAY_OAUTH_MICROSOFT_CLIENT_ID"
	envMicrosoftClientSecret = "GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET"
	envMicrosoftTenantID     = "GATEWAY_MICROSOFT_TENANT_ID"

	envAppleClientID = "GATEWAY_OAUTH_APPLE_CLIENT_ID"
	envAppleTeamID   = "GATEWAY_OAUTH_APPLE_TEAM_ID"
	envAppleKeyID    = "GATEWAY_OAUTH_APPLE_KEY_ID"
	envApplePrivKey  = "GATEWAY_OAUTH_APPLE_PRIVATE_KEY"

	envGitHubClientID     = "GATEWAY_OAUTH_GITHUB_CLIENT_ID"
	envGitHubClientSecret = "GATEWAY_OAUTH_GITHUB_CLIENT_SECRET"
)

func TestLive_Google(t *testing.T) {
	env := liveRequireEnv(t, "Google", envGoogleClientID, envGoogleClientSecret)

	// Construct the real provider from real config. A non-nil Exchanger
	// proves the credentials wire through the constructor.
	provider := oauth.NewGoogle(oauth.GoogleConfig{
		ClientID:     env[envGoogleClientID],
		ClientSecret: env[envGoogleClientSecret],
	})
	liveRequireProvider(t, provider)

	ctx, cancel := context.WithTimeout(context.Background(), liveTimeout)
	defer cancel()

	// Liveness: fetch Google's live OIDC discovery doc and its JWKS,
	// asserting a non-empty key set.
	liveAssertDiscoveryJWKS(t, ctx, liveGoogleDiscoveryURL)
}

func TestLive_Microsoft(t *testing.T) {
	env := liveRequireEnv(t, "Microsoft", envMicrosoftClientID, envMicrosoftClientSecret)

	tenant := strings.TrimSpace(os.Getenv(envMicrosoftTenantID))
	if tenant == "" {
		tenant = liveMicrosoftDefaultTenant
	}

	provider := oauth.NewMicrosoft(oauth.MicrosoftConfig{
		ClientID:     env[envMicrosoftClientID],
		ClientSecret: env[envMicrosoftClientSecret],
		TenantID:     tenant,
	})
	liveRequireProvider(t, provider)

	ctx, cancel := context.WithTimeout(context.Background(), liveTimeout)
	defer cancel()

	liveAssertDiscoveryJWKS(t, ctx, fmt.Sprintf(liveMicrosoftDiscoveryURLFormat, tenant))
}

func TestLive_Apple(t *testing.T) {
	env := liveRequireEnv(t, "Apple",
		envAppleClientID, envAppleTeamID, envAppleKeyID, envApplePrivKey)

	provider := oauth.NewApple(oauth.AppleConfig{
		ClientID:   env[envAppleClientID],
		TeamID:     env[envAppleTeamID],
		KeyID:      env[envAppleKeyID],
		PrivateKey: env[envApplePrivKey],
	})
	liveRequireProvider(t, provider)

	ctx, cancel := context.WithTimeout(context.Background(), liveTimeout)
	defer cancel()

	liveAssertDiscoveryJWKS(t, ctx, liveAppleDiscoveryURL)
}

func TestLive_GitHub(t *testing.T) {
	env := liveRequireEnv(t, "GitHub", envGitHubClientID, envGitHubClientSecret)

	// GitHub does not implement OIDC, so there is no discovery/JWKS to
	// probe. Construct the provider from real creds and confirm the
	// configured API base is reachable. We deliberately do NOT perform a
	// real token exchange (that needs an interactive authorization code).
	provider := oauth.NewGitHub(oauth.GitHubConfig{
		ClientID:     env[envGitHubClientID],
		ClientSecret: env[envGitHubClientSecret],
	})
	liveRequireProvider(t, provider)

	ctx, cancel := context.WithTimeout(context.Background(), liveTimeout)
	defer cancel()

	liveAssertReachable(t, ctx, liveGitHubAPIBaseURL)
}

// liveRequireEnv returns the values for the given env keys, or skips the
// test (keeping a credential-less run green) when any are unset/empty.
func liveRequireEnv(t *testing.T, provider string, keys ...string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			t.Skipf("set GATEWAY_OAUTH_%s_* to run live smoke for %s",
				strings.ToUpper(provider), provider)
		}
		out[k] = v
	}
	return out
}

// liveRequireProvider fails if the constructor returned a nil Exchanger
// (i.e. real config failed to wire through).
func liveRequireProvider(t *testing.T, provider oauth.Exchanger) {
	t.Helper()
	if provider == nil {
		t.Fatal("provider constructor returned nil Exchanger for real config")
	}
}

// liveAssertDiscoveryJWKS fetches an OIDC discovery document, follows its
// jwks_uri, and asserts the live JWK set is non-empty. A network error or
// empty key set fails the test — that is the point of a live smoke.
func liveAssertDiscoveryJWKS(t *testing.T, ctx context.Context, discoveryURL string) {
	t.Helper()

	body := liveGet(t, ctx, discoveryURL)
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse discovery document from %s: %v", discoveryURL, err)
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		t.Fatalf("discovery document %s missing jwks_uri", discoveryURL)
	}

	jwksBody := liveGet(t, ctx, doc.JWKSURI)
	set, err := jwk.Parse(jwksBody)
	if err != nil {
		t.Fatalf("parse JWKS from %s: %v", doc.JWKSURI, err)
	}
	if set.Len() == 0 {
		t.Fatalf("JWKS from %s contained no keys", doc.JWKSURI)
	}
	t.Logf("live JWKS OK: %s -> %s (%d keys)", discoveryURL, doc.JWKSURI, set.Len())
}

// liveAssertReachable issues a GET against url and asserts a non-error
// (< 400) HTTP status. Used for non-OIDC providers (GitHub) whose API
// root has no discovery document.
func liveAssertReachable(t *testing.T, ctx context.Context, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reach %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= http.StatusBadRequest {
		t.Fatalf("%s returned HTTP %d", url, resp.StatusCode)
	}
	t.Logf("live reachable OK: %s (HTTP %d)", url, resp.StatusCode)
}

// liveGet performs a GET and returns the (size-limited) response body,
// failing the test on any transport error or non-200 status.
func liveGet(t *testing.T, ctx context.Context, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body from %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	return body
}
