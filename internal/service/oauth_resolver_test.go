package service

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// rotatedGoogleScope is projectGoogleScope with a different encrypted secret, so
// its provider config hashes differently (simulating a config edit).
func rotatedGoogleScope(t *testing.T, projectID, clientID string) context.Context {
	t.Helper()
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: projectID,
		OAuth: ProjectOAuthConfig{Google: &ProjectOAuthGoogle{
			ClientID:         clientID,
			ClientSecretEnc:  encForProject(t, "rotated-secret"),
			AuthorizationURL: "https://accounts.example/authorize",
		}},
	})
}

func resolverSecretsKey() []byte { return make([]byte, 32) }

func encForProject(t *testing.T, plaintext string) string {
	t.Helper()
	ct, err := secretcrypto.Encrypt(plaintext, resolverSecretsKey())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return ct
}

// envGoogleRegistry builds a registry with a real Google exchanger whose
// client_id is clientID, so its authorization URL is distinguishable from a
// per-project one. AuthorizationURL is overridden to avoid any network.
func envGoogleRegistry(clientID string) *oauth.Registry {
	r := oauth.NewRegistry()
	r.Register("google", oauth.NewGoogle(oauth.GoogleConfig{
		ClientID:         clientID,
		ClientSecret:     "env-secret",
		AuthorizationURL: "https://accounts.example/authorize",
	}))
	return r
}

func projectGoogleScope(t *testing.T, projectID, clientID string) context.Context {
	t.Helper()
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: projectID,
		OAuth: ProjectOAuthConfig{
			Google: &ProjectOAuthGoogle{
				ClientID:         clientID,
				ClientSecretEnc:  encForProject(t, "proj-secret"),
				AuthorizationURL: "https://accounts.example/authorize",
			},
		},
	})
}

func authURL(t *testing.T, e oauth.Exchanger) string {
	t.Helper()
	a, ok := e.(oauth.Authorizer)
	if !ok {
		t.Fatal("exchanger is not an Authorizer")
	}
	u, err := a.AuthorizationURL(context.Background(), "https://app/cb", "state", "challenge")
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	return u
}

func TestOAuthResolver_DefaultProjectUsesEnv(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)

	// Unscoped and default-project-scoped requests both use the env provider.
	for name, ctx := range map[string]context.Context{
		"unscoped": context.Background(),
		"default":  WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default"}),
	} {
		if !r.available(ctx) {
			t.Fatalf("%s: expected available", name)
		}
		e, ok := r.exchangerFor(ctx, "google")
		if !ok {
			t.Fatalf("%s: expected google exchanger", name)
		}
		if got := authURL(t, e); !strings.Contains(got, "client_id=env-google") {
			t.Errorf("%s: want env client_id in %q", name, got)
		}
	}
}

func TestOAuthResolver_NonDefaultProjectWithoutConfig_Unavailable(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "other"})

	if r.available(ctx) {
		t.Fatal("non-default project without OAuth config must not be available")
	}
	if _, ok := r.exchangerFor(ctx, "google"); ok {
		t.Fatal("non-default project must NOT inherit the env google provider (isolation leak)")
	}
}

// Hub sharing (GATEWAY_OAUTH_HUB_SHARING) relaxes precedence rule 3: a
// non-default project with no config of its own borrows the default
// project's providers (ADR-0011).
func TestOAuthResolver_HubSharing_NonDefaultBorrowsDefault(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), true, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "other"})

	if !r.available(ctx) {
		t.Fatal("hub sharing must make the default providers available to a non-default project")
	}
	e, ok := r.exchangerFor(ctx, "google")
	if !ok {
		t.Fatal("hub sharing must resolve the env google provider for a non-default project")
	}
	if got := authURL(t, e); !strings.Contains(got, "client_id=env-google") {
		t.Errorf("want borrowed env client_id in %q", got)
	}
}

// Hub sharing never overrides rule 1: a project's own provider config still
// wins over the hub's.
func TestOAuthResolver_HubSharing_ProjectConfigStillWins(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), true, nil).
		withSecrets(resolverSecretsKey(), nil)

	e, ok := r.exchangerFor(projectGoogleScope(t, "other", "proj-google"), "google")
	if !ok {
		t.Fatal("project-configured google must resolve")
	}
	if got := authURL(t, e); !strings.Contains(got, "client_id=proj-google") {
		t.Errorf("project config must win over the hub provider, got %q", got)
	}
}

func TestOAuthResolver_ProjectConfigWinsAndIsolated(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)

	// A second project with its OWN google client_id resolves to THAT client_id.
	projCtx := projectGoogleScope(t, "other", "proj-google")
	e, ok := r.exchangerFor(projCtx, "google")
	if !ok {
		t.Fatal("project-configured google must resolve")
	}
	if got := authURL(t, e); !strings.Contains(got, "client_id=proj-google") {
		t.Errorf("want project client_id in %q", got)
	}

	// The default project still uses the env client_id — no cross-contamination.
	defCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default"})
	de, _ := r.exchangerFor(defCtx, "google")
	if got := authURL(t, de); !strings.Contains(got, "client_id=env-google") {
		t.Errorf("default project must keep env client_id, got %q", got)
	}
}

func TestOAuthResolver_DefaultProjectConfigOverridesEnv(t *testing.T) {
	// Even for the default project, an explicit config_json provider wins over
	// the env-configured one.
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := projectGoogleScope(t, "default", "override-google")

	e, ok := r.exchangerFor(ctx, "google")
	if !ok {
		t.Fatal("default project config google must resolve")
	}
	if got := authURL(t, e); !strings.Contains(got, "client_id=override-google") {
		t.Errorf("want overriding client_id in %q", got)
	}
}

// envGitHubRegistry builds a registry with a real GitHub exchanger whose
// client_id is clientID, so its authorization URL is distinguishable from a
// per-project one (GitHub's authorization URL is built offline, no network).
func envGitHubRegistry(clientID string) *oauth.Registry {
	r := oauth.NewRegistry()
	r.Register("github", oauth.NewGitHub(oauth.GitHubConfig{
		ClientID:     clientID,
		ClientSecret: "env-secret",
	}))
	return r
}

func projectGitHubScope(t *testing.T, projectID, clientID string) context.Context {
	t.Helper()
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: projectID,
		OAuth: ProjectOAuthConfig{
			GitHub: &ProjectOAuthGitHub{
				ClientID:        clientID,
				ClientSecretEnc: encForProject(t, "proj-gh-secret"),
			},
		},
	})
}

// TestOAuthResolver_GitHubPerProjectIsolation is the GitHub counterpart of the
// Google isolation test: a project's own config_json GitHub provider wins, the
// default project falls back to the env-configured provider, and a non-default
// project without a GitHub block cannot use GitHub (no env inheritance).
func TestOAuthResolver_GitHubPerProjectIsolation(t *testing.T) {
	r := newOAuthResolver("default", envGitHubRegistry("env-github"), false, nil).
		withSecrets(resolverSecretsKey(), nil)

	// A non-default project with its OWN github client_id resolves to THAT id.
	projCtx := projectGitHubScope(t, "other", "proj-github")
	e, ok := r.exchangerFor(projCtx, "github")
	if !ok {
		t.Fatal("project-configured github must resolve")
	}
	if got := authURL(t, e); !strings.Contains(got, "client_id=proj-github") {
		t.Errorf("want project client_id in %q", got)
	}

	// The default project still uses the env client_id — no cross-contamination.
	defCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default"})
	de, ok := r.exchangerFor(defCtx, "github")
	if !ok {
		t.Fatal("default project must resolve the env github provider")
	}
	if got := authURL(t, de); !strings.Contains(got, "client_id=env-github") {
		t.Errorf("default project must keep env client_id, got %q", got)
	}

	// A non-default project WITHOUT a github block never inherits the env one.
	bareCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "bare"})
	if _, ok := r.exchangerFor(bareCtx, "github"); ok {
		t.Fatal("non-default project without github config must NOT inherit env github (isolation leak)")
	}
}

func TestOAuthResolver_CacheReusesAndRebuilds(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := projectGoogleScope(t, "other", "proj-google")

	e1, ok := r.exchangerFor(ctx, "google")
	if !ok {
		t.Fatal("first build must succeed")
	}
	e2, _ := r.exchangerFor(ctx, "google")
	if e1 != e2 {
		t.Error("same config must reuse the cached exchanger instance")
	}

	// A changed secret (different ciphertext → different config hash) rebuilds.
	changed := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "other",
		OAuth: ProjectOAuthConfig{Google: &ProjectOAuthGoogle{
			ClientID:         "proj-google",
			ClientSecretEnc:  encForProject(t, "rotated-secret"),
			AuthorizationURL: "https://accounts.example/authorize",
		}},
	})
	e3, _ := r.exchangerFor(changed, "google")
	if e1 == e3 {
		t.Error("a changed config must rebuild the exchanger")
	}
}

func TestOAuthResolver_MissingSecretsKey_ProviderUnavailable(t *testing.T) {
	// No withSecrets: a project that stores an encrypted secret cannot be built.
	// The secret ciphertext value is irrelevant here — the key is absent — so a
	// plain marker string exercises every provider's decrypt-error branch.
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil)
	cases := map[string]ProjectOAuthConfig{
		"google":    {Google: &ProjectOAuthGoogle{ClientID: "g", ClientSecretEnc: "enc"}},
		"microsoft": {Microsoft: &ProjectOAuthMicrosoft{ClientID: "m", ClientSecretEnc: "enc"}},
		"apple":     {Apple: &ProjectOAuthApple{ClientID: "a", TeamID: "t", KeyID: "k", PrivateKeyEnc: "enc"}},
		"github":    {GitHub: &ProjectOAuthGitHub{ClientID: "gh", ClientSecretEnc: "enc"}},
		"oidc":      {OIDC: &ProjectOAuthOIDC{ClientID: "o", ClientSecretEnc: "enc", Issuer: "https://issuer.example"}},
	}
	for provider, cfg := range cases {
		ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "other", OAuth: cfg})
		// available is optimistic (the project DID configure a provider)...
		if !r.available(ctx) {
			t.Errorf("%s: a configured provider should report available", provider)
		}
		// ...but it cannot be built without the key.
		if _, ok := r.exchangerFor(ctx, provider); ok {
			t.Errorf("%s: must be unavailable when the secrets key is missing", provider)
		}
	}
}

func TestOAuthResolver_UnknownProviderMisses(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default"})
	if _, ok := r.exchangerFor(ctx, "github"); ok {
		t.Fatal("a provider not in the env registry must miss for the default project")
	}
}

func TestOAuthResolver_DisabledWhenNoProviders(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	if r.available(context.Background()) {
		t.Fatal("empty env registry + no project config must be unavailable")
	}
}

func TestOAuthResolver_BuildsAllProviders(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).
		withSecrets(resolverSecretsKey(), nil)

	cases := map[string]ProjectOAuthConfig{
		"google":    {Google: &ProjectOAuthGoogle{ClientID: "g", ClientSecretEnc: encForProject(t, "s")}},
		"microsoft": {Microsoft: &ProjectOAuthMicrosoft{ClientID: "m", ClientSecretEnc: encForProject(t, "s")}},
		"apple":     {Apple: &ProjectOAuthApple{ClientID: "a", TeamID: "t", KeyID: "k", PrivateKeyEnc: encForProject(t, "apple-private-key-pem")}},
		"github":    {GitHub: &ProjectOAuthGitHub{ClientID: "gh", ClientSecretEnc: encForProject(t, "s")}},
		"oidc":      {OIDC: &ProjectOAuthOIDC{ClientID: "o", ClientSecretEnc: encForProject(t, "s"), Issuer: "https://issuer.example"}},
	}
	for provider, cfg := range cases {
		ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "other", OAuth: cfg})
		if _, ok := r.exchangerFor(ctx, provider); !ok {
			t.Errorf("provider %q must build from project config", provider)
		}
	}
}

func TestOAuthResolver_CacheSingleSlotPerProviderEvictsSuperseded(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).
		withSecrets(resolverSecretsKey(), nil)

	// Build the initial config, then a rotated one (different hash) for the SAME
	// project+provider. The superseded entry must be evicted, not accumulated.
	if _, ok := r.exchangerFor(projectGoogleScope(t, "other", "proj-google"), "google"); !ok {
		t.Fatal("initial build must succeed")
	}
	if _, ok := r.exchangerFor(rotatedGoogleScope(t, "other", "proj-google"), "google"); !ok {
		t.Fatal("rotated build must succeed")
	}

	r.mu.RLock()
	n := len(r.cache)
	r.mu.RUnlock()
	if n != 1 {
		t.Fatalf("cache must hold at most one entry per project+provider, got %d", n)
	}
}

func TestOAuthResolver_NegativeResultCachedNoRebuildOrRelog(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	// No withSecrets: every build fails (cannot decrypt) and logs a warning.
	r := newOAuthResolver("default", oauth.NewRegistry(), false, zap.New(core))
	ctx := projectGoogleScope(t, "other", "proj-google")

	// Repeated logins with the SAME broken config must neither rebuild nor
	// re-log — the negative result is cached under its config hash.
	for i := 0; i < 3; i++ {
		if _, ok := r.exchangerFor(ctx, "google"); ok {
			t.Fatal("a build failure must report the provider unavailable")
		}
	}
	if got := logs.FilterMessage("oauth_project_provider_build_failed").Len(); got != 1 {
		t.Fatalf("a persistently-bad config must log exactly once, got %d", got)
	}

	// A genuinely changed config (new hash) misses the negative entry and retries.
	if _, ok := r.exchangerFor(rotatedGoogleScope(t, "other", "proj-google"), "google"); ok {
		t.Fatal("changed-but-still-broken config must still be unavailable")
	}
	if got := logs.FilterMessage("oauth_project_provider_build_failed").Len(); got != 2 {
		t.Fatalf("a changed config must retry and log again, got %d", got)
	}
}
