package service

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/oauth"
)

// The hosts a host-client test signs in on: hostB has an override, hostA has
// none and keeps the base client.
const (
	hostA        = "auth.a.example"
	hostB        = "auth.b.example"
	callbackOnA  = "https://auth.a.example/oauth/callback/google"
	callbackOnB  = "https://auth.b.example/oauth/callback/google"
	appleOnB     = "https://auth.b.example/oauth/callback/apple"
	hostBGoogle  = "host-b-google"
	hostBAppleID = "example.b.web"
)

// envGoogleBuilder is the EnvOAuthProviderBuilder app.New wires, reduced to
// the env Google of envGoogleRegistry: it rebuilds that provider with another
// client and keeps its endpoint, and reports false for any other provider.
func envGoogleBuilder(provider, clientID, clientSecret string) (oauth.Exchanger, bool) {
	if provider != oauthProviderGoogle {
		return nil, false
	}
	return oauth.NewGoogle(oauth.GoogleConfig{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		AuthorizationURL: "https://accounts.example/authorize",
	}), true
}

// hostClientScope scopes a request to projectID with cfg, adding a Google
// override for hostB whose secret is secretEnc.
func hostClientScope(projectID string, cfg ProjectOAuthConfig, secretEnc string) context.Context {
	cfg.Hosts = map[string]ProjectOAuthHostClients{
		hostB: {oauthProviderGoogle: {ClientID: hostBGoogle, ClientSecretEnc: secretEnc}},
	}
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: projectID, OAuth: cfg})
}

// mustClientID resolves provider for redirectURI and returns the client id
// its authorization URL carries, failing when the provider is unavailable.
func mustClientID(ctx context.Context, t *testing.T, r *OAuthResolver, provider, redirectURI string) string {
	t.Helper()
	e, ok := r.exchangerFor(ctx, provider, redirectURI)
	if !ok {
		t.Fatalf("%s at %s: want available", provider, redirectURI)
	}
	a, ok := e.(oauth.Authorizer)
	if !ok {
		t.Fatalf("%s at %s: exchanger is not an Authorizer", provider, redirectURI)
	}
	got, err := a.AuthorizationURL(ctx, "https://app/cb", "state", "challenge")
	if err != nil {
		t.Fatalf("%s at %s: authorization url: %v", provider, redirectURI, err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("%s at %s: authorization url %q: %v", provider, redirectURI, got, err)
	}
	return u.Query().Get("client_id")
}

// A project's own provider (rule 1) signs in through the host's client on
// that host, keeping the base's other settings, and through its own client on
// every other host and when no redirect URI is known.
func TestOAuthHostClient_OwnProviderBase(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := hostClientScope("other", ProjectOAuthConfig{Google: &ProjectOAuthGoogle{
		ClientID:         "proj-google",
		ClientSecretEnc:  encForProject(t, "proj-secret"),
		AuthorizationURL: "https://accounts.example/authorize",
	}}, encForProject(t, "host-secret"))

	e, ok := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB)
	if !ok {
		t.Fatal("the host's client must resolve")
	}
	if got := authURL(t, e); !strings.HasPrefix(got, "https://accounts.example/authorize?") || !strings.Contains(got, "client_id="+hostBGoogle) {
		t.Errorf("want the host client on the base endpoint, got %q", got)
	}
	for _, redirectURI := range []string{callbackOnA, ""} {
		if got := mustClientID(ctx, t, r, oauthProviderGoogle, redirectURI); got != "proj-google" {
			t.Errorf("redirect %q: client_id = %q, want the project's own", redirectURI, got)
		}
	}
}

// The default project's env provider (rule 2) is rebuilt with the host's
// client; the env client stays everywhere else.
func TestOAuthHostClient_EnvProviderBase(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	r.envProvider = envGoogleBuilder
	ctx := hostClientScope("default", ProjectOAuthConfig{}, encForProject(t, "host-secret"))

	if got := mustClientID(ctx, t, r, oauthProviderGoogle, callbackOnB); got != hostBGoogle {
		t.Errorf("host B: client_id = %q, want the host's", got)
	}
	if got := mustClientID(ctx, t, r, oauthProviderGoogle, callbackOnA); got != "env-google" {
		t.Errorf("host A: client_id = %q, want the env client", got)
	}
}

// A non-default project borrowing the hub's env provider (rule 3, hub
// sharing) gets the host's client too; without hub sharing it has no base,
// and the override does not create one.
func TestOAuthHostClient_BorrowedBase(t *testing.T) {
	for _, sharing := range []bool{true, false} {
		r := newOAuthResolver("default", envGoogleRegistry("env-google"), sharing, nil).
			withSecrets(resolverSecretsKey(), nil)
		r.envProvider = envGoogleBuilder
		ctx := hostClientScope("other", ProjectOAuthConfig{}, encForProject(t, "host-secret"))

		_, okB := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB)
		_, okA := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnA)
		if !sharing {
			if okB || okA {
				t.Fatalf("without hub sharing: host B ok=%v, host A ok=%v; an override must never enable a provider", okB, okA)
			}
			continue
		}
		if got := mustClientID(ctx, t, r, oauthProviderGoogle, callbackOnB); got != hostBGoogle {
			t.Errorf("borrowed, host B: client_id = %q, want the host's", got)
		}
		if got := mustClientID(ctx, t, r, oauthProviderGoogle, callbackOnA); got != "env-google" {
			t.Errorf("borrowed, host A: client_id = %q, want the hub's", got)
		}
	}
}

// A provider the env does not configure has no base for the default project,
// so its override leaves it unavailable.
func TestOAuthHostClient_NoEnvBaseNeverEnables(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	r.envProvider = envGoogleBuilder
	ctx := hostClientScope("default", ProjectOAuthConfig{}, encForProject(t, "host-secret"))
	if _, ok := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB); ok {
		t.Fatal("an override of a provider the env does not configure must stay unavailable")
	}
}

// A project's own native-only block (native_audiences alone) has no hosted
// client to swap, so a host client does not give it one: the provider stays
// unavailable for the hosted flow on the override's host, as on every other.
func TestOAuthHostClient_NativeOnlyBaseNeverEnables(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).withSecrets(resolverSecretsKey(), nil)
	secretEnc := encForProject(t, "host-secret")
	for _, tc := range []struct {
		provider string
		cfg      ProjectOAuthConfig
		client   ProjectOAuthHostClient
	}{
		{
			oauthProviderGoogle,
			ProjectOAuthConfig{Google: &ProjectOAuthGoogle{NativeAudiences: []string{"native.example"}}},
			ProjectOAuthHostClient{ClientID: hostBGoogle, ClientSecretEnc: secretEnc},
		},
		{
			oauthProviderMicrosoft,
			ProjectOAuthConfig{Microsoft: &ProjectOAuthMicrosoft{NativeAudiences: []string{"native.example"}}},
			ProjectOAuthHostClient{ClientID: "host-b-microsoft", ClientSecretEnc: secretEnc},
		},
		{
			oauthProviderApple,
			ProjectOAuthConfig{Apple: &ProjectOAuthApple{NativeAudiences: []string{"native.example"}}},
			ProjectOAuthHostClient{ClientID: hostBAppleID},
		},
	} {
		if err := tc.cfg.validate(); err != nil {
			t.Fatalf("%s: the native-only block must be a valid config: %v", tc.provider, err)
		}
		tc.cfg.Hosts = map[string]ProjectOAuthHostClients{hostB: {tc.provider: tc.client}}
		ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "other", OAuth: tc.cfg})
		for _, host := range []string{hostA, hostB} {
			if _, ok := r.exchangerFor(ctx, tc.provider, "https://"+host+"/oauth/callback/"+tc.provider); ok {
				t.Errorf("%s on %s: a native-only base must stay unavailable for the hosted flow", tc.provider, host)
			}
		}
	}
}

// Apple's host client swaps only the Services ID: the base team, key id and
// key sign for it, on an own base and on an env base alike.
func TestOAuthHostClient_AppleSwapsOnlyTheServicesID(t *testing.T) {
	hosts := map[string]ProjectOAuthHostClients{hostB: {oauthProviderApple: {ClientID: hostBAppleID}}}

	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).withSecrets(resolverSecretsKey(), nil)
	own := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "other", OAuth: ProjectOAuthConfig{
		Apple: &ProjectOAuthApple{ClientID: "example.base.web", TeamID: "TEAM", KeyID: "KEY", PrivateKeyEnc: encForProject(t, "apple-private-key-pem")},
		Hosts: hosts,
	}})
	if got := mustClientID(own, t, r, oauthProviderApple, appleOnB); got != hostBAppleID {
		t.Errorf("own base: client_id = %q, want the host's Services ID", got)
	}

	env := oauth.NewRegistry()
	env.Register(oauthProviderApple, oauth.NewApple(oauth.AppleConfig{ClientID: "example.env.web", TeamID: "TEAM", KeyID: "KEY", PrivateKey: "pem"}))
	var gotSecret string
	r = newOAuthResolver("default", env, false, nil).withSecrets(resolverSecretsKey(), nil)
	r.envProvider = func(provider, clientID, clientSecret string) (oauth.Exchanger, bool) {
		gotSecret = clientSecret
		return oauth.NewApple(oauth.AppleConfig{ClientID: clientID, TeamID: "TEAM", KeyID: "KEY", PrivateKey: "pem"}), provider == oauthProviderApple
	}
	def := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default", OAuth: ProjectOAuthConfig{Hosts: hosts}})
	if got := mustClientID(def, t, r, oauthProviderApple, appleOnB); got != hostBAppleID {
		t.Errorf("env base: client_id = %q, want the host's Services ID", got)
	}
	if gotSecret != "" {
		t.Errorf("an Apple host client has no secret, the env builder got %q", gotSecret)
	}
}

// A host client that cannot be built leaves the provider unavailable on that
// host, never falling back to the base client, which is not registered for
// the host's callback. It is logged once per configuration, naming the host,
// and other hosts keep the base.
func TestOAuthHostClient_BrokenOverrideIsUnavailableOnItsHost(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, zap.New(core)).
		withSecrets(resolverSecretsKey(), nil)
	r.envProvider = envGoogleBuilder
	ctx := hostClientScope("default", ProjectOAuthConfig{}, "not-ciphertext")

	for i := 0; i < 3; i++ {
		if _, ok := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB); ok {
			t.Fatal("an override whose secret will not decrypt must be unavailable on its host")
		}
	}
	failures := logs.FilterMessage("oauth_project_provider_build_failed")
	if failures.Len() != 1 {
		t.Fatalf("a broken override must log once, got %d", failures.Len())
	}
	if host := failures.All()[0].ContextMap()["callback_host"]; host != hostB {
		t.Errorf("the log must name the host, got %v", host)
	}
	if got := mustClientID(ctx, t, r, oauthProviderGoogle, callbackOnA); got != "env-google" {
		t.Errorf("another host must keep the env client, got %q", got)
	}
}

// When the embedder supplied the env registry, there is no builder to rebuild
// an env provider with, so an override whose base is one is unavailable on its
// host rather than signing in through the embedder's client.
func TestOAuthHostClient_EnvBaseWithoutBuilderIsUnavailable(t *testing.T) {
	r := newOAuthResolver("default", envGoogleRegistry("env-google"), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	ctx := hostClientScope("default", ProjectOAuthConfig{}, encForProject(t, "host-secret"))
	if _, ok := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB); ok {
		t.Fatal("without an env builder the override must be unavailable")
	}
	if got := mustClientID(ctx, t, r, oauthProviderGoogle, callbackOnA); got != "env-google" {
		t.Errorf("another host must keep the env client, got %q", got)
	}
}

// A host client is cached in its own slot beside the base's: the same config
// reuses it, and editing the override or the base rebuilds it.
func TestOAuthHostClient_CacheReusesAndRebuilds(t *testing.T) {
	r := newOAuthResolver("default", oauth.NewRegistry(), false, nil).
		withSecrets(resolverSecretsKey(), nil)
	base := func(authorizationURL string) ProjectOAuthConfig {
		return ProjectOAuthConfig{Google: &ProjectOAuthGoogle{
			ClientID: "proj-google", ClientSecretEnc: encForProject(t, "proj-secret"), AuthorizationURL: authorizationURL,
		}}
	}
	baseCfg := base("https://accounts.example/authorize")
	hostSecret := encForProject(t, "host-secret")
	ctx := hostClientScope("other", baseCfg, hostSecret)

	e1, _ := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB)
	e2, _ := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnB)
	if e1 == nil || e1 != e2 {
		t.Fatal("the same config must reuse the cached host client")
	}
	if _, ok := r.exchangerFor(ctx, oauthProviderGoogle, callbackOnA); !ok {
		t.Fatal("the base must resolve on host A")
	}
	r.mu.RLock()
	n := len(r.cache)
	r.mu.RUnlock()
	if n != 2 {
		t.Fatalf("the base and the host client take one slot each, got %d", n)
	}

	rotated, _ := r.exchangerFor(hostClientScope("other", baseCfg, encForProject(t, "rotated")), oauthProviderGoogle, callbackOnB)
	if rotated == nil || rotated == e1 {
		t.Error("a changed host client must rebuild")
	}
	rebased, _ := r.exchangerFor(hostClientScope("other", base("https://accounts.example/v2/authorize"), hostSecret), oauthProviderGoogle, callbackOnB)
	if rebased == nil || rebased == rotated {
		t.Error("a changed base must rebuild the host client")
	}
	if got := authURL(t, rebased); !strings.HasPrefix(got, "https://accounts.example/v2/authorize?") {
		t.Errorf("the rebuilt host client must use the new base endpoint, got %q", got)
	}
	r.mu.RLock()
	n = len(r.cache)
	r.mu.RUnlock()
	if n != 2 {
		t.Fatalf("a rebuilt host client replaces its slot, got %d entries", n)
	}
}

// A host is matched in the form oauth.hosts keys are stored in, whatever the
// case, port or trailing dot of the redirect URI.
func TestCallbackHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://auth.b.example/oauth/callback/google", hostB},
		{"https://Auth.B.Example:8443/oauth/callback/google", hostB},
		{"https://auth.b.example./oauth/callback/google", hostB},
		{" https://auth.b.example/cb ", hostB},
		{"", ""},
		{"/oauth/callback/google", ""},
		{"https://[::1]:8443/cb", "::1"},
		{"%zz", ""},
	} {
		if got := callbackHost(tc.in); got != tc.want {
			t.Errorf("callbackHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// withHostClient replaces the client identity of each provider and leaves the
// rest of the base, and the base itself, untouched.
func TestWithHostClient_SwapsOnlyTheClient(t *testing.T) {
	client := ProjectOAuthHostClient{ClientID: "host", ClientSecretEnc: "host-enc"}

	google := &ProjectOAuthGoogle{ClientID: "base", ClientSecretEnc: "base-enc", AuthorizationURL: "https://accounts.example/authorize"}
	if got := withHostClient(google, client).(*ProjectOAuthGoogle); got.ClientID != "host" || got.ClientSecretEnc != "host-enc" || got.AuthorizationURL != google.AuthorizationURL {
		t.Errorf("google = %+v", got)
	}
	microsoft := &ProjectOAuthMicrosoft{ClientID: "base", ClientSecretEnc: "base-enc", TenantID: "organizations"}
	if got := withHostClient(microsoft, client).(*ProjectOAuthMicrosoft); got.ClientID != "host" || got.ClientSecretEnc != "host-enc" || got.TenantID != "organizations" {
		t.Errorf("microsoft = %+v", got)
	}
	github := &ProjectOAuthGitHub{ClientID: "base", ClientSecretEnc: "base-enc", TokenURL: "https://ghe.example/token"}
	if got := withHostClient(github, client).(*ProjectOAuthGitHub); got.ClientID != "host" || got.ClientSecretEnc != "host-enc" || got.TokenURL != github.TokenURL {
		t.Errorf("github = %+v", got)
	}
	oidc := &ProjectOAuthOIDC{ClientID: "base", ClientSecretEnc: "base-enc", Issuer: "https://issuer.example"}
	if got := withHostClient(oidc, client).(*ProjectOAuthOIDC); got.ClientID != "host" || got.ClientSecretEnc != "host-enc" || got.Issuer != oidc.Issuer {
		t.Errorf("oidc = %+v", got)
	}
	apple := &ProjectOAuthApple{ClientID: "base", TeamID: "TEAM", KeyID: "KEY", PrivateKeyEnc: "key-enc"}
	if got := withHostClient(apple, ProjectOAuthHostClient{ClientID: "host"}).(*ProjectOAuthApple); got.ClientID != "host" || got.TeamID != "TEAM" || got.KeyID != "KEY" || got.PrivateKeyEnc != "key-enc" {
		t.Errorf("apple = %+v", got)
	}

	if google.ClientID != "base" || microsoft.ClientID != "base" || github.ClientID != "base" || oidc.ClientID != "base" || apple.ClientID != "base" {
		t.Error("withHostClient must not modify the base")
	}
	if got := withHostClient(struct{}{}, client); got != nil {
		t.Errorf("an unknown provider type must fail closed, got %#v", got)
	}
	for _, native := range []any{
		&ProjectOAuthGoogle{NativeAudiences: []string{"native.example"}},
		&ProjectOAuthMicrosoft{NativeAudiences: []string{"native.example"}},
		&ProjectOAuthApple{NativeAudiences: []string{"native.example"}},
	} {
		if got := withHostClient(native, client); got != nil {
			t.Errorf("a base with no hosted client (%T) must take no override, got %#v", native, got)
		}
	}
}
