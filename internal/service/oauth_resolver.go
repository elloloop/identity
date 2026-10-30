package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// OAuthResolver resolves the OAuth Exchanger to use for a request's project and
// provider, implementing the Firebase-project isolation model: every project
// configures its OWN providers in config_json, and one project never sees
// another's. The env-configured GATEWAY_OAUTH_* providers are the DEFAULT
// PROJECT's providers only — they are held in defaultRegistry.
//
// Precedence for provider P and the request's project:
//
//  1. the project's config_json.oauth.P — built (secret decrypted) and cached;
//  2. else, if the project IS the default project (or the request is unscoped),
//     the env-built defaultRegistry entry for P (today's behaviour);
//  3. else — a non-default project with no config for P — P is unavailable,
//     UNLESS hub sharing is enabled (GATEWAY_OAUTH_HUB_SHARING, ADR-0011):
//     then the default project's entry for P is borrowed, so hundreds of
//     projects can share one provider client routed via the central hub.
//
// Hub sharing is a deployment-level opt-in because it is only safe when every
// project belongs to the same trust domain as the hub (the provider consent
// screen shows the shared client's branding). It never overrides rule 1: a
// project's own provider config always wins, including a configured-but-broken
// one.
//
// Within whichever provider those rules select, a project may name another
// client for one callback host (config_json.oauth.hosts, ADR-0019): a flow
// whose callback is on that host signs in through it, with every other setting
// taken from the selected provider. The override never selects a provider of
// its own, and a broken one leaves the provider unavailable on that host.
//
// Building an Exchanger creates a JWKS/discovery cache, so instances are cached
// keyed by (projectID, provider[, host], configHash): a config change rebuilds,
// steady state reuses the cache.
type OAuthResolver struct {
	defaultProjectID string
	defaultRegistry  *oauth.Registry
	hubSharing       bool
	logger           *zap.Logger
	// envProvider rebuilds an env provider of defaultRegistry with another
	// client, for a host override whose base is one (rules 2 and 3). nil when
	// the registry was not built from the env (an embedder supplied it), and
	// such an override is then unavailable.
	envProvider EnvOAuthProviderBuilder

	// secretsKey decrypts per-project provider secrets at rest (AES-256-GCM).
	// Empty until wiring calls withSecrets; when empty, a project that stores
	// encrypted provider secrets cannot be built (a clear error is logged).
	secretsKey []byte
	// wrap decorates a freshly-built per-project Exchanger (observability
	// spans). The default project's registry entries are wrapped by app wiring;
	// this wraps the per-project ones identically. nil leaves them unwrapped.
	wrap func(provider string, e oauth.Exchanger) oauth.Exchanger

	mu sync.RWMutex
	// cache holds at most ONE entry per (projectID, provider), and one per
	// (projectID, provider, host) for each host override a request has used: a
	// config change (new hash) overwrites the superseded entry rather than
	// accumulating. An entry with a nil exchanger is a NEGATIVE result (the
	// build failed for that hash), cached so a persistently-misconfigured
	// project neither rebuilds nor re-logs on every login; a genuinely fixed
	// config (new hash) retries.
	cache map[string]oauthCacheEntry
}

// oauthCacheEntry is one resolver cache slot. hash pins it to a specific
// provider config; exchanger is nil when the build failed for that hash.
type oauthCacheEntry struct {
	hash      string
	exchanger oauth.Exchanger
}

// newOAuthResolver builds a resolver over the env-built default-project
// registry. defaultRegistry may be nil/empty (OAuth disabled for the default
// project); per-project providers still work once withSecrets is wired.
// hubSharing enables precedence rule 3's borrow of the default project's
// providers by non-default projects (GATEWAY_OAUTH_HUB_SHARING).
func newOAuthResolver(defaultProjectID string, defaultRegistry *oauth.Registry, hubSharing bool, logger *zap.Logger) *OAuthResolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &OAuthResolver{
		defaultProjectID: defaultProjectID,
		defaultRegistry:  defaultRegistry,
		hubSharing:       hubSharing,
		logger:           logger,
		cache:            make(map[string]oauthCacheEntry),
	}
}

// withSecrets wires the at-rest decryption key and the per-project Exchanger
// wrapper. Called once at construction before any request; not concurrency-safe.
func (r *OAuthResolver) withSecrets(secretsKey []byte, wrap func(provider string, e oauth.Exchanger) oauth.Exchanger) *OAuthResolver {
	r.secretsKey = secretsKey
	r.wrap = wrap
	return r
}

// EnvOAuthProviderBuilder builds the env-configured (GATEWAY_OAUTH_*) provider
// with another client id and secret, keeping every other env setting, or
// reports ok=false when the env does not configure the provider. Apple takes
// no secret: the env key signs for the client. It builds the host overrides
// (ADR-0019) whose base is an env provider.
type EnvOAuthProviderBuilder func(provider, clientID, clientSecret string) (e oauth.Exchanger, ok bool)

// available reports whether ANY OAuth provider is usable for the request's
// project. It drives the ErrOAuthDisabled short-circuit; a specific
// unconfigured provider is still reported by exchangerFor as a miss.
func (r *OAuthResolver) available(ctx context.Context) bool {
	if r == nil {
		return false
	}
	scope := ProjectScopeFromContext(ctx)
	if scope != nil {
		if scope.OAuth.hasAny() {
			return true
		}
		if r.isNonDefaultProject(scope.ProjectID) && !r.hubSharing {
			return false
		}
	}
	return r.defaultRegistry.Len() > 0
}

// exchangerFor returns the Exchanger for the request's project and provider,
// signing in through the client the project names for redirectURI's host when
// it names one (ADR-0019), or ok=false when the provider is not available for
// that project (an unconfigured provider, a non-default project without it, or
// a build failure). provider must already be lower-cased/trimmed by the
// caller. Callers pass the redirect URI the flow is bound to, so a start and
// its callback resolve the same client.
func (r *OAuthResolver) exchangerFor(ctx context.Context, provider, redirectURI string) (oauth.Exchanger, bool) {
	if r == nil {
		return nil, false
	}
	scope := ProjectScopeFromContext(ctx)
	if scope != nil {
		host := callbackHost(redirectURI)
		if client, ok := scope.OAuth.hostClient(host, provider); ok {
			built := r.buildHostClient(scope.ProjectID, provider, host, client, scope.OAuth)
			return built, built != nil
		}
		if present, built := r.buildProject(scope.ProjectID, provider, scope.OAuth); present {
			// present with a nil Exchanger means the project configured this
			// provider but it could not be built (bad secret / config). Project
			// config wins, so we do NOT fall through to env — the provider is
			// unavailable for this request.
			return built, built != nil
		}
		// The provider is not in the project's config. Isolation: a non-default
		// project never inherits the env (default-project) providers — unless
		// the deployment opted into hub sharing (ADR-0011), which borrows the
		// default project's entry so the central-hub flow can serve projects
		// that configure no client of their own.
		if r.isNonDefaultProject(scope.ProjectID) && !r.hubSharing {
			return nil, false
		}
	}
	return r.defaultRegistry.Get(provider)
}

// buildHostClient builds (and caches) the provider for a host override: the
// provider exchangerFor would otherwise select, signing in through client. It
// returns nil when there is no such provider or the build fails — never the
// base client, which is not registered for this host's callback.
func (r *OAuthResolver) buildHostClient(projectID, provider, host string, client ProjectOAuthHostClient, cfg ProjectOAuthConfig) oauth.Exchanger {
	key := projectID + "\x00" + provider + "\x00" + host
	fields := []zap.Field{zap.String("project_id", projectID), zap.String("provider", provider), zap.String("callback_host", host)}
	if base, ok := cfg.provider(provider); ok {
		// A nil swap (a type withHostClient does not know) fails in build and
		// is cached as unavailable.
		swapped := withHostClient(base, client)
		return r.cached(key, providerConfigHash(swapped), provider, fields, func() (oauth.Exchanger, error) {
			return r.build(provider, swapped)
		})
	}
	if r.isNonDefaultProject(projectID) && !r.hubSharing {
		return nil
	}
	if _, ok := r.defaultRegistry.Get(provider); !ok {
		return nil
	}
	return r.cached(key, "env\x00"+providerConfigHash(client), provider, fields, func() (oauth.Exchanger, error) {
		if r.envProvider == nil {
			return nil, errors.New("the env providers were supplied by the embedder, so none can be rebuilt with a host's client")
		}
		secret := ""
		if client.ClientSecretEnc != "" {
			var err error
			if secret, err = r.decrypt(client.ClientSecretEnc); err != nil {
				return nil, fmt.Errorf("%s client_secret: %w", provider, err)
			}
		}
		e, ok := r.envProvider(provider, client.ClientID, secret)
		if !ok {
			return nil, errors.New("the env does not configure the provider")
		}
		return e, nil
	})
}

// providersFor returns the provider keys CONFIGURED for the request's
// project, split by where their flow must start, mirroring exchangerFor's
// precedence without building any Exchanger. own are the providers whose
// client belongs to the request's project (its config_json ones — and the
// env registry's when the request IS the default project or unscoped);
// borrowed are the default project's providers a non-default project may
// use under hub sharing, whose client is registered for the HUB's callback
// URL and whose flow must therefore start on the hub origin. Both lists are
// sorted; a key never appears in both (the project's own config wins). A
// configured but unbuildable provider (bad secret) still lists — building
// every Exchanger per page render would decrypt secrets and hit
// JWKS/discovery each time; the login attempt itself surfaces the
// misconfiguration.
func (r *OAuthResolver) providersFor(ctx context.Context) (own, borrowed []string) {
	if r == nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	add := func(dst *[]string, providers []string) {
		for _, p := range providers {
			if !seen[p] {
				seen[p] = true
				*dst = append(*dst, p)
			}
		}
	}
	scope := ProjectScopeFromContext(ctx)
	if scope != nil {
		add(&own, scope.OAuth.providers())
		if r.isNonDefaultProject(scope.ProjectID) {
			if r.hubSharing {
				add(&borrowed, r.defaultRegistry.Providers())
			}
			sort.Strings(own)
			sort.Strings(borrowed)
			return own, borrowed
		}
	}
	add(&own, r.defaultRegistry.Providers())
	sort.Strings(own)
	return own, nil
}

// isNonDefaultProject reports whether projectID names a project OTHER than the
// default one — the projects that must NOT inherit the env-configured
// (default-project) providers. It is the exact negation of the shared
// config.IsDefaultProject rule (single source of truth), so hosted-provider and
// native-audience resolution stay in lock-step: when no default project is
// configured (a Config built directly without app.New — unit tests / a
// non-project embedding), every request is treated as default and the env
// providers apply as they did before this feature.
func (r *OAuthResolver) isNonDefaultProject(projectID string) bool {
	return !config.IsDefaultProject(r.defaultProjectID, projectID)
}

// buildProject looks up (and lazily builds + caches) the project-configured
// Exchanger for provider. present reports whether the project configured this
// provider at all; when present, the returned Exchanger is nil only if the
// build failed.
func (r *OAuthResolver) buildProject(projectID, provider string, cfg ProjectOAuthConfig) (present bool, exchanger oauth.Exchanger) {
	raw, ok := cfg.provider(provider)
	if !ok {
		return false, nil
	}
	// One slot per (projectID, provider) — a config change overwrites it.
	fields := []zap.Field{zap.String("project_id", projectID), zap.String("provider", provider)}
	return true, r.cached(projectID+"\x00"+provider, providerConfigHash(raw), provider, fields, func() (oauth.Exchanger, error) {
		return r.build(provider, raw)
	})
}

// cached returns provider's Exchanger cached in slot key for hash, building,
// wrapping and storing it on a miss. A failed build is cached too, as nil, and
// logged with fields once, so the same broken config neither rebuilds nor
// re-logs on every login; a fixed config (new hash) misses the entry and
// retries.
func (r *OAuthResolver) cached(key, hash, provider string, fields []zap.Field, build func() (oauth.Exchanger, error)) oauth.Exchanger {
	r.mu.RLock()
	entry, hit := r.cache[key]
	r.mu.RUnlock()
	if hit && entry.hash == hash {
		// Hit for the current config — positive OR negative (nil exchanger).
		return entry.exchanger
	}

	built, err := build()
	if err != nil {
		// Host-client builds log under this event too, env bases included;
		// their callback_host field tells them apart.
		r.logger.Warn("oauth_project_provider_build_failed", append(fields, zap.Error(err))...)
	} else if r.wrap != nil {
		built = r.wrap(provider, built)
	}

	r.mu.Lock()
	// A concurrent builder of the SAME hash wins so callers share one instance;
	// otherwise store (and thereby evict any superseded hash for this key).
	if existing, ok := r.cache[key]; ok && existing.hash == hash {
		built = existing.exchanger
	} else {
		r.cache[key] = oauthCacheEntry{hash: hash, exchanger: built}
	}
	r.mu.Unlock()
	return built
}

// build constructs the concrete Exchanger for a project-configured provider,
// decrypting its at-rest secret. The raw type identifies the provider, so no
// string switch is needed.
func (r *OAuthResolver) build(provider string, raw any) (oauth.Exchanger, error) {
	switch c := raw.(type) {
	case *ProjectOAuthGoogle:
		secret, err := r.decrypt(c.ClientSecretEnc)
		if err != nil {
			return nil, fmt.Errorf("google client_secret: %w", err)
		}
		return oauth.NewGoogle(oauth.GoogleConfig{
			ClientID:         c.ClientID,
			ClientSecret:     secret,
			AuthorizationURL: c.AuthorizationURL,
			TokenURL:         c.TokenURL,
			JWKSURL:          c.JWKSURL,
			Issuer:           c.Issuer,
		}), nil
	case *ProjectOAuthMicrosoft:
		secret, err := r.decrypt(c.ClientSecretEnc)
		if err != nil {
			return nil, fmt.Errorf("microsoft client_secret: %w", err)
		}
		return oauth.NewMicrosoft(oauth.MicrosoftConfig{
			ClientID:       c.ClientID,
			ClientSecret:   secret,
			TenantID:       c.TenantID,
			AllowedTenants: c.AllowedTenants,
			IssuerFormat:   c.IssuerFormat,
		}), nil
	case *ProjectOAuthApple:
		key, err := r.decrypt(c.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("apple private_key: %w", err)
		}
		return oauth.NewApple(oauth.AppleConfig{
			ClientID:   c.ClientID,
			TeamID:     c.TeamID,
			KeyID:      c.KeyID,
			PrivateKey: key,
		}), nil
	case *ProjectOAuthGitHub:
		secret, err := r.decrypt(c.ClientSecretEnc)
		if err != nil {
			return nil, fmt.Errorf("github client_secret: %w", err)
		}
		return oauth.NewGitHub(oauth.GitHubConfig{
			ClientID:         c.ClientID,
			ClientSecret:     secret,
			AuthorizationURL: c.AuthorizationURL,
			TokenURL:         c.TokenURL,
			UserURL:          c.UserURL,
			UserMailURL:      c.UserMailURL,
		}), nil
	case *ProjectOAuthOIDC:
		secret, err := r.decrypt(c.ClientSecretEnc)
		if err != nil {
			return nil, fmt.Errorf("oidc client_secret: %w", err)
		}
		return oauth.NewOIDC(oauth.GenericOIDCConfig{
			ProviderKey:  "oidc",
			IssuerURL:    c.Issuer,
			DiscoveryURL: c.DiscoveryURL,
			ClientID:     c.ClientID,
			ClientSecret: secret,
			Scopes:       strings.Fields(c.Scopes),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported oauth provider config %T", raw)
	}
}

// decrypt reverses the at-rest encryption of a per-project secret. A missing
// key is a deployment error: postgres control-plane deployments MUST set
// GATEWAY_PROJECT_SECRETS_KEY (enforced by config.Validate); this guards the
// case a Config was built directly without it.
func (r *OAuthResolver) decrypt(ciphertext string) (string, error) {
	if len(r.secretsKey) == 0 {
		return "", errors.New("GATEWAY_PROJECT_SECRETS_KEY is not configured; cannot decrypt per-project OAuth secrets")
	}
	return secretcrypto.Decrypt(ciphertext, r.secretsKey)
}

// provider returns the configured sub-struct for a provider key (as a pointer,
// so build can type-switch), or ok=false when the project did not configure it.
func (c ProjectOAuthConfig) provider(provider string) (any, bool) {
	switch provider {
	case "google":
		if c.Google != nil {
			return c.Google, true
		}
	case "microsoft":
		if c.Microsoft != nil {
			return c.Microsoft, true
		}
	case "apple":
		if c.Apple != nil {
			return c.Apple, true
		}
	case "github":
		if c.GitHub != nil {
			return c.GitHub, true
		}
	case "oidc":
		if c.OIDC != nil {
			return c.OIDC, true
		}
	}
	return nil, false
}

// hostClient returns the client the project names for provider on host
// (ADR-0019), or ok=false when it names none there.
func (c ProjectOAuthConfig) hostClient(host, provider string) (ProjectOAuthHostClient, bool) {
	if !isOAuthProviderKey(provider) {
		return ProjectOAuthHostClient{}, false // e.g. an env OIDC provider under its own key
	}
	client, ok := c.Hosts[host][provider]
	return client, ok
}

// withHostClient returns a copy of a configured provider (as provider returns
// it) whose client identity is client's, or nil for a type it does not know.
// Apple keeps its key: it signs for any Services ID of its team, so only the
// client id changes.
func withHostClient(base any, client ProjectOAuthHostClient) any {
	switch b := base.(type) {
	case *ProjectOAuthGoogle:
		c := *b
		c.ClientID, c.ClientSecretEnc = client.ClientID, client.ClientSecretEnc
		return &c
	case *ProjectOAuthMicrosoft:
		c := *b
		c.ClientID, c.ClientSecretEnc = client.ClientID, client.ClientSecretEnc
		return &c
	case *ProjectOAuthApple:
		c := *b
		c.ClientID = client.ClientID
		return &c
	case *ProjectOAuthGitHub:
		c := *b
		c.ClientID, c.ClientSecretEnc = client.ClientID, client.ClientSecretEnc
		return &c
	case *ProjectOAuthOIDC:
		c := *b
		c.ClientID, c.ClientSecretEnc = client.ClientID, client.ClientSecretEnc
		return &c
	}
	// A provider type this function does not know: fail closed, since the
	// base client is not registered for the host's callback.
	return nil
}

// callbackHost is the host a host override is keyed by: redirectURI's, in the
// form oauth.hosts keys are stored in (lower-cased, no port, no trailing dot),
// or "" when it has none.
func callbackHost(redirectURI string) string {
	u, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// hasAny reports whether the project configured at least one provider.
func (c ProjectOAuthConfig) hasAny() bool {
	return c.Google != nil || c.Microsoft != nil || c.Apple != nil || c.GitHub != nil || c.OIDC != nil
}

// providers returns the provider keys the project configured, in declaration
// order. The keys are the same ones provider() switches on.
func (c ProjectOAuthConfig) providers() []string {
	var out []string
	for _, p := range []struct {
		key string
		set bool
	}{
		{"google", c.Google != nil},
		{"microsoft", c.Microsoft != nil},
		{"apple", c.Apple != nil},
		{"github", c.GitHub != nil},
		{"oidc", c.OIDC != nil},
	} {
		if p.set {
			out = append(out, p.key)
		}
	}
	return out
}

// providerConfigHash is the cache-key component that changes when a provider's
// config changes, so a config edit rebuilds the Exchanger (and its JWKS cache)
// while steady state reuses it. The encrypted secret is part of the marshalled
// form, so rotating a secret also busts the cache.
func providerConfigHash(raw any) string {
	b, err := json.Marshal(raw)
	if err != nil {
		// Marshalling a plain struct cannot fail; fall back to a constant so a
		// hypothetical failure degrades to "one shared entry" rather than panics.
		return "unhashable"
	}
	return sha256Hex(string(b))
}
