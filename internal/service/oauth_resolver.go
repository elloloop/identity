package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
//  3. else — a non-default project with no config for P — P is unavailable.
//
// Building an Exchanger creates a JWKS/discovery cache, so instances are cached
// keyed by (projectID, provider, configHash): a config change rebuilds, steady
// state reuses the cache.
type OAuthResolver struct {
	defaultProjectID string
	defaultRegistry  *oauth.Registry
	logger           *zap.Logger

	// secretsKey decrypts per-project provider secrets at rest (AES-256-GCM).
	// Empty until wiring calls withSecrets; when empty, a project that stores
	// encrypted provider secrets cannot be built (a clear error is logged).
	secretsKey []byte
	// wrap decorates a freshly-built per-project Exchanger (observability
	// spans). The default project's registry entries are wrapped by app wiring;
	// this wraps the per-project ones identically. nil leaves them unwrapped.
	wrap func(provider string, e oauth.Exchanger) oauth.Exchanger

	mu sync.RWMutex
	// cache holds at most ONE entry per (projectID, provider): a config change
	// (new hash) overwrites the superseded entry rather than accumulating. An
	// entry with a nil exchanger is a NEGATIVE result (the build failed for that
	// hash), cached so a persistently-misconfigured project neither rebuilds nor
	// re-logs on every login; a genuinely fixed config (new hash) retries.
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
func newOAuthResolver(defaultProjectID string, defaultRegistry *oauth.Registry, logger *zap.Logger) *OAuthResolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &OAuthResolver{
		defaultProjectID: defaultProjectID,
		defaultRegistry:  defaultRegistry,
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
		if r.isNonDefaultProject(scope.ProjectID) {
			return false
		}
	}
	return r.defaultRegistry.Len() > 0
}

// exchangerFor returns the Exchanger for the request's project and provider,
// or ok=false when the provider is not available for that project (an
// unconfigured provider, a non-default project without it, or a build failure).
// provider must already be lower-cased/trimmed by the caller.
func (r *OAuthResolver) exchangerFor(ctx context.Context, provider string) (oauth.Exchanger, bool) {
	if r == nil {
		return nil, false
	}
	scope := ProjectScopeFromContext(ctx)
	if scope != nil {
		if present, built := r.buildProject(scope.ProjectID, provider, scope.OAuth); present {
			// present with a nil Exchanger means the project configured this
			// provider but it could not be built (bad secret / config). Project
			// config wins, so we do NOT fall through to env — the provider is
			// unavailable for this request.
			return built, built != nil
		}
		// The provider is not in the project's config. Isolation: a non-default
		// project never inherits the env (default-project) providers.
		if r.isNonDefaultProject(scope.ProjectID) {
			return nil, false
		}
	}
	return r.defaultRegistry.Get(provider)
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
	hash := providerConfigHash(raw)
	// One slot per (projectID, provider) — a config change overwrites it.
	key := projectID + "\x00" + provider

	r.mu.RLock()
	entry, hit := r.cache[key]
	r.mu.RUnlock()
	if hit && entry.hash == hash {
		// Hit for the current config — positive OR negative (nil exchanger).
		return true, entry.exchanger
	}

	built, err := r.build(provider, raw)
	if err != nil {
		// Cache the negative result under this hash so the same broken config
		// neither rebuilds nor re-logs on every login; a fixed config (new
		// hash) misses this entry and retries. built stays nil.
		r.logger.Warn("oauth_project_provider_build_failed",
			zap.String("project_id", projectID),
			zap.String("provider", provider),
			zap.Error(err))
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
	return true, built
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
	case "oidc":
		if c.OIDC != nil {
			return c.OIDC, true
		}
	}
	return nil, false
}

// hasAny reports whether the project configured at least one provider.
func (c ProjectOAuthConfig) hasAny() bool {
	return c.Google != nil || c.Microsoft != nil || c.Apple != nil || c.OIDC != nil
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
