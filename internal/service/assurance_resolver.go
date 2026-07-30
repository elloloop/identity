package service

import (
	"context"
	"errors"
	"sync"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/assurance/appattest"
	"github.com/elloloop/identity/pkg/assurance/playintegrity"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// AssuranceProviders is the set of attestation verifiers available to
// one project. A nil field means that platform is not configured for
// the project.
type AssuranceProviders struct {
	AppAttest     *appattest.Verifier
	PlayIntegrity *playintegrity.Verifier
}

// AssuranceResolver resolves the attestation verifiers for a request's
// project, mirroring OAuthResolver: per-project verifiers are built
// lazily from the project's config_json assurance block (decrypting the
// Play service-account key with secretsKey) and cached per config hash;
// the default project falls back to the env-built defaults. A failed
// build is cached negatively for its hash so a persistently
// misconfigured project neither rebuilds nor re-logs on every request.
type AssuranceResolver struct {
	defaultProjectID string
	defaults         AssuranceProviders
	secretsKey       []byte
	logger           *zap.Logger

	mu sync.RWMutex
	// cache holds at most ONE entry per project id; a config change (new
	// hash) overwrites the superseded entry.
	cache map[string]assuranceCacheEntry
}

// assuranceCacheEntry is one resolver cache slot; providers may hold nil
// fields when that platform's build failed for this hash.
type assuranceCacheEntry struct {
	hash      string
	providers AssuranceProviders
}

// NewAssuranceResolver returns a resolver whose default project serves
// the env-built defaults. secretsKey may be empty; projects storing an
// encrypted service-account key then fail Android builds with a clear
// log line.
func NewAssuranceResolver(defaultProjectID string, defaults AssuranceProviders, secretsKey []byte, logger *zap.Logger) *AssuranceResolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AssuranceResolver{
		defaultProjectID: defaultProjectID,
		defaults:         defaults,
		secretsKey:       secretsKey,
		logger:           logger,
		cache:            make(map[string]assuranceCacheEntry),
	}
}

// For returns the providers for the request's resolved project.
//
// Precedence mirrors OAuthResolver.exchangerFor: a project's OWN
// config_json assurance block always wins — including for the default
// project, so a stored block is never inert. Only when a project
// configures nothing does the default project fall back to the
// env-configured app identity; a non-default project inherits nothing
// (isolation: one product's attestation must not satisfy another's).
func (r *AssuranceResolver) For(ctx context.Context) AssuranceProviders {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || scope.ProjectID == "" {
		return r.defaults
	}
	if scope.Assurance.isZero() {
		if scope.ProjectID == r.defaultProjectID {
			return r.defaults
		}
		return AssuranceProviders{}
	}
	hash := scope.Assurance.hash()

	r.mu.RLock()
	entry, ok := r.cache[scope.ProjectID]
	r.mu.RUnlock()
	if ok && entry.hash == hash {
		return entry.providers
	}

	// Build under the write lock and re-check: a cold start that fans out
	// across concurrent requests would otherwise build (and, for Android,
	// perform a Google service-account exchange) once per racer.
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.cache[scope.ProjectID]; ok && entry.hash == hash {
		return entry.providers
	}
	built := r.build(scope.ProjectID, scope.Assurance)
	r.cache[scope.ProjectID] = assuranceCacheEntry{hash: hash, providers: built}
	return built
}

// build constructs the verifiers for one project's assurance block.
// Platform builds fail independently: a bad Android key does not take
// down a working iOS config.
func (r *AssuranceResolver) build(projectID string, cfg ProjectAssuranceConfig) AssuranceProviders {
	var out AssuranceProviders
	if ios := cfg.IOS; ios != nil {
		v, err := appattest.New(appattest.Config{
			TeamID:   ios.TeamID,
			BundleID: ios.BundleID,
			Env:      ios.Env,
		})
		if err != nil {
			r.logger.Error("assurance_ios_build_failed",
				zap.String("project_id", projectID), zap.Error(err))
		} else {
			out.AppAttest = v
		}
	}
	if and := cfg.Android; and != nil {
		saKey, err := r.decrypt(and.ServiceAccountKeyEnc)
		if err != nil {
			r.logger.Error("assurance_android_key_decrypt_failed",
				zap.String("project_id", projectID), zap.Error(err))
			return out
		}
		v, err := playintegrity.New(playintegrity.Config{
			PackageName:        and.PackageName,
			CertSHA256Digests:  and.CertSHA256Digests,
			ServiceAccountJSON: saKey,
		})
		if err != nil {
			r.logger.Error("assurance_android_build_failed",
				zap.String("project_id", projectID), zap.Error(err))
		} else {
			out.PlayIntegrity = v
		}
	}
	return out
}

// decrypt unwraps a *_enc value with the deployment's project-secrets
// key. An unset key is by far the likeliest misconfiguration, so it is
// named explicitly rather than surfacing as a raw secretcrypto error.
func (r *AssuranceResolver) decrypt(enc string) ([]byte, error) {
	if len(r.secretsKey) == 0 {
		return nil, errors.New("GATEWAY_PROJECT_SECRETS_KEY is not configured; per-project assurance secrets cannot be decrypted")
	}
	plain, err := secretcrypto.Decrypt(enc, r.secretsKey)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}
