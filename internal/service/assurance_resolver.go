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
// config_json assurance block wins — including for the default project,
// so a stored block is never shadowed. Only when a project configures
// nothing does the default project fall back to the env-configured app
// identity; a non-default project inherits nothing (isolation: one
// product's attestation must not satisfy another's).
//
// Note the scope must actually CARRY the block: the zero-config
// default-project pin (internal/middleware/project.go) stamps no
// config_json, so those requests always take the env defaults. A stored
// block on the default project applies to requests that resolve it
// explicitly (X-Project-Key or a mapped auth-domain host).
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

	// Build OUTSIDE the lock. The build is pure CPU — a JSON unmarshal and a
	// PKCS#8 parse; the Google service-account exchange happens lazily
	// inside Verify, not here — but it is still a cold-start cost, and
	// holding the write lock across it blocks resolution for every OTHER
	// project, cache hits included. Racing builds for the same project are
	// wasted work, not a correctness problem: the build is deterministic in
	// (projectID, config), so whichever result is published is the same one.
	// Mirrors OAuthResolver.buildProject.
	built := r.build(scope.ProjectID, scope.Assurance)
	// The default project falls back PER PLATFORM to the env identity for an
	// arm its block does not configure. Without this the same project
	// resolves to different arms depending on how the request arrived: the
	// zero-config pin stamps no config_json and yields the full env
	// defaults, while an X-Project-Key-resolved request carrying an
	// iOS-only block would silently lose Android.
	if scope.ProjectID == r.defaultProjectID {
		if built.AppAttest == nil {
			built.AppAttest = r.defaults.AppAttest
		}
		if built.PlayIntegrity == nil {
			built.PlayIntegrity = r.defaults.PlayIntegrity
		}
	}

	// Take the write lock only to publish, and re-check: a racer may have
	// published an entry for this same hash while we were building. Reusing
	// theirs keeps one live verifier set per (project, config) rather than
	// leaving callers holding two.
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.cache[scope.ProjectID]; ok && entry.hash == hash {
		return entry.providers
	}
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
