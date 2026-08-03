package service

import "context"

// ProjectScope is the per-request project binding carried in the request
// context by the project-resolution middleware. A Project is the redesign's
// top-level isolation entity (Firebase-project equivalent): it is resolved
// from a request's credential key or its Host header (via an auth-domain),
// ahead of any tenant resolution.
//
// In a zero-config single-project deployment every request resolves to the
// default project, so the scope is always present once the middleware is
// installed; nothing downstream is forced to special-case its absence.
type ProjectScope struct {
	// ProjectID is the resolved control-plane project id.
	ProjectID string

	// StorageScopeID is the physical storage scope the project maps onto.
	// It is distinct from ProjectID (a project is a logical entity that
	// points at a storage scope) and must not be conflated with it.
	StorageScopeID string

	// PrimaryAuthDomain is the project's primary serving hostname, when one
	// is configured. The service builds branded links (email verification,
	// password reset, magic-link, …) from it so a user sees a URL on the
	// product's own domain. Empty when the project has no auth-domain, in
	// which case the service falls back to its configured base URL.
	PrimaryAuthDomain string

	// CORSAllowedOrigins is the project's own browser CORS allow-list,
	// parsed and validated from its config_json. It is layered on top of
	// the global GATEWAY_ALLOWED_ORIGINS floor by the CORS middleware: a
	// request whose Origin is in either set is allowed. Empty when the
	// project configures none, in which case only the global floor applies.
	CORSAllowedOrigins []string

	// Branding is the project's transactional-email branding, parsed from
	// its config_json. Empty fields fall back to the global
	// GATEWAY_EMAIL_BRAND_* defaults so a zero-config project's mail is
	// byte-compatible with today's.
	Branding ProjectBrandingConfig

	// Passkey is the project's WebAuthn relying-party identity, parsed from
	// its config_json. Empty fields fall back to the global GATEWAY_PASSKEY_*
	// values.
	Passkey ProjectPasskeyConfig

	// LoginDefaults is the project-wide login-method policy applied to users
	// with NO claimed tenant, parsed from config_json. It is layered UNDER
	// any tenant LoginPolicy (tenant overrides project overrides global) by
	// the login-path enforcement. The zero value imposes no restriction, so
	// a project that configures none behaves exactly as before.
	LoginDefaults ProjectLoginConfig

	// OAuth is the project's own hosted-flow OAuth providers, parsed from
	// config_json. Each provider present here is built (and its secret
	// decrypted) on demand for this project only. A provider absent here is
	// unavailable to the project, except that the default project additionally
	// falls back to the env-configured GATEWAY_OAUTH_* providers. Empty for a
	// zero-config project, which then behaves exactly as before.
	OAuth ProjectOAuthConfig

	// Access is the project's authentication access policy (mode + optional
	// allowlist), parsed from config_json — or, for the env default project,
	// assembled from GATEWAY_DEFAULT_PROJECT_ACCESS_MODE and stamped on by the
	// project-resolution middleware. It is DEFAULT-DENY: an empty/unset access
	// block (no mode) FAILS CLOSED and denies all authentication. A project is
	// unrestricted only when it explicitly sets mode:open.
	Access ProjectAccessConfig

	// Products is the project's per-product guardrail policy, parsed from
	// config_json and keyed by the product slug a request carries in its
	// X-Product header. It FAILS OPEN (the inverse of Access): an absent
	// products block, an absent slug, or an absent minimum_age_band all mean
	// "no restriction", so a project that configures none behaves exactly as
	// before. The env default project has no config_json and therefore no
	// product policy — gating a product requires a control-plane project.
	Products ProjectProductsConfig
	// Assurance is the project's client-attestation identity (which app
	// builds' hardware attestations it accepts), parsed from config_json.
	// Zero for a project that configures none, in which case only the
	// default project can attest (via the env-configured app identity).
	Assurance ProjectAssuranceConfig

	// Anonymous is the project's anonymous-sign-in policy, parsed from
	// config_json — or, for the env default project, assembled from
	// GATEWAY_ANONYMOUS_* and stamped on by the project-resolution
	// middleware. Zero (disabled) for a project that configures none.
	Anonymous ProjectAnonymousConfig
}

type projectScopeCtxKey struct{}

// WithProjectScope returns a child context carrying scope. The
// project-resolution middleware calls this once it has resolved the
// request's project. A nil scope is a no-op so callers need not branch.
func WithProjectScope(ctx context.Context, scope *ProjectScope) context.Context {
	if scope == nil {
		return ctx
	}
	return context.WithValue(ctx, projectScopeCtxKey{}, scope)
}

// ProjectScopeFromContext returns the per-request project scope, or nil
// when none was injected (any code path that runs before resolution, or a
// deployment whose driver has no control plane).
func ProjectScopeFromContext(ctx context.Context) *ProjectScope {
	scope, _ := ctx.Value(projectScopeCtxKey{}).(*ProjectScope)
	return scope
}

// ResolvedProject is what a ProjectResolver returns: the minimal project
// identity the middleware needs to build a ProjectScope. It is a
// driver-agnostic value so the resolver contract does not leak a concrete
// store type into the middleware or app wiring.
type ResolvedProject struct {
	ID                 string
	StorageScopeID     string
	PrimaryAuthDomain  string
	CORSAllowedOrigins []string
	Branding           ProjectBrandingConfig
	Passkey            ProjectPasskeyConfig
	LoginDefaults      ProjectLoginConfig
	OAuth              ProjectOAuthConfig
	Access             ProjectAccessConfig
	Products           ProjectProductsConfig
	Assurance          ProjectAssuranceConfig
	Anonymous          ProjectAnonymousConfig
}

// ProjectResolver resolves a request's project from the credentials it
// carries. It is implemented by the control-plane store (postgres only);
// deployments whose driver has no control plane pass a nil resolver and the
// middleware pins every request to the default project.
//
// Both methods return (nil, nil) for a clean miss — an unknown key or an
// unmapped hostname — and a non-nil error only for an infrastructure
// failure. A resolver must NOT resolve a suspended project or a revoked
// credential; those are misses.
type ProjectResolver interface {
	// ResolveByCredential resolves the active project a credential public
	// id belongs to.
	ResolveByCredential(ctx context.Context, publicID string) (*ResolvedProject, error)
	// ResolveByHostname resolves the active project a serving hostname maps
	// onto (case-insensitive).
	ResolveByHostname(ctx context.Context, hostname string) (*ResolvedProject, error)
}
