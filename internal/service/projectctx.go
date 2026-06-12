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
	ID             string
	StorageScopeID string
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
