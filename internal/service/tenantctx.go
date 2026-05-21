package service

import "context"

// TenantScope is the per-request tenant binding carried in the request
// context by the tenant-resolution middleware in mode=multi. It pairs
// the resolved tenant id with a Repository scoped to that tenant so the
// service layer can serve a request against the caller's tenant without
// re-binding the singleton services per request.
//
// In mode=single no TenantScope is ever placed in the context: services
// fall back to their boot-time DefaultTenantID and boot-time Repository,
// keeping the single-tenant path a clean constant (no host/JWT
// inspection, no per-request lookup). See docs/IDENTITY.md decision log.
type TenantScope struct {
	// TenantID is the resolved tenant (the organisation slug, which is
	// 1:1 with the tenant-shard-db tenant — decision log §2).
	TenantID string

	// Repo is a Repository scoped to TenantID. May be nil for services
	// that only use the DB interface (which takes the tenant id per
	// call) — those read TenantID alone.
	Repo Repository
}

type tenantScopeCtxKey struct{}

// WithTenantScope returns a child context carrying scope. The
// tenant-resolution middleware calls this after authenticating the
// request and verifying tenant membership.
func WithTenantScope(ctx context.Context, scope *TenantScope) context.Context {
	if scope == nil {
		return ctx
	}
	return context.WithValue(ctx, tenantScopeCtxKey{}, scope)
}

// TenantScopeFromContext returns the per-request tenant scope, or nil
// when none was injected (the mode=single path, and any mode=multi code
// path that runs before resolution).
func TenantScopeFromContext(ctx context.Context) *TenantScope {
	scope, _ := ctx.Value(tenantScopeCtxKey{}).(*TenantScope)
	return scope
}
