package service

import "context"

// requestProjectID resolves the project a request operates under: the
// per-request ProjectScope when the project-resolution middleware injected
// one (ADR-0002), else the service's boot-default project. This single
// value drives BOTH the WithProject binding (postgres / memory
// Repository) and the per-call tenant argument the graph DB transport
// partitions on, so every data-plane read/write is filtered by the
// resolved project.
func requestProjectID(ctx context.Context, defaultProjectID string) string {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.ProjectID != "" {
		return scope.ProjectID
	}
	return defaultProjectID
}

// scopedRepository returns defaultRepo bound to the request's project. The
// mandatory `WHERE project_id = $1` predicate is enforced inside the returned
// repository.
func scopedRepository(ctx context.Context, defaultRepo Repository, defaultProjectID string) Repository {
	if defaultRepo == nil {
		return nil
	}
	return defaultRepo.WithProject(requestProjectID(ctx, defaultProjectID))
}

// scopedDB returns bootDB bound to the request's project. The postgres DB
// is the same concrete type as its Repository (it ignores the per-call
// tenant argument and filters on its bound project), so it is rebound via
// WithProject and asserted back to DB. A DB that is not also a Repository —
// a graph transport partitioning on the per-call tenant argument every method
// already takes — needs no rebinding and is returned unchanged.
func scopedDB(ctx context.Context, bootDB DB, defaultProjectID string) DB {
	if bootDB == nil {
		return nil
	}
	scoper, ok := bootDB.(Repository)
	if !ok {
		return bootDB
	}
	if scoped, ok := scoper.WithProject(requestProjectID(ctx, defaultProjectID)).(DB); ok {
		return scoped
	}
	return bootDB
}

// ScopedDB resolves a request's project from ctx and returns bootDB bound to
// that project together with the resolved project id. It is the exported pair
// of scopedDB + requestProjectID, wired by internal/app into the audit logger
// so an audit write lands under the SAME project the request resolved to
// (ADR-0002): the project id partitions the graph transport (which keys on the
// per-call tenant argument every method already takes), and the returned DB is
// the project-bound postgres writer (which ignores that argument and filters on
// its bound project). Reads via ProfileService.ListAuditEvents resolve the
// project identically, so writes and reads round-trip under one project.
func ScopedDB(ctx context.Context, bootDB DB, defaultProjectID string) (DB, string) {
	return scopedDB(ctx, bootDB, defaultProjectID), requestProjectID(ctx, defaultProjectID)
}
