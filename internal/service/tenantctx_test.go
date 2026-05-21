package service

import (
	"context"
	"testing"
)

// TestWithTenantScope_NilNoOp confirms a nil scope leaves the context
// untouched (the mode=single path never installs a scope).
func TestWithTenantScope_NilNoOp(t *testing.T) {
	ctx := context.Background()
	if got := WithTenantScope(ctx, nil); got != ctx {
		t.Fatalf("WithTenantScope(ctx, nil) must return the same context")
	}
	if TenantScopeFromContext(ctx) != nil {
		t.Fatalf("expected no scope on a bare context")
	}
}

// TestWithTenantScope_RoundTrip confirms a scope survives the context.
func TestWithTenantScope_RoundTrip(t *testing.T) {
	repo := newFakeRepo()
	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: "acmecorp", Repo: repo})
	scope := TenantScopeFromContext(ctx)
	if scope == nil {
		t.Fatalf("expected a scope")
	}
	if scope.TenantID != "acmecorp" {
		t.Fatalf("TenantID = %q, want acmecorp", scope.TenantID)
	}
	if scope.Repo != repo {
		t.Fatalf("Repo not threaded through context")
	}
}

// TestServiceAccessors_PreferScope_FallBackToDefault exercises both
// branches of every service's tenantID(ctx)/repo(ctx) accessor: with a
// resolved scope present (mode=multi) it must return the scoped value;
// with no scope (mode=single) it must fall back to the boot-time
// default. These accessors are how the per-request tenant reaches the
// service layer, so both branches are load-bearing.
func TestServiceAccessors_PreferScope_FallBackToDefault(t *testing.T) {
	const (
		defaultTenant  = "system"
		resolvedTenant = "acmecorp"
	)
	defaultRepo := newFakeRepo()
	scopedRepo := newFakeRepo()

	bg := context.Background()
	scoped := WithTenantScope(bg, &TenantScope{TenantID: resolvedTenant, Repo: scopedRepo})

	// tenantID-only accessors (DB-backed services scope by id per call).
	tenantIDOnly := map[string]func(context.Context) string{
		"AdminService":   (&AdminService{defaultTenantID: defaultTenant}).tenantID,
		"GroupService":   (&GroupService{defaultTenantID: defaultTenant}).tenantID,
		"HelpService":    (&HelpService{defaultTenantID: defaultTenant}).tenantID,
		"ProfileService": (&ProfileService{defaultTenantID: defaultTenant}).tenantID,
	}
	for name, fn := range tenantIDOnly {
		if got := fn(bg); got != defaultTenant {
			t.Fatalf("%s.tenantID(no scope) = %q, want %q", name, got, defaultTenant)
		}
		if got := fn(scoped); got != resolvedTenant {
			t.Fatalf("%s.tenantID(scoped) = %q, want %q", name, got, resolvedTenant)
		}
	}

	// Services that also carry a tenant-scoped Repository.
	auth := &AuthService{defaultTenantID: defaultTenant, defaultRepo: defaultRepo}
	idv := &IdentityVerificationService{defaultTenantID: defaultTenant, defaultRepo: defaultRepo}

	repoAccessors := map[string]struct {
		tenantID func(context.Context) string
		repo     func(context.Context) Repository
	}{
		"AuthService":                 {auth.tenantID, auth.repo},
		"IdentityVerificationService": {idv.tenantID, idv.repo},
	}
	for name, a := range repoAccessors {
		if got := a.tenantID(bg); got != defaultTenant {
			t.Fatalf("%s.tenantID(no scope) = %q, want %q", name, got, defaultTenant)
		}
		if got := a.tenantID(scoped); got != resolvedTenant {
			t.Fatalf("%s.tenantID(scoped) = %q, want %q", name, got, resolvedTenant)
		}
		if got := a.repo(bg); got != Repository(defaultRepo) {
			t.Fatalf("%s.repo(no scope) must return the boot-time repo", name)
		}
		if got := a.repo(scoped); got != Repository(scopedRepo) {
			t.Fatalf("%s.repo(scoped) must return the resolved tenant's repo", name)
		}
	}

	// A scope with an empty TenantID / nil Repo must fall back, not
	// return the zero value (defends the && guard in each accessor).
	emptyScope := WithTenantScope(bg, &TenantScope{TenantID: "", Repo: nil})
	if got := auth.tenantID(emptyScope); got != defaultTenant {
		t.Fatalf("empty-scope tenantID = %q, want fallback %q", got, defaultTenant)
	}
	if got := auth.repo(emptyScope); got != Repository(defaultRepo) {
		t.Fatalf("empty-scope repo must fall back to the boot-time repo")
	}
}
