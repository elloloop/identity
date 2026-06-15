package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// newTenantDomainStores migrates a Postgres at dsn and returns the
// control-plane project store plus the tenant and domain stores, all
// sharing one repository/pool. The owning *pgRepository is closed on
// cleanup. Shared by the env-driven smoke test and the container test.
func newTenantDomainStores(ctx context.Context, t *testing.T, dsn string) (*ProjectStore, *TenantStore, *DomainStore) {
	t.Helper()
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	return NewProjectStore(repo), NewTenantStore(repo), NewDomainStore(repo)
}

// TestTenantDomainStore_Smoke runs the tenant + domain store round-trip
// against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN (CI's
// coverage job), skipping when unset. The dockerpostgres container test
// runs the same body locally.
func TestTenantDomainStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping tenant/domain store smoke test")
	}
	runTenantDomainSmoke(t, dsn)
}

// runTenantDomainSmoke asserts tenant + domain CRUD, status transitions,
// case-insensitive domain lookup, the one-tenant-per-domain uniqueness
// rule, project-scoping (a row in project A is invisible from project B),
// and argument validation.
func runTenantDomainSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, domains := newTenantDomainStores(ctx, t, dsn)

	// Two projects, to prove project-scoping.
	projA, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-A", Name: "A"})
	require.NoError(t, err)
	projB, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-B", Name: "B"})
	require.NoError(t, err)

	// ── tenant round-trip ───────────────────────────────────────────
	tenID, err := tenants.CreateTenant(ctx, &service.Tenant{
		ProjectID:     projA,
		Name:          "Acme",
		PrimaryDomain: "acme.com",
	})
	require.NoError(t, err)
	require.NotEmpty(t, tenID)

	ten, err := tenants.GetTenant(ctx, projA, tenID)
	require.NoError(t, err)
	require.NotNil(t, ten)
	require.Equal(t, "Acme", ten.Name)
	require.Equal(t, "acme.com", ten.PrimaryDomain)
	require.Equal(t, service.TenantStatusLatent, ten.Status, "new tenant defaults to latent")
	require.NotZero(t, ten.CreatedAtMs)
	require.Equal(t, ten.CreatedAtMs, ten.UpdatedAtMs)

	// Resolve by primary domain (case-insensitive).
	byDom, err := tenants.GetTenantByPrimaryDomain(ctx, projA, "ACME.COM")
	require.NoError(t, err)
	require.NotNil(t, byDom)
	require.Equal(t, tenID, byDom.ID)

	// Claim it.
	require.NoError(t, tenants.SetTenantStatus(ctx, projA, tenID, service.TenantStatusClaimed))
	ten, err = tenants.GetTenant(ctx, projA, tenID)
	require.NoError(t, err)
	require.Equal(t, service.TenantStatusClaimed, ten.Status)
	require.GreaterOrEqual(t, ten.UpdatedAtMs, ten.CreatedAtMs)

	// Project-scoping: project B cannot see project A's tenant.
	cross, err := tenants.GetTenant(ctx, projB, tenID)
	require.NoError(t, err)
	require.Nil(t, cross, "a tenant must not be visible from another project")
	crossDom, err := tenants.GetTenantByPrimaryDomain(ctx, projB, "acme.com")
	require.NoError(t, err)
	require.Nil(t, crossDom)

	list, err := tenants.ListTenants(ctx, projA)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, tenID, list[0].ID)
	listB, err := tenants.ListTenants(ctx, projB)
	require.NoError(t, err)
	require.Empty(t, listB, "project B has no tenants yet")

	// Misses + validation.
	miss, err := tenants.GetTenant(ctx, projA, "no-such")
	require.NoError(t, err)
	require.Nil(t, miss)
	_, err = tenants.CreateTenant(ctx, &service.Tenant{})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	require.ErrorIs(t, tenants.SetTenantStatus(ctx, "", tenID, service.TenantStatusClaimed), service.ErrInvalidArgument)
	require.ErrorIs(t, tenants.SetTenantStatus(ctx, projA, "", service.TenantStatusClaimed), service.ErrInvalidArgument)
	// Setting status on an unknown (but well-formed) id is a silent no-op.
	require.NoError(t, tenants.SetTenantStatus(ctx, projA, "no-such", service.TenantStatusSuspended))

	// ── domain round-trip ───────────────────────────────────────────
	domID, err := domains.CreateDomain(ctx, &service.Domain{
		ProjectID: projA,
		TenantID:  tenID,
		Domain:    "acme.com",
	})
	require.NoError(t, err)
	require.NotEmpty(t, domID)

	dom, err := domains.GetDomain(ctx, projA, domID)
	require.NoError(t, err)
	require.NotNil(t, dom)
	require.Equal(t, tenID, dom.TenantID)
	require.Equal(t, service.DomainVerificationDNSTXT, dom.VerificationMethod, "default method")
	require.Equal(t, service.DomainStatusPending, dom.Status, "default status")
	require.Zero(t, dom.VerifiedAtMs)

	// Case-insensitive name lookup.
	byName, err := domains.GetDomainByName(ctx, projA, "ACME.COM")
	require.NoError(t, err)
	require.NotNil(t, byName)
	require.Equal(t, domID, byName.ID)

	// Verify it.
	require.NoError(t, domains.SetDomainStatus(ctx, projA, domID, service.DomainStatusVerified, 0))
	dom, err = domains.GetDomain(ctx, projA, domID)
	require.NoError(t, err)
	require.Equal(t, service.DomainStatusVerified, dom.Status)
	require.NotZero(t, dom.VerifiedAtMs, "verify stamps verified_at_ms")

	// One tenant per domain within a project: duplicate (project, domain).
	_, err = domains.CreateDomain(ctx, &service.Domain{
		ProjectID: projA, TenantID: tenID, Domain: "ACME.com",
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "duplicate domain in a project must conflict")

	// The same domain string IS allowed in a different project.
	tenB, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projB, PrimaryDomain: "acme.com"})
	require.NoError(t, err)
	_, err = domains.CreateDomain(ctx, &service.Domain{ProjectID: projB, TenantID: tenB, Domain: "acme.com"})
	require.NoError(t, err, "the same domain is allowed once per project")

	// Project-scoping on domains.
	crossD, err := domains.GetDomainByName(ctx, projB, "acme.com")
	require.NoError(t, err)
	require.NotNil(t, crossD)
	require.NotEqual(t, domID, crossD.ID, "each project has its own domain row")

	byTenant, err := domains.ListDomainsByTenant(ctx, projA, tenID)
	require.NoError(t, err)
	require.Len(t, byTenant, 1)
	require.Equal(t, domID, byTenant[0].ID)

	// Misses + validation.
	dMiss, err := domains.GetDomainByName(ctx, projA, "unknown.test")
	require.NoError(t, err)
	require.Nil(t, dMiss)
	_, err = domains.CreateDomain(ctx, &service.Domain{ProjectID: projA, TenantID: tenID})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = domains.CreateDomain(ctx, &service.Domain{ProjectID: projA, Domain: "x.com"})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	require.ErrorIs(t, domains.SetDomainStatus(ctx, "", domID, service.DomainStatusFailed, 0), service.ErrInvalidArgument)
	require.NoError(t, domains.SetDomainStatus(ctx, projA, "no-such", service.DomainStatusFailed, 0))
}
