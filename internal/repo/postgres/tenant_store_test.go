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
	return NewProjectStore(repo, true, nil), NewTenantStore(repo), NewDomainStore(repo)
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
	runContestedDomainClaims(t, dsn)
}

// runTenantDomainSmoke asserts tenant + domain CRUD, status transitions,
// case-insensitive domain lookup, the domain uniqueness rules (once per
// tenant, one verified row per project), project-scoping (a row in project
// A is invisible from project B), and argument validation.
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

	status, err := tenants.GetTenantStatus(ctx, projA, tenID)
	require.NoError(t, err)
	require.Equal(t, service.TenantStatusClaimed, status)
	for _, key := range [][2]string{{projB, tenID}, {projA, "no-such"}, {"", tenID}, {projA, ""}} {
		status, err = tenants.GetTenantStatus(ctx, key[0], key[1])
		require.NoError(t, err)
		require.Empty(t, status, "no status for %v", key)
	}

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

	require.False(t, dom.LegacyTXTChallenge, "a new registration never takes the legacy challenge")

	// A tenant holds a domain once.
	_, err = domains.CreateDomain(ctx, &service.Domain{
		ProjectID: projA, TenantID: tenID, Domain: "ACME.com",
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "a tenant registering its own domain again must conflict")

	// Another tenant of the project cannot register a domain that is verified.
	other, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projA, Name: "Other"})
	require.NoError(t, err)
	_, err = domains.CreateDomain(ctx, &service.Domain{ProjectID: projA, TenantID: other, Domain: "acme.com"})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "a verified domain admits no other tenant's claim")

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

// runContestedDomainClaims asserts that tenants may contest a domain until
// one verifies it: unproven claims coexist, the by-name lookup prefers the
// verified row and otherwise the oldest claim, and once one claim is
// verified no other can be verified or made.
func runContestedDomainClaims(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, domains := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-contest", Name: "Contest"})
	require.NoError(t, err)

	newTenant := func(name string) string {
		t.Helper()
		id, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Name: name, Status: service.TenantStatusClaimed})
		require.NoError(t, err)
		return id
	}
	squatter, owner, late := newTenant("Squatter"), newTenant("Owner"), newTenant("Late")

	squatID, err := domains.CreateDomain(ctx, &service.Domain{ProjectID: proj, TenantID: squatter, Domain: "acme.com"})
	require.NoError(t, err)
	ownerID, err := domains.CreateDomain(ctx, &service.Domain{ProjectID: proj, TenantID: owner, Domain: "ACME.com"})
	require.NoError(t, err, "a pending claim does not keep another tenant from registering the domain")

	byName, err := domains.GetDomainByName(ctx, proj, "acme.com")
	require.NoError(t, err)
	require.Equal(t, squatID, byName.ID, "with no verified row the oldest claim is returned")

	require.NoError(t, domains.SetDomainStatus(ctx, proj, ownerID, service.DomainStatusVerified, 0))
	byName, err = domains.GetDomainByName(ctx, proj, "acme.com")
	require.NoError(t, err)
	require.Equal(t, ownerID, byName.ID, "the verified row wins the by-name lookup")
	require.Equal(t, owner, byName.TenantID)

	err = domains.SetDomainStatus(ctx, proj, squatID, service.DomainStatusVerified, 0)
	require.ErrorIs(t, err, service.ErrAlreadyExists, "a domain is verified by one tenant at a time")
	squat, err := domains.GetDomain(ctx, proj, squatID)
	require.NoError(t, err)
	require.Equal(t, service.DomainStatusPending, squat.Status, "the refused verify changed nothing")
	require.NoError(t, domains.SetDomainStatus(ctx, proj, squatID, service.DomainStatusFailed, 0),
		"an unproven claim may still fail")

	_, err = domains.CreateDomain(ctx, &service.Domain{ProjectID: proj, TenantID: late, Domain: "acme.com"})
	require.ErrorIs(t, err, service.ErrAlreadyExists)
	_, err = domains.CreateDomain(ctx, &service.Domain{
		ProjectID: proj, TenantID: late, Domain: "acme.com", Status: service.DomainStatusVerified,
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "nor may a second verified row be inserted outright")
}
