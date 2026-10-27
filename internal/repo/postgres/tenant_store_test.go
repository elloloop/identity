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
	claimed, err := tenants.SetTenantStatus(ctx, projA, tenID, service.TenantStatusLatent, service.TenantStatusClaimed)
	require.NoError(t, err)
	require.True(t, claimed)
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

	list, err := tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: projA, Limit: 100})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, tenID, list[0].ID)

	listB, err := tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: projB, Limit: 100})
	require.NoError(t, err)
	require.Empty(t, listB, "project B has no tenants yet")

	// Misses + validation.
	miss, err := tenants.GetTenant(ctx, projA, "no-such")
	require.NoError(t, err)
	require.Nil(t, miss)
	_, err = tenants.CreateTenant(ctx, &service.Tenant{})
	require.ErrorIs(t, err, service.ErrInvalidArgument)

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

	// The verified lookup passes over an unproven claim.
	byName, err := domains.GetVerifiedDomain(ctx, projA, "acme.com")
	require.NoError(t, err)
	require.Nil(t, byName, "a pending claim is not a verified domain")

	// Verify it.
	require.NoError(t, domains.SetDomainStatus(ctx, projA, domID, service.DomainStatusVerified, 0))
	dom, err = domains.GetDomain(ctx, projA, domID)
	require.NoError(t, err)
	require.Equal(t, service.DomainStatusVerified, dom.Status)
	require.NotZero(t, dom.VerifiedAtMs, "verify stamps verified_at_ms")

	// Writing the status it already holds changes nothing, not even the stamp.
	require.NoError(t, domains.SetDomainStatus(ctx, projA, domID, service.DomainStatusVerified, dom.VerifiedAtMs+1000))
	again, err := domains.GetDomain(ctx, projA, domID)
	require.NoError(t, err)
	require.Equal(t, dom.VerifiedAtMs, again.VerifiedAtMs, "a no-op verify keeps the first stamp")

	// Case-insensitive verified lookup.
	byName, err = domains.GetVerifiedDomain(ctx, projA, "ACME.COM")
	require.NoError(t, err)
	require.NotNil(t, byName)
	require.Equal(t, domID, byName.ID)

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
	crossID, err := domains.CreateDomain(ctx, &service.Domain{ProjectID: projB, TenantID: tenB, Domain: "acme.com"})
	require.NoError(t, err, "the same domain is allowed once per project")
	require.NoError(t, domains.SetDomainStatus(ctx, projB, crossID, service.DomainStatusVerified, 0),
		"a domain verified in one project does not block verifying it in another")

	// Project-scoping on domains.
	crossD, err := domains.GetVerifiedDomain(ctx, projB, "acme.com")
	require.NoError(t, err)
	require.NotNil(t, crossD)
	require.NotEqual(t, domID, crossD.ID, "each project has its own domain row")
	require.Equal(t, crossID, crossD.ID)

	byTenant, err := domains.ListDomainsByTenant(ctx, projA, tenID)
	require.NoError(t, err)
	require.Len(t, byTenant, 1)
	require.Equal(t, domID, byTenant[0].ID)

	// Misses + validation.
	dMiss, err := domains.GetVerifiedDomain(ctx, projA, "unknown.test")
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
// one verifies it: unproven claims coexist, the verified lookup answers only
// the verified row, and once one claim is verified no other can be verified
// or made.
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

	byName, err := domains.GetVerifiedDomain(ctx, proj, "acme.com")
	require.NoError(t, err)
	require.Nil(t, byName, "with no verified row there is no verified domain, however old a claim")

	require.NoError(t, domains.SetDomainStatus(ctx, proj, ownerID, service.DomainStatusVerified, 0))
	byName, err = domains.GetVerifiedDomain(ctx, proj, "acme.com")
	require.NoError(t, err)
	require.NotNil(t, byName)
	require.Equal(t, ownerID, byName.ID, "the verified row answers the lookup")
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

// TestDomainStore_RecordDomainAttempt: a tenant's attempts are capped in a
// window, each tenant has its own budget, older attempts are pruned and stop
// counting, and racing attempts never pass the cap.
func TestDomainStore_RecordDomainAttempt(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping domain attempt test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, domains := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-attempts", Name: "Attempts"})
	require.NoError(t, err)
	newTenant := func() string {
		t.Helper()
		id, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Status: service.TenantStatusClaimed})
		require.NoError(t, err)
		return id
	}
	tenant, other := newTenant(), newTenant()
	rows := func(tenantID string) int {
		t.Helper()
		var n int
		require.NoError(t, domains.pool.QueryRow(ctx,
			`SELECT count(*) FROM domain_attempts WHERE project_id=$1 AND tenant_id=$2`, proj, tenantID).Scan(&n))
		return n
	}

	now := nowMs()
	hour := int64(3_600_000)
	attempt := func(tenantID string, at, windowStart int64, max int) error {
		t.Helper()
		return domains.RecordDomainAttempt(ctx, service.DomainAttempt{
			ProjectID: proj, TenantID: tenantID, AtMs: at, MaxPerWindow: max, WindowStartMs: windowStart,
		})
	}

	require.NoError(t, attempt(tenant, now-2*hour, now-3*hour, 2))
	require.NoError(t, attempt(tenant, now, now-3*hour, 2))
	require.ErrorIs(t, attempt(tenant, now, now-3*hour, 2), service.ErrDomainAttemptsLimited)
	require.Equal(t, 2, rows(tenant), "a refused attempt writes nothing")
	require.NoError(t, attempt(other, now, now-3*hour, 2), "each tenant has its own budget")

	require.NoError(t, attempt(tenant, now, now-hour, 2), "an attempt before the window does not count")
	require.Equal(t, 2, rows(tenant), "and is pruned as the next is recorded")
	require.NoError(t, attempt(tenant, 0, now-hour, 3), "an unset time is now")

	require.ErrorIs(t, attempt("", now, 0, 1), service.ErrInvalidArgument)
	require.ErrorIs(t, attempt(tenant, now, 0, 0), service.ErrInvalidArgument, "an attempt must be given a cap")

	const racers, limit = 8, 3
	fresh := newTenant()
	errs := make(chan error, racers)
	for range racers {
		go func() { errs <- attempt(fresh, nowMs(), now-hour, limit) }()
	}
	refused := 0
	for range racers {
		if err := <-errs; err != nil {
			require.ErrorIs(t, err, service.ErrDomainAttemptsLimited)
			refused++
		}
	}
	require.Equal(t, racers-limit, refused)
	require.Equal(t, limit, rows(fresh))
}

// suspendTenant moves a tenant, in whatever status it is, to suspended.
func suspendTenant(ctx context.Context, t *testing.T, ts *TenantStore, projectID, tenantID string) {
	t.Helper()
	status, err := ts.GetTenantStatus(ctx, projectID, tenantID)
	require.NoError(t, err)
	moved, err := ts.SetTenantStatus(ctx, projectID, tenantID, status, service.TenantStatusSuspended)
	require.NoError(t, err)
	require.True(t, moved, "suspend %s from %q", tenantID, status)
}

// TestTenantStore_SetTenantStatusComparesAndSets: a status change compares
// and sets in one statement, so a tenant suspended between a caller's read
// and a claim stays suspended, and a tenant claimed or restored meanwhile is
// not moved by a change made from the status it left.
func TestTenantStore_SetTenantStatusComparesAndSets(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping tenant status test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, _ := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-claim", Name: "Claim"})
	require.NoError(t, err)
	status := func(id string) string {
		t.Helper()
		got, err := tenants.GetTenantStatus(ctx, proj, id)
		require.NoError(t, err)
		return got
	}
	move := func(id, from, to string) bool {
		t.Helper()
		moved, err := tenants.SetTenantStatus(ctx, proj, id, from, to)
		require.NoError(t, err)
		return moved
	}

	latent, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Status: service.TenantStatusLatent, UpdatedAtMs: 1})
	require.NoError(t, err)
	require.True(t, move(latent, service.TenantStatusLatent, service.TenantStatusClaimed))
	require.Equal(t, service.TenantStatusClaimed, status(latent))
	moved, err := tenants.GetTenant(ctx, proj, latent)
	require.NoError(t, err)
	require.Greater(t, moved.UpdatedAtMs, int64(1), "a move stamps updated_at_ms")

	suspended, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Status: service.TenantStatusSuspended})
	require.NoError(t, err)
	require.False(t, move(suspended, service.TenantStatusLatent, service.TenantStatusClaimed))
	require.Equal(t, service.TenantStatusSuspended, status(suspended), "a suspension is never undone by a claim")

	require.True(t, move(latent, service.TenantStatusClaimed, service.TenantStatusSuspended))
	require.False(t, move(latent, service.TenantStatusClaimed, service.TenantStatusSuspended), "a second suspension finds nothing to move")
	require.True(t, move(latent, service.TenantStatusSuspended, service.TenantStatusClaimed))
	require.Equal(t, service.TenantStatusClaimed, status(latent))

	require.False(t, move("no-such", service.TenantStatusClaimed, service.TenantStatusSuspended))
	other, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-claim-other", Name: "Other"})
	require.NoError(t, err)
	movedElsewhere, err := tenants.SetTenantStatus(ctx, other, latent, service.TenantStatusClaimed, service.TenantStatusSuspended)
	require.NoError(t, err)
	require.False(t, movedElsewhere, "another project cannot move the tenant")
	require.Equal(t, service.TenantStatusClaimed, status(latent))

	for _, args := range [][4]string{
		{"", latent, service.TenantStatusClaimed, service.TenantStatusSuspended},
		{proj, "", service.TenantStatusClaimed, service.TenantStatusSuspended},
		{proj, latent, "", service.TenantStatusSuspended},
		{proj, latent, service.TenantStatusClaimed, ""},
	} {
		_, err := tenants.SetTenantStatus(ctx, args[0], args[1], args[2], args[3])
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", args)
	}
}

// TestDomainStore_SetDomainStatusNeverUnverifies: a failed check that races a
// successful one cannot move the verified domain back, which would also
// fire the 0046 revocation.
func TestDomainStore_SetDomainStatusNeverUnverifies(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping domain status test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, domains := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-unverify", Name: "Unverify"})
	require.NoError(t, err)
	tenant, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	id, err := domains.CreateDomain(ctx, &service.Domain{ProjectID: proj, TenantID: tenant, Domain: "acme.example.test"})
	require.NoError(t, err)

	require.NoError(t, domains.SetDomainStatus(ctx, proj, id, service.DomainStatusFailed, 0))
	failed, err := domains.GetDomain(ctx, proj, id)
	require.NoError(t, err)
	require.Equal(t, service.DomainStatusFailed, failed.Status, "an unverified claim records its failed check")

	require.NoError(t, domains.SetDomainStatus(ctx, proj, id, service.DomainStatusVerified, 0))
	verified, err := domains.GetDomain(ctx, proj, id)
	require.NoError(t, err)
	for _, status := range []string{service.DomainStatusFailed, service.DomainStatusPending} {
		require.NoError(t, domains.SetDomainStatus(ctx, proj, id, status, 0))
		kept, err := domains.GetDomain(ctx, proj, id)
		require.NoError(t, err)
		require.Equal(t, service.DomainStatusVerified, kept.Status, "%s never replaces verified", status)
		require.Equal(t, verified.UpdatedAtMs, kept.UpdatedAtMs, "nor is anything written")
	}
}
