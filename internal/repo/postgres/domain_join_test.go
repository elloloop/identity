package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestDomainStore_SetDomainAllowJoin: a domain does not let its people join
// until SetDomainAllowJoin turns it on; the store returns the row as it
// stands and whether this call changed it, so an unchanged value is the row
// with false and an unknown id or another project's domain is nil; and every
// read of the domain carries the setting.
func TestDomainStore_SetDomainAllowJoin(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping domain join store test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, domains := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-join", Name: "Join"})
	require.NoError(t, err)
	other, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-join-other", Name: "Other"})
	require.NoError(t, err)
	tenantID, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Name: "Acme", Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	domainID, err := domains.CreateDomain(ctx, &service.Domain{
		ProjectID: proj, TenantID: tenantID, Domain: "join.example",
		VerificationMethod: service.DomainVerificationDNSTXT, Status: service.DomainStatusPending,
	})
	require.NoError(t, err)

	created, err := domains.GetDomain(ctx, proj, domainID)
	require.NoError(t, err)
	require.False(t, created.AllowJoin, "a new domain does not let anyone join")

	updated, changed, err := domains.SetDomainAllowJoin(ctx, proj, domainID, true)
	require.NoError(t, err)
	require.True(t, changed)
	require.NotNil(t, updated)
	require.True(t, updated.AllowJoin, "the returned row carries the new value")
	require.Equal(t, domainID, updated.ID)
	again, changed, err := domains.SetDomainAllowJoin(ctx, proj, domainID, true)
	require.NoError(t, err)
	require.False(t, changed, "the value the domain already has changes nothing")
	require.NotNil(t, again)
	require.True(t, again.AllowJoin)
	require.Equal(t, updated.UpdatedAtMs, again.UpdatedAtMs, "an unchanged value writes nothing")

	got, err := domains.GetDomain(ctx, proj, domainID)
	require.NoError(t, err)
	require.True(t, got.AllowJoin)
	require.GreaterOrEqual(t, got.UpdatedAtMs, created.UpdatedAtMs)
	require.Equal(t, service.DomainStatusPending, got.Status, "the setting leaves the status alone")

	require.NoError(t, domains.SetDomainStatus(ctx, proj, domainID, service.DomainStatusVerified, time.Now().UnixMilli()))
	verified, err := domains.GetVerifiedDomain(ctx, proj, "JOIN.example")
	require.NoError(t, err)
	require.NotNil(t, verified)
	require.True(t, verified.AllowJoin)
	listed, err := domains.ListDomainsByTenant(ctx, proj, tenantID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.True(t, listed[0].AllowJoin)

	for name, key := range map[string][2]string{
		"unknown id":      {proj, "dom-unknown"},
		"another project": {other, domainID},
		"unknown project": {"proj-unknown", domainID},
	} {
		gone, changed, err := domains.SetDomainAllowJoin(ctx, key[0], key[1], false)
		require.NoError(t, err, name)
		require.False(t, changed, name)
		require.Nil(t, gone, name)
	}
	got, err = domains.GetDomain(ctx, proj, domainID)
	require.NoError(t, err)
	require.True(t, got.AllowJoin, "a write elsewhere left the domain alone")

	off, changed, err := domains.SetDomainAllowJoin(ctx, proj, domainID, false)
	require.NoError(t, err)
	require.True(t, changed)
	require.False(t, off.AllowJoin)

	for _, key := range [][2]string{{"", domainID}, {proj, ""}} {
		_, _, err := domains.SetDomainAllowJoin(ctx, key[0], key[1], true)
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", key)
	}
}

// TestDomainStore_SetDomainAllowJoinOneRacerChanges: admins turning joining
// on at once each lock the row, so exactly one reports the change and the
// rest find the value already set, which is what lets SetDomainJoin record a
// change once.
func TestDomainStore_SetDomainAllowJoinOneRacerChanges(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping domain join race test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, domains := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-join-race", Name: "Join race"})
	require.NoError(t, err)
	tenantID, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: proj, Name: "Acme", Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	domainID, err := domains.CreateDomain(ctx, &service.Domain{
		ProjectID: proj, TenantID: tenantID, Domain: "race.example",
		VerificationMethod: service.DomainVerificationDNSTXT, Status: service.DomainStatusVerified,
	})
	require.NoError(t, err)

	const racers = 8
	start := make(chan struct{})
	changes := make(chan bool, racers)
	errs := make(chan error, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, changed, err := domains.SetDomainAllowJoin(ctx, proj, domainID, true)
			if err == nil && (d == nil || !d.AllowJoin) {
				err = errors.New("the returned domain does not allow joining")
			}
			if err != nil {
				errs <- err
				return
			}
			changes <- changed
		}()
	}
	close(start)
	wg.Wait()
	close(changes)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	won := 0
	for changed := range changes {
		if changed {
			won++
		}
	}
	require.Equal(t, 1, won, "exactly one racer changes the domain")
}

// TestGovernanceRevocation_SettingDomainJoinRevokesNothing: turning joining
// on or off writes a domain's row but not its status, tenant or name, so the
// 0046 trigger does not fire and no governed agent loses anything.
func TestGovernanceRevocation_SettingDomainJoinRevokesNothing(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	d := f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusVerified)
	e := f.seedEveryone(ctx, t)

	for _, allowJoin := range []bool{true, false} {
		_, changed, err := f.domains.SetDomainAllowJoin(ctx, f.project, d, allowJoin)
		require.NoError(t, err)
		require.True(t, changed)
	}
	f.requireNothingRevoked(ctx, t, e)
}

// TestDomainJoinMigrationRoundTrip asserts 0051 adds domains.allow_join,
// false on every existing row, and its down drops it.
func TestDomainJoinMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	column := func() (string, bool) {
		t.Helper()
		var def string
		var nullable string
		err := raw.QueryRow(ctx, `
			SELECT coalesce(column_default, ''), is_nullable FROM information_schema.columns
			WHERE table_name = 'domains' AND column_name = 'allow_join'`).Scan(&def, &nullable)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false
		}
		require.NoError(t, err)
		require.Equal(t, "NO", nullable)
		return def, true
	}

	migrateToVersion(t, scratch, 50)
	_, exists := column()
	require.False(t, exists)
	for _, q := range []string{
		`INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('proj-before', 'scope-before', 1, 1)`,
		`INSERT INTO tenants (id, project_id, status, created_at_ms, updated_at_ms) VALUES ('tenant-before', 'proj-before', 'claimed', 1, 1)`,
		`INSERT INTO domains (id, project_id, tenant_id, domain, verification_method, status, created_at_ms, updated_at_ms)
			VALUES ('dom-before', 'proj-before', 'tenant-before', 'before.example', 'dns_txt', 'verified', 1, 1)`,
	} {
		_, err = raw.Exec(ctx, q)
		require.NoError(t, err)
	}

	for _, version := range []uint{51, 50, 51} {
		migrateToVersion(t, scratch, version)
		def, exists := column()
		require.Equal(t, version == 51, exists, "version %d", version)
		if exists {
			require.Equal(t, "false", def)
			var allowJoin bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT allow_join FROM domains WHERE id = 'dom-before'`).Scan(&allowJoin))
			require.False(t, allowJoin, "a domain from before the migration does not let anyone join")
		}
	}
}
