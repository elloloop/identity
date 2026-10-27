package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestDomainStore_SetDomainAllowJoin: a domain does not let its people join
// until SetDomainAllowJoin turns it on; the store reports whether a row
// changed, so an unchanged value, an unknown id or another project's domain
// is false; and every read of the domain carries the setting.
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

	changed, err := domains.SetDomainAllowJoin(ctx, proj, domainID, true)
	require.NoError(t, err)
	require.True(t, changed)
	changed, err = domains.SetDomainAllowJoin(ctx, proj, domainID, true)
	require.NoError(t, err)
	require.False(t, changed, "the value the domain already has changes nothing")

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
		changed, err := domains.SetDomainAllowJoin(ctx, key[0], key[1], false)
		require.NoError(t, err, name)
		require.False(t, changed, name)
	}
	got, err = domains.GetDomain(ctx, proj, domainID)
	require.NoError(t, err)
	require.True(t, got.AllowJoin, "a write elsewhere left the domain alone")

	changed, err = domains.SetDomainAllowJoin(ctx, proj, domainID, false)
	require.NoError(t, err)
	require.True(t, changed)

	for _, key := range [][2]string{{"", domainID}, {proj, ""}} {
		_, err := domains.SetDomainAllowJoin(ctx, key[0], key[1], true)
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", key)
	}
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
		changed, err := f.domains.SetDomainAllowJoin(ctx, f.project, d, allowJoin)
		require.NoError(t, err)
		require.True(t, changed)
	}
	f.requireNothingRevoked(ctx, t, e)
}

// TestDomainJoinMigrationRoundTrip asserts 0050 adds domains.allow_join,
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

	migrateToVersion(t, scratch, 49)
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

	for _, version := range []uint{50, 49, 50} {
		migrateToVersion(t, scratch, version)
		def, exists := column()
		require.Equal(t, version == 50, exists, "version %d", version)
		if exists {
			require.Equal(t, "false", def)
			var allowJoin bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT allow_join FROM domains WHERE id = 'dom-before'`).Scan(&allowJoin))
			require.False(t, allowJoin, "a domain from before the migration does not let anyone join")
		}
	}
}
