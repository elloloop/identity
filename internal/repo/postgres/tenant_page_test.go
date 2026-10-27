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

// TestTenantStore_ListTenantsPagesNewestFirst: ListTenants keys its order on
// (created_at_ms, id), so pages walked with the last row's position return
// every tenant of the project exactly once, in every status, newest first,
// and two tenants created in the same millisecond are ordered by id.
func TestTenantStore_ListTenantsPagesNewestFirst(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping tenant paging test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, _ := newTenantDomainStores(ctx, t, dsn)
	proj, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-page", Name: "Page"})
	require.NoError(t, err)
	other, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-page-other", Name: "Other"})
	require.NoError(t, err)

	for _, tn := range []service.Tenant{
		{ID: "t-a", Status: service.TenantStatusClaimed, CreatedAtMs: 1000},
		{ID: "t-b", Status: service.TenantStatusLatent, CreatedAtMs: 2000},
		{ID: "t-c1", Status: service.TenantStatusSuspended, CreatedAtMs: 3000},
		{ID: "t-c2", Status: service.TenantStatusClaimed, CreatedAtMs: 3000},
		{ID: "t-d", Status: service.TenantStatusLatent, CreatedAtMs: 4000},
	} {
		tn.ProjectID = proj
		_, err := tenants.CreateTenant(ctx, &tn)
		require.NoError(t, err)
	}
	_, err = tenants.CreateTenant(ctx, &service.Tenant{ID: "t-other", ProjectID: other, CreatedAtMs: 5000})
	require.NoError(t, err)

	var got []string
	var after *service.TenantPosition
	for page := 0; ; page++ {
		require.Less(t, page, 10, "paging never ended")
		list, err := tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: proj, After: after, Limit: 2})
		require.NoError(t, err)
		require.LessOrEqual(t, len(list), 2)
		if len(list) == 0 {
			break
		}
		for _, tn := range list {
			got = append(got, tn.ID)
		}
		last := list[len(list)-1]
		after = &service.TenantPosition{CreatedAtMs: last.CreatedAtMs, ID: last.ID}
	}
	require.Equal(t, []string{"t-d", "t-c2", "t-c1", "t-b", "t-a"}, got)

	all, err := tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: proj, Limit: 100})
	require.NoError(t, err)
	require.Len(t, all, 5)
	require.Equal(t, "t-d", all[0].ID)
	require.Equal(t, service.TenantStatusLatent, all[0].Status)
	require.Equal(t, int64(4000), all[0].CreatedAtMs)

	_, err = tenants.ListTenants(ctx, service.TenantListQuery{Limit: 1})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: proj})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
}

// TestPageTenantsMigrationRoundTrip asserts 0048 swaps the project-only
// tenants index for the paging one, and its down swaps them back.
func TestPageTenantsMigrationRoundTrip(t *testing.T) {
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

	indexDef := func(name string) string {
		t.Helper()
		var def string
		err := raw.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE tablename = 'tenants' AND indexname = $1`, name).Scan(&def)
		if errors.Is(err, pgx.ErrNoRows) {
			return ""
		}
		require.NoError(t, err)
		return def
	}
	for _, version := range []uint{48, 47, 48} {
		migrateToVersion(t, scratch, version)
		paging, projectOnly := indexDef("tenants_project_created_idx"), indexDef("tenants_project_idx")
		if version == 48 {
			require.Contains(t, paging, "(project_id, created_at_ms, id)")
			require.Empty(t, projectOnly)
		} else {
			require.Empty(t, paging)
			require.Contains(t, projectOnly, "(project_id)")
		}
	}
}
