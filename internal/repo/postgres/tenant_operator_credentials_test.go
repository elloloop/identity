package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// A tenant_operator credential is stored like any other kind and read back
// uncached by its public id, which is how the operator service checks one on
// every call. It never selects a project as X-Project-Key.
func TestTenantOperatorCredential_StoredAndReadByPublicID(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)
	projectID, err := store.CreateProject(ctx, &service.AdminProject{StorageScopeID: "scope-tenant-operator", Name: "Operators"})
	require.NoError(t, err)

	_, err = store.CreateProjectCredential(ctx, &service.AdminProjectCredential{
		ProjectID: projectID, Kind: service.CredentialKindTenantOperator, PublicID: "ok_store", SecretHash: "hash",
	})
	require.NoError(t, err)
	got, err := store.CredentialByPublicIDInActiveProject(ctx, "ok_store")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, service.CredentialKindTenantOperator, got.Kind)
	require.Equal(t, projectID, got.ProjectID)
	require.Equal(t, "hash", got.SecretHash)

	resolved, err := store.ResolveByCredential(ctx, "ok_store")
	require.NoError(t, err)
	require.Nil(t, resolved, "a tenant operator key must not select a project as X-Project-Key")
}

// 0054 widens the kind check to admit tenant_operator; rolling it back
// deletes those credentials alone and narrows the check again.
func TestTenantOperatorCredentialMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	migrateToVersion(t, scratch, 54)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	_, err = raw.Exec(ctx, `INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('p', 'scope-p', 1, 1)`)
	require.NoError(t, err)
	insert := func(id, kind string) error {
		_, err := raw.Exec(ctx, `INSERT INTO project_credentials (id, project_id, kind, public_id, created_at_ms) VALUES ($1, 'p', $2, $1, 1)`, id, kind)
		return err
	}
	require.NoError(t, insert("ok_one", "tenant_operator"))
	require.NoError(t, insert("tk_one", "teammate_key_manager"))
	kinds := func() string {
		var def string
		require.NoError(t, raw.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'project_credentials_kind_check'`).Scan(&def))
		return def
	}
	require.Contains(t, kinds(), "tenant_operator")

	migrateToVersion(t, scratch, 53)
	require.NotContains(t, kinds(), "tenant_operator")
	require.Contains(t, kinds(), "teammate_key_manager")
	rows, err := raw.Query(ctx, `SELECT id FROM project_credentials ORDER BY id`)
	require.NoError(t, err)
	left, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Equal(t, []string{"tk_one"}, left, "the rollback deletes the tenant_operator credentials alone")
	err = insert("ok_two", "tenant_operator")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "project_credentials_kind_check"), err.Error())

	migrateToVersion(t, scratch, 54)
	require.NoError(t, insert("ok_two", "tenant_operator"))
}
