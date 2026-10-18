package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestAgentMachineMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	source, err := iofs.New(migrationFS, "migrations")
	require.NoError(t, err)
	defer func() { _ = source.Close() }()
	previous, err := source.Prev(42)
	require.NoError(t, err)
	migrateToVersion(t, scratch, previous)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	for _, version := range []uint{42, previous, 42} {
		migrateToVersion(t, scratch, version)
		for _, table := range []string{"agent_machines"} {
			var exists bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists))
			require.Equal(t, version == 42, exists)
		}
		var registry bool
		require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass('oauth_clients') IS NOT NULL`).Scan(&registry))
		require.True(t, registry, "delegation rollback must retain native registrations")
	}
}
