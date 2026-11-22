package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestGuardianDeletionReceiptMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx := context.Background()
	scratch := createScratchDatabase(ctx, t, dsn)
	migrateToVersion(t, scratch, 63)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	_, err = raw.Exec(ctx, `INSERT INTO projects(id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('erasure','erasure',1,1)`)
	require.NoError(t, err)
	migrateToVersion(t, scratch, 64)
	_, err = raw.Exec(ctx, `INSERT INTO guardian_deletion_receipts(project_id,guardian_user_id,child_user_id,completed_at_ms) VALUES ('erasure','parent','child',1000)`)
	require.NoError(t, err)
	migrateToVersion(t, scratch, 63)
	migrateToVersion(t, scratch, 64)
	var count int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM guardian_deletion_receipts`).Scan(&count))
	require.Zero(t, count)
}
