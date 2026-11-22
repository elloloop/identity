package sqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGuardianDeletionReceiptMigrationRoundTrip(t *testing.T) {
	repo := newTestRepo(t, "erasure-migrate")
	ctx := context.Background()
	migrateTo(t, repo.db.db, 31)
	raw := repo.db
	var err error

	_, err = raw.Exec(ctx, `INSERT INTO projects(id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('erasure','erasure',1,1)`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 32)
	_, err = raw.Exec(ctx, `INSERT INTO guardian_deletion_receipts(project_id,guardian_user_id,child_user_id,completed_at_ms) VALUES ('erasure','parent','child',1000)`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 31)
	migrateTo(t, repo.db.db, 32)
	var count int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM guardian_deletion_receipts`).Scan(&count))
	require.Zero(t, count)
}
