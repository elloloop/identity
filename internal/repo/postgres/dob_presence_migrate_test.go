package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestDateOfBirthPresenceMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	migrateToVersion(t, scratch, 61)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	_, err = raw.Exec(ctx, `INSERT INTO projects (id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('dob','dob',1,1)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO users (id,project_id,email,date_of_birth_ms,created_at_ms,updated_at_ms) VALUES ('unknown','dob','unknown@example.test',0,1,1),('historical','dob','old@example.test',-1000,1,1)`)
	require.NoError(t, err)
	migrateToVersion(t, scratch, 62)
	for _, id := range []string{"unknown", "historical"} {
		var present bool
		require.NoError(t, raw.QueryRow(ctx, `SELECT date_of_birth_present FROM users WHERE id=$1`, id).Scan(&present))
		require.Equal(t, id == "historical", present)
	}
	migrateToVersion(t, scratch, 61)
	var dob int64
	require.NoError(t, raw.QueryRow(ctx, `SELECT date_of_birth_ms FROM users WHERE id='historical'`).Scan(&dob))
	require.Equal(t, int64(-1000), dob)
	migrateToVersion(t, scratch, 62)
}
