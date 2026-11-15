package sqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDateOfBirthPresenceMigrationRoundTrip(t *testing.T) {
	repo := newTestRepo(t, "dob-presence-migration")
	ctx := context.Background()
	migrateTo(t, repo.db.db, 29)
	_, err := repo.db.Exec(ctx, `INSERT INTO projects (id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('dob','dob',1,1)`)
	require.NoError(t, err)
	_, err = repo.db.Exec(ctx, `INSERT INTO users (id,project_id,email,date_of_birth_ms,created_at_ms,updated_at_ms) VALUES ('unknown','dob','unknown@example.test',0,1,1),('historical','dob','old@example.test',-1000,1,1)`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 30)
	for _, id := range []string{"unknown", "historical"} {
		var present bool
		require.NoError(t, repo.db.QueryRow(ctx, `SELECT date_of_birth_present FROM users WHERE id=$1`, id).Scan(&present))
		require.Equal(t, id == "historical", present)
	}
	migrateTo(t, repo.db.db, 29)
	var dob int64
	require.NoError(t, repo.db.QueryRow(ctx, `SELECT date_of_birth_ms FROM users WHERE id='historical'`).Scan(&dob))
	require.Equal(t, int64(-1000), dob)
	migrateTo(t, repo.db.db, 30)
}
