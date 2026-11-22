package sqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasskeyProvenanceMigrationRoundTrip(t *testing.T) {
	repo := newTestRepo(t, "provenance-migrate")
	ctx := context.Background()
	migrateTo(t, repo.db.db, 32)
	raw := repo.db
	var err error

	_, err = raw.Exec(ctx, `INSERT INTO projects(id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('provenance','provenance',1,1)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO users(id,project_id,email,created_at_ms,updated_at_ms) VALUES ('owner','provenance','owner@example.test',1,1)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO passkeys(id,project_id,credential_id,user_id,public_key,created_at_ms,last_used_at_ms) VALUES ('legacy','provenance','legacy','owner','public',1,1)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO refresh_tokens(id,project_id,token_hash,user_id,expires_at_ms,created_at_ms,last_used_at_ms) VALUES ('legacy','provenance','hash','owner',3000,1,1)`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 33)
	var eligible, sessionEligible bool
	var source string
	require.NoError(t, raw.QueryRow(ctx, `SELECT reauthentication_eligible FROM passkeys WHERE id='legacy'`).Scan(&eligible))
	require.False(t, eligible)
	require.NoError(t, raw.QueryRow(ctx, `SELECT credential_enrollment_eligible,credential_enrollment_passkey_id FROM refresh_tokens WHERE id='legacy'`).Scan(&sessionEligible, &source))
	require.False(t, sessionEligible)
	require.Empty(t, source)
	_, err = raw.Exec(ctx, `UPDATE passkeys SET reauthentication_eligible=true WHERE id='legacy'`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 32)
	migrateTo(t, repo.db.db, 33)
	require.NoError(t, raw.QueryRow(ctx, `SELECT reauthentication_eligible FROM passkeys WHERE id='legacy'`).Scan(&eligible))
	require.False(t, eligible, "rollback never infers enrollment provenance from old credentials")
	var count int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id='legacy'`).Scan(&count))
	require.Equal(t, 1, count, "ordinary sign-in records are preserved")
}
