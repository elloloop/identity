package sqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReauthenticationMigrationRoundTrip(t *testing.T) {
	repo := newTestRepo(t, "reauth-migration")
	ctx := context.Background()
	migrateTo(t, repo.db.db, 30)
	raw := repo.db
	var err error

	_, err = raw.Exec(ctx, `INSERT INTO projects (id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('reauth','reauth',1,1)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO passkey_challenges (id,project_id,user_id,challenge,challenge_type,expires_at_ms,created_at_ms) VALUES ('login','reauth','parent','login','authentication',3000,1000)`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 31)
	var action, resource string
	require.NoError(t, raw.QueryRow(ctx, `SELECT action,resource_id FROM passkey_challenges WHERE id='login'`).Scan(&action, &resource))
	require.Empty(t, action)
	require.Empty(t, resource)
	_, err = raw.Exec(ctx, `INSERT INTO passkey_challenges (id,project_id,user_id,challenge,challenge_type,expires_at_ms,created_at_ms,action,resource_id) VALUES ('bound','reauth','parent','stepup','authentication',3000,1000,'account.pin.set','parent')`)
	require.NoError(t, err)
	migrateTo(t, repo.db.db, 30)
	var count int
	require.NoError(t, raw.QueryRow(ctx, `SELECT COUNT(*) FROM passkey_challenges`).Scan(&count))
	require.Equal(t, 1, count)
	var id string
	require.NoError(t, raw.QueryRow(ctx, `SELECT id FROM passkey_challenges`).Scan(&id))
	require.Equal(t, "login", id)
	migrateTo(t, repo.db.db, 31)
}
