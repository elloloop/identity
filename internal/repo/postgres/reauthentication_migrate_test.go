package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestReauthenticationMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	migrateToVersion(t, scratch, 62)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	_, err = raw.Exec(ctx, `INSERT INTO projects (id,storage_scope_id,created_at_ms,updated_at_ms) VALUES ('reauth','reauth',1,1)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO passkey_challenges (id,project_id,user_id,challenge,challenge_type,expires_at_ms,created_at_ms) VALUES ('login','reauth','parent','login','authentication',3000,1000)`)
	require.NoError(t, err)
	migrateToVersion(t, scratch, 63)
	var action, resource string
	require.NoError(t, raw.QueryRow(ctx, `SELECT action,resource_id FROM passkey_challenges WHERE id='login'`).Scan(&action, &resource))
	require.Empty(t, action)
	require.Empty(t, resource)
	_, err = raw.Exec(ctx, `INSERT INTO passkey_challenges (id,project_id,user_id,challenge,challenge_type,expires_at_ms,created_at_ms,action,resource_id) VALUES ('bound','reauth','parent','stepup','authentication',3000,1000,'account.pin.set','parent')`)
	require.NoError(t, err)
	migrateToVersion(t, scratch, 62)
	var count int
	require.NoError(t, raw.QueryRow(ctx, `SELECT COUNT(*) FROM passkey_challenges`).Scan(&count))
	require.Equal(t, 1, count)
	var id string
	require.NoError(t, raw.QueryRow(ctx, `SELECT id FROM passkey_challenges`).Scan(&id))
	require.Equal(t, "login", id)
	migrateToVersion(t, scratch, 63)
}
