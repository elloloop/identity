package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// managedAccountsMigrationVersion is the migration that adds managed
// accounts' columns and index.
const managedAccountsMigrationVersion = 68

func migrateTo67WithRows(ctx context.Context, t *testing.T) (*pgx.Conn, func(uint)) {
	t.Helper()
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres 0068 test")
	}
	scratch := createScratchDatabase(ctx, t, dsn)
	m, err := newMigrator(scratch)
	require.NoError(t, err)
	t.Cleanup(func() { closeMigrator(m) })
	require.NoError(t, m.Migrate(uint(managedAccountsMigrationVersion-1)))
	conn, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	_, err = conn.Exec(ctx, `SELECT set_config($1, 'p', false)`, rlsGUC)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `
		INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('p', 'scope-p', 0, 0);
		INSERT INTO tenants (id, project_id, created_at_ms, updated_at_ms) VALUES ('t', 'p', 0, 0);
		INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms) VALUES ('u', 'p', 'zoe@example.com', 0, 0);
		INSERT INTO tenant_invitations (id, project_id, tenant_id, token_hash, email, status, expires_at_ms, created_at_ms)
		VALUES ('inv', 'p', 't', 'h', 'zoe@example.com', 'pending', 9999999999999, 0)`)
	require.NoError(t, err)
	return conn, func(v uint) { require.NoError(t, m.Migrate(v)) }
}

func hasIndex(ctx context.Context, t *testing.T, conn *pgx.Conn, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = $1`, name).Scan(&n))
	return n == 1
}

// TestMigrate_0068RowsStoredBeforeItArePersonalAndOrdinary: a user and an
// invitation stored before 0068 read as a personal account and an ordinary
// invitation; the down migration drops the columns and the index and keeps
// both rows.
func TestMigrate_0068RowsStoredBeforeItArePersonalAndOrdinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, migrateTo := migrateTo67WithRows(ctx, t)

	migrateTo(managedAccountsMigrationVersion)
	var managedBy, userID, delivery string
	var setUpAt, userEpoch, linkEpoch int64
	require.NoError(t, conn.QueryRow(ctx, `SELECT managed_by_tenant_id, set_up_at_ms, setup_epoch FROM users WHERE id = 'u'`).Scan(&managedBy, &setUpAt, &userEpoch))
	require.Equal(t, "", managedBy)
	require.Zero(t, setUpAt)
	require.Zero(t, userEpoch)
	require.NoError(t, conn.QueryRow(ctx, `SELECT user_id, delivery_email, setup_epoch FROM tenant_invitations WHERE id = 'inv'`).Scan(&userID, &delivery, &linkEpoch))
	require.Equal(t, "", userID)
	require.Equal(t, "", delivery)
	require.Zero(t, linkEpoch)
	require.True(t, hasIndex(ctx, t, conn, "tenant_invitations_pending_user_idx"))

	migrateTo(managedAccountsMigrationVersion - 1)
	for table, columns := range map[string][]string{
		"users":              {"managed_by_tenant_id", "set_up_at_ms", "setup_epoch"},
		"tenant_invitations": {"user_id", "delivery_email", "setup_epoch"},
	} {
		for _, column := range columns {
			require.False(t, hasColumn(ctx, t, conn, table, column), table+"."+column)
		}
	}
	require.False(t, hasIndex(ctx, t, conn, "tenant_invitations_pending_user_idx"))
	var kept int
	require.NoError(t, conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM users WHERE id = 'u') + (SELECT count(*) FROM tenant_invitations WHERE id = 'inv')`).Scan(&kept))
	require.Equal(t, 2, kept)
}

// TestMigrate_0068AfterTheUpgradeGuidesPrebuild: the statements
// docs/UPGRADE.md gives to add the columns and build the index before
// upgrading leave 0068 nothing to do.
func TestMigrate_0068AfterTheUpgradeGuidesPrebuild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, migrateTo := migrateTo67WithRows(ctx, t)

	recipe := upgradeSQL(t, "ALTER TABLE users\n    ADD COLUMN IF NOT EXISTS managed_by_tenant_id")
	for _, statement := range strings.Split(strings.TrimSuffix(recipe, ";\n"), ";\n") {
		_, err := conn.Exec(ctx, statement)
		require.NoError(t, err, statement)
	}
	require.True(t, hasIndex(ctx, t, conn, "tenant_invitations_pending_user_idx"))
	migrateTo(managedAccountsMigrationVersion)
	require.True(t, hasColumn(ctx, t, conn, "users", "managed_by_tenant_id"))
	require.True(t, hasIndex(ctx, t, conn, "tenant_invitations_pending_user_idx"))
}

// TestMigrate_0069SignOutIndexes: 0069 adds the partial indexes the managed
// sign-out reads, and its down migration drops them.
func TestMigrate_0069SignOutIndexes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, migrateTo := migrateTo67WithRows(ctx, t)
	indexes := []string{"qr_login_sessions_approved_user_idx", "oauth_one_time_codes_unconsumed_user_idx", "login_challenges_project_user_idx"}
	migrateTo(managedAccountsMigrationVersion + 1)
	for _, name := range indexes {
		require.True(t, hasIndex(ctx, t, conn, name), name)
	}
	migrateTo(managedAccountsMigrationVersion)
	for _, name := range indexes {
		require.False(t, hasIndex(ctx, t, conn, name), name)
	}
}

// TestMigrate_0069AfterTheUpgradeGuidesPrebuild: the guide's CONCURRENTLY
// statements leave 0069 nothing to do.
func TestMigrate_0069AfterTheUpgradeGuidesPrebuild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, migrateTo := migrateTo67WithRows(ctx, t)
	migrateTo(managedAccountsMigrationVersion)
	recipe := upgradeSQL(t, "CREATE INDEX CONCURRENTLY IF NOT EXISTS qr_login_sessions_approved_user_idx")
	for _, statement := range strings.Split(strings.TrimSuffix(recipe, ";\n"), ";\n") {
		_, err := conn.Exec(ctx, statement)
		require.NoError(t, err, statement)
	}
	migrateTo(managedAccountsMigrationVersion + 1)
	require.True(t, hasIndex(ctx, t, conn, "login_challenges_project_user_idx"))
}
