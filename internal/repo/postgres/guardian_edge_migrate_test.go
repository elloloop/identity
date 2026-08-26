package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// migrateToVersion drives golang-migrate to exactly the given schema version
// (up or down), so a test can seed pre-migration rows and then apply the
// migration under test.
func migrateToVersion(t *testing.T, dsn string, version uint) {
	t.Helper()
	src, err := iofs.New(migrationFS, "migrations")
	require.NoError(t, err)
	migrateDSN := dsn
	if len(migrateDSN) >= len("postgres://") && migrateDSN[:len("postgres://")] == "postgres://" {
		migrateDSN = "pgx5://" + migrateDSN[len("postgres://"):]
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateDSN)
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Migrate(version))
}

// TestMigration0031_GuardianEdgeBackfill proves the 0031 up migration derives
// exactly one guardian edge per ACTIVE parental consent whose adult and child
// both still exist. Revoked consents and consents referencing a deleted user
// (the record survives deletion by design) gain no edge.
//
// The whole test runs as a NON-superuser database owner: under that posture
// FORCE ROW LEVEL SECURITY applies to the owner too, and the migration
// runner's connection never sets the app.current_project_id GUC, so without
// the DISABLE/ENABLE RLS wrapper around the backfill (see the migration
// header) the SELECT from parental_consents/users would fail closed and
// silently backfill NOTHING — the trap migration 0028's down documents.
func TestMigration0031_GuardianEdgeBackfill(t *testing.T) {
	adminDSN := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if adminDSN == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres migration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Provision a throwaway database owned by a NON-superuser role, so every
	// statement below — migrations included — runs under RLS as the owner.
	suffix := time.Now().UnixNano()
	role := fmt.Sprintf("mig0031_role_%d", suffix)
	dbName := fmt.Sprintf("mig0031_db_%d", suffix)
	admin, err := pgx.Connect(ctx, adminDSN)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	_, err = admin.Exec(ctx, fmt.Sprintf(
		`CREATE ROLE %s LOGIN PASSWORD 'mig0031_pw' NOSUPERUSER NOBYPASSRLS`, role,
	))
	require.NoError(t, err)
	_, err = admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, dbName, role))
	require.NoError(t, err)
	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), `DROP DATABASE IF EXISTS `+dbName)
		_, _ = c.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	u, err := url.Parse(adminDSN)
	require.NoError(t, err)
	u.User = url.UserPassword(role, "mig0031_pw")
	u.Path = "/" + dbName
	dsn := u.String()

	// Migrations 0001→0030, then seed the pre-0031 world.
	migrateToVersion(t, dsn, 30)

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	project := "p-backfill"
	// The seed queries run under the RLS GUC for this project, the same
	// posture the driver's PrepareConn hook establishes for data-plane
	// traffic.
	_, err = conn.Exec(ctx, `SELECT set_config('app.current_project_id', $1, false)`, project)
	require.NoError(t, err)

	_, err = conn.Exec(ctx, `
		INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms)
		VALUES ($1, $2, 1, 1)`, project, "scope-"+project)
	require.NoError(t, err)

	seedUser := func(id, email string) {
		t.Helper()
		_, err := conn.Exec(ctx, `
			INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms)
			VALUES ($1, $2, $3, 1, 1)`, id, project, email)
		require.NoError(t, err)
	}
	seedUser("guardian-1", "g1@example.com")
	seedUser("child-1", "c1@example.com")
	seedUser("guardian-2", "g2@example.com")
	seedUser("child-2", "c2@example.com")
	// "ghost-guardian" / "ghost-child" stand in for users deleted after the
	// consent was recorded (the record survives deletion by design).

	seedConsent := func(id, guardian, child string, grantedAt, revokedAt int64) {
		t.Helper()
		_, err := conn.Exec(ctx, `
			INSERT INTO parental_consents (
				id, project_id, child_user_id, consenting_user_id, granted_at_ms, revoked_at_ms
			) VALUES ($1, $2, $3, $4, $5, $6)`, id, project, child, guardian, grantedAt, revokedAt)
		require.NoError(t, err)
	}
	seedConsent("pc-active", "guardian-1", "child-1", 1000, 0)         // → edge
	seedConsent("pc-revoked", "guardian-1", "child-2", 2000, 3000)     // revoked → no edge
	seedConsent("pc-ghost-adult", "ghost-guardian", "child-1", 100, 0) // deleted adult → no edge
	seedConsent("pc-ghost-child", "guardian-2", "ghost-child", 100, 0) // deleted child → no edge
	seedConsent("pc-active-2", "guardian-2", "child-2", 5000, 0)       // → edge

	migrateToVersion(t, dsn, 31)

	type edge struct {
		guardian, child string
		createdAtMs     int64
	}
	queryEdges := func() []edge {
		t.Helper()
		rows, err := conn.Query(ctx, `
			SELECT guardian_user_id, child_user_id, created_at_ms
			  FROM guardian_edges
			 WHERE project_id = $1
			 ORDER BY guardian_user_id, child_user_id`, project)
		require.NoError(t, err)
		defer rows.Close()
		var got []edge
		for rows.Next() {
			var e edge
			require.NoError(t, rows.Scan(&e.guardian, &e.child, &e.createdAtMs))
			got = append(got, e)
		}
		require.NoError(t, rows.Err())
		return got
	}

	require.Equal(t, []edge{
		{guardian: "guardian-1", child: "child-1", createdAtMs: 1000},
		{guardian: "guardian-2", child: "child-2", createdAtMs: 5000},
	}, queryEdges())

	// The table is RLS-forced like every other data-plane table: scoped to a
	// DIFFERENT project, this same non-superuser role must see no rows.
	_, err = conn.Exec(ctx, `SELECT set_config('app.current_project_id', $1, false)`, "other-project")
	require.NoError(t, err)
	var n int
	require.NoError(t, conn.QueryRow(ctx, `SELECT COUNT(*) FROM guardian_edges`).Scan(&n))
	require.Equal(t, 0, n, "RLS must hide another project's guardian edges")

	// Idempotency: stepping down to 0030 and back up re-runs the backfill,
	// which must not duplicate rows or move created_at_ms.
	_, err = conn.Exec(ctx, `SELECT set_config('app.current_project_id', $1, false)`, project)
	require.NoError(t, err)
	migrateToVersion(t, dsn, 30)
	migrateToVersion(t, dsn, 31)
	require.Equal(t, []edge{
		{guardian: "guardian-1", child: "child-1", createdAtMs: 1000},
		{guardian: "guardian-2", child: "child-2", createdAtMs: 5000},
	}, queryEdges())
}
