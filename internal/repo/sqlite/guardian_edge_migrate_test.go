package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrateTo drives golang-migrate against pool up to (and including) the
// given schema version, so a test can seed pre-migration rows and then apply
// the migration under test.
func migrateTo(t *testing.T, pool *sql.DB, version uint) {
	t.Helper()
	src, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		t.Fatalf("open migrations source: %v", err)
	}
	driver, err := sqlitemigrate.WithInstance(pool, &sqlitemigrate.Config{NoTxWrap: true})
	if err != nil {
		t.Fatalf("init migrate driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		t.Fatalf("init migrate: %v", err)
	}
	if err := m.Migrate(version); err != nil {
		t.Fatalf("migrate to %d: %v", version, err)
	}
}

// TestMigration0016_GuardianEdgeBackfill proves the 0016 up migration derives
// exactly one guardian edge per ACTIVE parental consent whose adult and child
// both still exist: revoked consents and consents referencing a deleted user
// (the record survives deletion by design) gain no edge.
func TestMigration0016_GuardianEdgeBackfill(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	name := fmt.Sprintf("sqlite-mig0016-%d", time.Now().UnixNano())
	pool, err := sql.Open("sqlite", memoryDSNForName(name))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })

	// Stop one migration short of guardian edges (0016), then seed the
	// pre-migration world.
	migrateTo(t, pool, 15)

	const project = "p-backfill"
	if _, err := pool.ExecContext(ctx, `
		INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms)
		VALUES ($1, $1, 1, 1)`, project); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	seedUser := func(id, email string) {
		t.Helper()
		if _, err := pool.ExecContext(ctx, `
			INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms)
			VALUES ($1, $2, $3, 1, 1)`, id, project, email); err != nil {
			t.Fatalf("seed user %s: %v", id, err)
		}
	}
	seedUser("guardian-1", "g1@example.com")
	seedUser("child-1", "c1@example.com")
	seedUser("guardian-2", "g2@example.com")
	seedUser("child-2", "c2@example.com")
	// "ghost-guardian" and "ghost-child" are referenced by consents but never
	// created — standing in for users deleted after the consent was recorded.

	seedConsent := func(id, guardian, child string, grantedAt, revokedAt int64) {
		t.Helper()
		if _, err := pool.ExecContext(ctx, `
			INSERT INTO parental_consents (
				id, project_id, child_user_id, consenting_user_id, granted_at_ms, revoked_at_ms
			) VALUES ($1, $2, $3, $4, $5, $6)`, id, project, child, guardian, grantedAt, revokedAt); err != nil {
			t.Fatalf("seed consent %s: %v", id, err)
		}
	}
	seedConsent("pc-active", "guardian-1", "child-1", 1000, 0)         // → edge
	seedConsent("pc-revoked", "guardian-1", "child-2", 2000, 3000)     // revoked → no edge
	seedConsent("pc-ghost-adult", "ghost-guardian", "child-1", 100, 0) // deleted adult → no edge
	seedConsent("pc-ghost-child", "guardian-2", "ghost-child", 100, 0) // deleted child → no edge
	seedConsent("pc-active-2", "guardian-2", "child-2", 5000, 0)       // → edge

	migrateTo(t, pool, 16)

	rows, err := pool.QueryContext(ctx, `
		SELECT guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1
		 ORDER BY guardian_user_id, child_user_id`, project)
	if err != nil {
		t.Fatalf("query edges: %v", err)
	}
	defer func() { _ = rows.Close() }()
	type edge struct {
		guardian, child string
		createdAtMs     int64
	}
	var got []edge
	for rows.Next() {
		var e edge
		if err := rows.Scan(&e.guardian, &e.child, &e.createdAtMs); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := []edge{
		{guardian: "guardian-1", child: "child-1", createdAtMs: 1000},
		{guardian: "guardian-2", child: "child-2", createdAtMs: 5000},
	}
	if len(got) != len(want) {
		t.Fatalf("edges = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("edge[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Idempotency: re-applying the backfill INSERT (ON CONFLICT DO NOTHING)
	// must not duplicate or move created_at_ms.
	if _, err := pool.ExecContext(ctx, `
		INSERT INTO guardian_edges (project_id, guardian_user_id, child_user_id, created_at_ms)
		SELECT pc.project_id, pc.consenting_user_id, pc.child_user_id, pc.granted_at_ms
		FROM parental_consents pc
		JOIN users g ON g.id = pc.consenting_user_id AND g.project_id = pc.project_id
		JOIN users c ON c.id = pc.child_user_id AND c.project_id = pc.project_id
		WHERE pc.revoked_at_ms = 0
		ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("re-run backfill: %v", err)
	}
	var n int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM guardian_edges WHERE project_id = $1`, project).Scan(&n); err != nil {
		t.Fatalf("count edges: %v", err)
	}
	if n != len(want) {
		t.Fatalf("edge count after backfill re-run = %d, want %d", n, len(want))
	}
}
