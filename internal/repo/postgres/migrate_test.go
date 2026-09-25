package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestMigrate_EmptyDSN_Errors runs without a database: an empty DSN must
// be rejected before any connection is attempted.
func TestMigrate_EmptyDSN_Errors(t *testing.T) {
	if err := Migrate(""); err == nil {
		t.Fatal(`Migrate(""): want error, got nil`)
	}
	if err := Migrate("   "); err == nil {
		t.Fatal(`Migrate("   "): want error for blank DSN, got nil`)
	}
}

// TestMigrate_AppliesAndIdempotent is the real-Postgres e2e: it applies
// the full migration set to the database at GATEWAY_TEST_POSTGRES_DSN,
// proves the second run is a no-op (idempotent), and that the resulting
// schema is usable. Skipped when the env var is unset (CI provides it).
func TestMigrate_AppliesAndIdempotent(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres migrate e2e")
	}

	// First run applies every pending migration.
	if err := Migrate(dsn); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	// Second run is a no-op rather than an error (idempotent).
	if err := Migrate(dsn); err != nil {
		t.Fatalf("second Migrate (idempotent): %v", err)
	}

	// The migrated schema is usable: a read against a migrated table
	// succeeds and returns no rows on an empty database.
	ctx := context.Background()
	r, err := New(ctx, Config{DSN: dsn, MaxConns: 5, ProjectID: "migrate-test"})
	if err != nil {
		t.Fatalf("New after migrate: %v", err)
	}
	defer r.Close()
	if u, err := r.FindUserByEmail(ctx, "nobody@example.com"); err != nil {
		t.Fatalf("FindUserByEmail on migrated schema: %v", err)
	} else if u != nil {
		t.Fatalf("want nil user on empty schema, got %#v", u)
	}
}

// TestForceMigrationVersion_RefusesBadInput runs without a database: an empty
// DSN, and a version no embedded migration has, are refused before any
// connection is attempted.
func TestForceMigrationVersion_RefusesBadInput(t *testing.T) {
	if err := ForceMigrationVersion(" ", 1); err == nil {
		t.Fatal("ForceMigrationVersion with a blank DSN: want error, got nil")
	}
	const unreachable = "postgres://nobody@127.0.0.1:1/none?sslmode=disable"
	for _, version := range []int{0, -1, 9999} {
		err := ForceMigrationVersion(unreachable, version)
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("ForceMigrationVersion(%d) = %v, want a version error before connecting", version, err)
		}
	}
}

// TestDirtyVersionError_NamesTheRecovery pins the recovery the refusal names
// for a failed migration in the middle, at the start and at the end of the
// set.
func TestDirtyVersionError_NamesTheRecovery(t *testing.T) {
	middle := dirtyVersionError{version: 33, previous: 32, next: 34}.Error()
	for _, want := range []string{"identity migrate force 32", "rolling back migration 34", "identity migrate force 34"} {
		if !strings.Contains(middle, want) {
			t.Errorf("middle: %q lacks %q", middle, want)
		}
	}
	first := dirtyVersionError{version: 1, next: 2}.Error()
	if !strings.Contains(first, "drop the schema_migrations table") || strings.Contains(first, "force 0") {
		t.Errorf("first: %q, want the empty-database recovery and no force to 0", first)
	}
	last := dirtyVersionError{version: 34, previous: 33}.Error()
	if !strings.Contains(last, "identity migrate force 33") || strings.Contains(last, "rolling back") {
		t.Errorf("last: %q, want force 33 and no rollback branch", last)
	}
}

// emailFoldMigrationVersion is 0034, whose lock_timeout the dirty-state test
// trips.
const emailFoldMigrationVersion = 34

// TestMigrate_FailedMigrationIsForcedAndRerun reproduces the recovery path
// against real Postgres. A migration that fails (here 0034's lock_timeout,
// tripped by a transaction holding a lock on users) rolls its SQL back but
// leaves the schema version dirty, and every later run refuses until an
// operator forces the version; the error names the command. After forcing the
// version before the failed one, migrating again applies it.
func TestMigrate_FailedMigrationIsForcedAndRerun(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres dirty-migration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)

	m, err := newMigrator(scratch)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(uint(emailFoldMigrationVersion-1)))
	closeMigrator(m)

	holder, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = holder.Close(ctx) }()
	tx, err := holder.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `LOCK TABLE users IN ACCESS SHARE MODE`)
	require.NoError(t, err)

	forcePrevious := fmt.Sprintf("identity migrate force %d", emailFoldMigrationVersion-1)
	err = Migrate(scratch)
	require.Error(t, err, "0034 must fail while another transaction holds a lock on users")
	var dirty dirtyVersionError
	require.ErrorAs(t, err, &dirty)
	require.Equal(t, emailFoldMigrationVersion, dirty.version)
	require.Equal(t, emailFoldMigrationVersion-1, dirty.previous)
	require.Contains(t, err.Error(), forcePrevious)
	require.False(t, hasColumn(ctx, t, holder, "users", "email_fold"), "the failed migration must leave no change behind")
	require.NoError(t, tx.Rollback(ctx))

	// With the lock gone the run still refuses: the version is dirty.
	err = Migrate(scratch)
	require.ErrorAs(t, err, &dirty)
	require.Contains(t, err.Error(), forcePrevious)

	require.NoError(t, ForceMigrationVersion(scratch, emailFoldMigrationVersion-1))
	require.NoError(t, Migrate(scratch))
	require.True(t, hasColumn(ctx, t, holder, "users", "email_fold"))
}

// createScratchDatabase creates an empty database next to the one dsn names,
// drops it when the test ends, and returns its DSN.
func createScratchDatabase(ctx context.Context, t *testing.T, dsn string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	name := fmt.Sprintf("migrate_scratch_%d", time.Now().UnixNano())
	_, err = admin.Exec(ctx, `CREATE DATABASE `+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(dropCtx, dsn)
		if err != nil {
			t.Logf("drop scratch database %s: %v", name, err)
			return
		}
		defer func() { _ = c.Close(dropCtx) }()
		if _, err := c.Exec(dropCtx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
			t.Logf("drop scratch database %s: %v", name, err)
		}
	})
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}

func hasColumn(ctx context.Context, t *testing.T, conn *pgx.Conn, table, column string) bool {
	t.Helper()
	var n int
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
		table, column).Scan(&n))
	return n == 1
}

// TestMigrate_0034CanonicalizesPendingInvitations: pending invitations stored
// before the service canonicalized carry the address as typed. 0034 rewrites
// each all-ASCII one in exactly the form service.CanonicalizeEmail gives,
// revokes all but the newest of any that then name one mailbox, and leaves
// non-ASCII addresses and settled invitations as they are.
func TestMigrate_0034CanonicalizesPendingInvitations(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres 0034 invitation test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	m, err := newMigrator(scratch)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(uint(emailFoldMigrationVersion-1)))
	closeMigrator(m)

	conn, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, `
		INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('p', 'scope-p', 0, 0);
		INSERT INTO tenants (id, project_id, created_at_ms, updated_at_ms) VALUES ('t', 'p', 0, 0)`)
	require.NoError(t, err)
	seed := []struct {
		id, email, status string
	}{
		{"old-tag", "zoe+old@gmail.com", "pending"},
		{"new-dots", "z.o.e@googlemail.com", "pending"}, // same mailbox, newer: survives
		{"tagged", "bob+jira@corp.com", "pending"},
		{"trailing-dot", "carol@corp.com.", "pending"},
		{"dots-kept", "d.ave@corp.com", "pending"},
		{"non-ascii", "zoé+x@corp.com", "pending"},
		{"settled", "eve+x@corp.com", "accepted"},
	}
	for i, s := range seed {
		_, err := conn.Exec(ctx, `
			INSERT INTO tenant_invitations (id, project_id, tenant_id, token_hash, email, status, expires_at_ms, created_at_ms)
			VALUES ($1, 'p', 't', $1, $2, $3, 9999999999999, $4)`, s.id, s.email, s.status, i)
		require.NoError(t, err)
	}

	require.NoError(t, Migrate(scratch))

	got := map[string][2]string{}
	rows, err := conn.Query(ctx, `SELECT id, email, status FROM tenant_invitations`)
	require.NoError(t, err)
	for rows.Next() {
		var id, email, status string
		require.NoError(t, rows.Scan(&id, &email, &status))
		got[id] = [2]string{email, status}
	}
	require.NoError(t, rows.Err())

	require.Equal(t, "revoked", got["old-tag"][1], "the older of two invitations to one mailbox is revoked")
	for _, id := range []string{"new-dots", "tagged", "trailing-dot", "dots-kept"} {
		var original string
		for _, s := range seed {
			if s.id == id {
				original = s.email
			}
		}
		require.Equal(t, [2]string{service.CanonicalizeEmail(original), "pending"}, got[id],
			"%s: the migration's canonical form must be CanonicalizeEmail's", id)
	}
	require.Equal(t, [2]string{"zoé+x@corp.com", "pending"}, got["non-ascii"])
	require.Equal(t, [2]string{"eve+x@corp.com", "accepted"}, got["settled"])
}
