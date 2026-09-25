package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
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
	if _, err := ForceMigrationVersion(" ", 1, false); err == nil {
		t.Fatal("ForceMigrationVersion with a blank DSN: want error, got nil")
	}
	const unreachable = "postgres://nobody@127.0.0.1:1/none?sslmode=disable"
	for _, version := range []int{0, -1, 9999} {
		_, err := ForceMigrationVersion(unreachable, version, false)
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("ForceMigrationVersion(%d) = %v, want a version error before connecting", version, err)
		}
	}
}

// TestDescribeDirtyVersion places a dirty version among the embedded
// migrations: in the middle, the first, the last, and one this build does not
// ship — left by a newer release — which must never read as "first".
func TestDescribeDirtyVersion(t *testing.T) {
	src, err := iofs.New(migrationFS, migrationsDir)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	latest := latestEmbeddedVersion(t)

	for _, tc := range []struct {
		name    string
		version int
		want    DirtyMigrationError
	}{
		{"middle", 33, DirtyMigrationError{Version: 33, Known: true, Latest: latest, Previous: 32, Next: 34}},
		{"first", 1, DirtyMigrationError{Version: 1, Known: true, Latest: latest, First: true, Next: 2}},
		{"latest", latest, DirtyMigrationError{Version: latest, Known: true, Latest: latest, Previous: latest - 1}},
		{"newer release", latest + 1, DirtyMigrationError{Version: latest + 1, Latest: latest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := describeDirtyVersion(src, uint(tc.version))
			require.NoError(t, err)
			require.Equal(t, tc.want, *got)
		})
	}

	newer, err := describeDirtyVersion(src, uint(latest+1))
	require.NoError(t, err)
	require.Contains(t, newer.Error(), "newer identity release")
	require.NotContains(t, newer.Error(), "can be cleared")
}

func latestEmbeddedVersion(t *testing.T) int {
	t.Helper()
	src, err := iofs.New(migrationFS, migrationsDir)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	versions, err := embeddedVersions(src)
	require.NoError(t, err)
	return int(versions[len(versions)-1])
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

	err = Migrate(scratch)
	require.Error(t, err, "0034 must fail while another transaction holds a lock on users")
	var dirty *DirtyMigrationError
	require.ErrorAs(t, err, &dirty)
	require.Equal(t, emailFoldMigrationVersion, dirty.Version)
	require.Equal(t, emailFoldMigrationVersion-1, dirty.Previous)
	require.False(t, hasColumn(ctx, t, holder, "users", "email_fold"), "the failed migration must leave no change behind")
	require.NoError(t, tx.Rollback(ctx))

	// With the lock gone the run still refuses: the version is dirty.
	err = Migrate(scratch)
	require.ErrorAs(t, err, &dirty)
	require.Equal(t, emailFoldMigrationVersion, dirty.Version)

	replaced, err := ForceMigrationVersion(scratch, emailFoldMigrationVersion-1, false)
	require.NoError(t, err)
	require.Equal(t, MigrationState{Version: emailFoldMigrationVersion, Dirty: true}, replaced,
		"force reports the dirty version it overwrote")
	require.NoError(t, Migrate(scratch))
	require.True(t, hasColumn(ctx, t, holder, "users", "email_fold"))
}

// TestForceMigrationVersion_RefusesWhatItIsNotFor: force clears a failed
// migration's dirty flag and nothing else. On a clean database, and on one a
// newer release migrated, it refuses unless overridden.
func TestForceMigrationVersion_RefusesWhatItIsNotFor(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres force refusal test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	require.NoError(t, Migrate(scratch))
	latest := latestEmbeddedVersion(t)

	_, err := ForceMigrationVersion(scratch, latest-1, false)
	require.ErrorIs(t, err, ErrForceRefused, "a clean database is refused")

	conn, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	newer := latest + 1
	_, err = conn.Exec(ctx, `UPDATE schema_migrations SET version = $1, dirty = true`, newer)
	require.NoError(t, err)
	_, err = ForceMigrationVersion(scratch, latest, false)
	require.ErrorIs(t, err, ErrForceRefused, "a database a newer release migrated is refused")

	replaced, err := ForceMigrationVersion(scratch, latest, true)
	require.NoError(t, err, "the override forces anyway")
	require.Equal(t, MigrationState{Version: newer, Dirty: true}, replaced)
	replaced, err = ForceMigrationVersion(scratch, latest, true)
	require.NoError(t, err)
	require.Equal(t, MigrationState{Version: latest}, replaced, "and on a clean database")
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
		INSERT INTO tenants (id, project_id, created_at_ms, updated_at_ms)
		VALUES ('t', 'p', 0, 0), ('t-tag', 'p', 0, 0), ('t-dot', 'p', 0, 0), ('t-googlemail', 'p', 0, 0)`)
	require.NoError(t, err)
	seed := []struct {
		id, tenant, email, status string
	}{
		{"old-tag", "t", "zoe+old@gmail.com", "pending"},
		{"new-dots", "t", "z.o.e@googlemail.com", "pending"}, // same mailbox, newer: survives
		{"tagged", "t", "bob+jira@corp.com", "pending"},
		{"trailing-dot", "t", "carol@corp.com.", "pending"},
		{"dots-kept", "t", "d.ave@corp.com", "pending"},
		{"non-ascii", "t", "zoé+x@corp.com", "pending"},
		{"kelvin", "t", "\u212aate@corp.com", "pending"}, // lowers to kate@ under en_US; not the same mailbox
		{"kate", "t", "KATE+x@corp.com", "pending"},
		{"settled", "t", "eve+x@corp.com", "accepted"},
		// The older invitation is already canonical and the newer one is not:
		// the older must be revoked before the newer takes its address.
		{"canonical-older-1", "t-tag", "zoe@gmail.com", "pending"},
		{"tagged-newer", "t-tag", "zoe+team@gmail.com", "pending"},
		{"canonical-older-2", "t-dot", "zoe@gmail.com", "pending"},
		{"dotted-newer", "t-dot", "z.oe@gmail.com", "pending"},
		{"canonical-older-3", "t-googlemail", "zoe@gmail.com", "pending"},
		{"googlemail-newer", "t-googlemail", "z.o.e@googlemail.com", "pending"},
	}
	for i, s := range seed {
		_, err := conn.Exec(ctx, `
			INSERT INTO tenant_invitations (id, project_id, tenant_id, token_hash, email, status, expires_at_ms, created_at_ms)
			VALUES ($1, 'p', $2, $1, $3, $4, 9999999999999, $5)`, s.id, s.tenant, s.email, s.status, i)
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
	for _, id := range []string{"new-dots", "tagged", "trailing-dot", "dots-kept", "kate"} {
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
	require.Equal(t, [2]string{"\u212aate@corp.com", "pending"}, got["kelvin"])
	require.Equal(t, [2]string{"kate@corp.com", "pending"}, got["kate"])
	require.Equal(t, [2]string{"eve+x@corp.com", "accepted"}, got["settled"])
	for _, pair := range [][2]string{
		{"canonical-older-1", "tagged-newer"},
		{"canonical-older-2", "dotted-newer"},
		{"canonical-older-3", "googlemail-newer"},
	} {
		require.Equal(t, [2]string{"zoe@gmail.com", "revoked"}, got[pair[0]], pair[0])
		require.Equal(t, [2]string{"zoe@gmail.com", "pending"}, got[pair[1]], pair[1])
	}
}
