package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestPostgres_RLS_Smoke proves the migration-0016 Row-Level Security
// boundary against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN.
// It skips when the env var is unset so the default unit-test job passes
// without a backing service; the dockerpostgres container test
// (rls_dockertest_test.go) drives the same body against a throwaway
// container so the proof runs in CI's coverage gate too.
func TestPostgres_RLS_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres RLS smoke test")
	}
	runRLSProof(t, dsn)
}

// runRLSProof is the shared RLS assertion body. It writes a user under
// project A through the real repository (which sets the RLS GUC to A on its
// pooled connections), then opens a SEPARATE raw connection — one that does
// NOT go through the repo's PrepareConn hook and does NOT add a
// `WHERE project_id = …` predicate — and drives the RLS policy directly by
// setting the app.current_project_id GUC by hand:
//
//   - GUC = A  ⇒ the raw, unfiltered `SELECT * FROM users` sees A's row.
//   - GUC = B  ⇒ the SAME unfiltered query sees ZERO rows (RLS hides A's row
//     from project B — this is the leak the application WHERE clause alone
//     could not prevent if a query forgot it).
//   - GUC unset ⇒ ZERO rows (fail closed: missing_ok=true ⇒ NULL ⇒ no match).
//
// Because the raw query has no project_id predicate, a non-empty result for
// B (or for the unset case) could only come from a row the database itself
// exposed — i.e. it proves RLS, not the Go-side filter.
func runRLSProof(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))

	// RLS is bypassed by SUPERUSER and BYPASSRLS roles regardless of FORCE.
	// The default test DSN typically connects as a superuser (the
	// testcontainers postgres module's POSTGRES_USER is a superuser), which
	// would make this proof vacuous. So provision a dedicated NON-superuser
	// application role and run BOTH the repository and the raw probe as it —
	// exactly the role posture docs/postgres-rls.md requires in production.
	appDSN := provisionRLSAppRole(ctx, t, dsn)

	const projectA = "rls-project-a"
	const projectB = "rls-project-b"

	// Seed both project rows (the project_id FK target) as the admin/owner;
	// the projects table is control-plane and has no RLS.
	admin, err := New(ctx, Config{
		DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectA,
	})
	require.NoError(t, err)
	defer admin.Close()
	seedProject(ctx, t, admin, projectA)
	seedProject(ctx, t, admin, projectB)

	// Real repo bound to project A, connecting as the NON-superuser app role.
	repoA, err := New(ctx, Config{
		DSN:         appDSN,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		ProjectID:   projectA,
	})
	require.NoError(t, err)
	defer repoA.Close()

	now := time.Now()
	uidA, err := repoA.CreateUser(ctx, &service.User{
		Email:     "rls-a@example.com",
		Name:      "RLS A",
		Role:      "member",
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NotEmpty(t, uidA)

	// Raw connection AS THE NON-SUPERUSER APP ROLE that bypasses the repo's
	// PrepareConn GUC plumbing AND issues an UNFILTERED query (no project_id
	// predicate). Whatever it sees is exactly what the RLS policy admits.
	raw, err := pgx.Connect(ctx, appDSN)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	// Guard the whole proof: if the probe role can bypass RLS, the assertions
	// below are meaningless. Assert it cannot, up front.
	var isSuper, canBypass bool
	require.NoError(t, raw.QueryRow(
		ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&isSuper, &canBypass))
	require.False(t, isSuper, "RLS proof role must not be a superuser")
	require.False(t, canBypass, "RLS proof role must not have BYPASSRLS")

	countAllUsers := func() int {
		t.Helper()
		var n int
		// No project_id predicate: this is the "forgot the WHERE clause" path.
		err := raw.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
		require.NoError(t, err)
		return n
	}
	setGUC := func(project string) {
		t.Helper()
		_, err := raw.Exec(ctx, `SELECT set_config('app.current_project_id', $1, false)`, project)
		require.NoError(t, err)
	}
	resetGUC := func() {
		t.Helper()
		_, err := raw.Exec(ctx, `RESET app.current_project_id`)
		require.NoError(t, err)
	}

	// GUC unset ⇒ fail closed: zero rows even with no WHERE clause.
	resetGUC()
	require.Equal(t, 0, countAllUsers(),
		"RLS must fail closed: an unset app.current_project_id GUC must expose zero rows")

	// GUC = B ⇒ A's row is invisible to project B (the cross-project leak
	// the application filter alone could not stop on a predicate-less query).
	setGUC(projectB)
	require.Equal(t, 0, countAllUsers(),
		"RLS leak: project B saw project A's rows via a predicate-less query")

	// GUC = A ⇒ A's own row IS visible, proving the policy admits the bound
	// project (and is not merely hiding everything).
	setGUC(projectA)
	require.Equal(t, 1, countAllUsers(),
		"RLS over-restricts: project A could not see its own row")
	var gotEmail string
	require.NoError(t, raw.QueryRow(ctx, `SELECT email FROM users`).Scan(&gotEmail))
	require.Equal(t, "rls-a@example.com", gotEmail)
}

// provisionRLSAppRole creates (idempotently) a NON-superuser, non-BYPASSRLS
// login role and returns a DSN that authenticates as it. The role is granted
// schema usage and full DML on every table plus sequence usage, so the
// repository can read and write through it — but because it neither owns the
// tables nor can bypass RLS, the migration-0016 policies apply to it. This is
// the production-correct posture: serve traffic as a least-privilege role
// that is subject to RLS (see docs/postgres-rls.md).
func provisionRLSAppRole(ctx context.Context, t *testing.T, adminDSN string) string {
	t.Helper()

	const (
		appRole = "identity_rls_app"
		appPass = "identity_rls_app_pw"
	)

	admin, err := pgx.Connect(ctx, adminDSN)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()

	// CREATE ROLE has no IF NOT EXISTS; do it conditionally so the proof is
	// re-runnable against a persistent database (the env-DSN smoke path).
	_, err = admin.Exec(ctx, fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
				CREATE ROLE %[1]s LOGIN PASSWORD '%[2]s' NOSUPERUSER NOBYPASSRLS;
			END IF;
		END
		$$;
	`, appRole, appPass))
	require.NoError(t, err)

	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + appRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + appRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + appRole,
	} {
		_, err := admin.Exec(ctx, stmt)
		require.NoError(t, err)
	}

	// Build the app-role DSN by swapping userinfo on the admin DSN.
	u, err := url.Parse(adminDSN)
	require.NoError(t, err)
	u.User = url.UserPassword(appRole, appPass)
	return u.String()
}
