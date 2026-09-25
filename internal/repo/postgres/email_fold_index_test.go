package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// emailFoldIndexProjectUsers is how many accounts the plan probe seeds: enough
// that a scan of the project costs more than an index probe, so the planner
// picks the index whenever it is allowed to.
const emailFoldIndexProjectUsers = 2000

// TestPostgres_EmailLookupsUseTheIndexUnderRLS proves the account-email
// lookups reach users_project_email_fold_uidx as an index condition when they
// run as a role that row-level security applies to. Under FORCE RLS a
// predicate can be evaluated ahead of the row policy — and so drive an index
// scan — only if it is leakproof; lower(email) is not, and made every lookup
// scan the whole project. A superuser or BYPASSRLS role skips the policy, so
// the plan is taken as a least-privilege role, as production runs.
func TestPostgres_EmailLookupsUseTheIndexUnderRLS(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres email-index plan test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, runMigrations(dsn))

	projectID := fmt.Sprintf("email-fold-plan-%d", time.Now().UnixNano())
	admin, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectID})
	require.NoError(t, err)
	defer admin.Close()
	seedProject(ctx, t, admin, projectID)

	appDSN := provisionRLSAppRole(ctx, t, dsn)
	app, err := pgx.Connect(ctx, appDSN)
	require.NoError(t, err)
	defer func() { _ = app.Close(ctx) }()
	var isSuper, canBypass bool
	require.NoError(t, app.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper, &canBypass))
	require.False(t, isSuper || canBypass, "the plan must be taken by a role row-level security applies to")

	_, err = app.Exec(ctx, `SELECT set_config($1, $2, false)`, rlsGUC, projectID)
	require.NoError(t, err)
	_, err = app.Exec(ctx, `
		INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms)
		SELECT $1 || '-' || g, $1, 'User' || g || '@Example.com', g, g
		FROM generate_series(1, $2::int) AS g`, projectID, emailFoldIndexProjectUsers)
	require.NoError(t, err)
	// Only the table's owner may ANALYZE it; the app role would be skipped
	// with a warning and the plan costed on no statistics.
	owner, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = owner.Close(ctx) }()
	_, err = owner.Exec(ctx, `ANALYZE users`)
	require.NoError(t, err)

	countQuery, countArgs := admin.countUsersQuery(service.UserListFilter{Email: "USER7@example.com"})
	nodesQuery, nodesArgs := admin.userNodesQuery(map[string]any{dbUfEmail: "USER7@example.com"})
	for _, probe := range []struct {
		name  string
		query string
		args  []any
	}{
		{"FindUserByEmail", findUserByEmailQuery, []any{projectID, service.FoldEmail("USER7@example.com")}},
		{"FindUsersByEmails", findUsersByEmailsQuery, []any{projectID, foldEmails([]string{"USER7@example.com", "user8@EXAMPLE.com"})}},
		{"ListUsers and CountUsers email filter", countQuery, countArgs},
		{"QueryNodes users email filter", nodesQuery, nodesArgs},
	} {
		t.Run(probe.name, func(t *testing.T) {
			rows, err := app.Query(ctx, `EXPLAIN (COSTS OFF) `+probe.query, probe.args...)
			require.NoError(t, err)
			plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
			require.NoError(t, err)
			text := strings.Join(plan, "\n")
			require.Contains(t, text, "users_project_email_fold_uidx", "plan:\n%s", text)
			require.True(t, hasIndexCondOn(plan, "email_fold"),
				"email_fold must be an index condition, not a filter over the project's rows; plan:\n%s", text)
		})
	}
}

// hasIndexCondOn reports whether an EXPLAIN plan applies column as an index
// condition (rather than as a filter over the scanned rows).
func hasIndexCondOn(plan []string, column string) bool {
	for _, line := range plan {
		if strings.Contains(line, "Index Cond:") && strings.Contains(line, column) {
			return true
		}
	}
	return false
}
