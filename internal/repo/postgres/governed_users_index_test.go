package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// governedUsersIndexProjectUsers is how many accounts the plan probe seeds on
// top of the governance fixture's: enough that a scan of the project costs
// more than an index probe, so the planner picks the index whenever it may.
const governedUsersIndexProjectUsers = 2000

// TestPostgres_GovernanceRevocationFindsAccountsThroughTheDomainIndex proves
// that a 0046 governance trigger finds the accounts on a domain through
// users_project_email_domain_idx, as an index condition, when it runs as a
// role row-level security applies to. Under FORCE RLS only a leakproof
// predicate can drive an index scan, so an expression index on the email's
// domain would serve only project_id and every fire would read the whole
// project. It also proves the trigger reads the accounts once per fire, and
// not at all when the change involves no domain.
func TestPostgres_GovernanceRevocationFindsAccountsThroughTheDomainIndex(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)

	app, err := pgx.Connect(ctx, roleDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = app.Close(context.WithoutCancel(ctx)) })
	var isSuper, canBypass bool
	require.NoError(t, app.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper, &canBypass))
	require.False(t, isSuper || canBypass, "the trigger must run as a role row-level security applies to")

	_, err = app.Exec(ctx, `SELECT set_config($1, $2, false)`, rlsGUC, f.project)
	require.NoError(t, err)
	_, err = app.Exec(ctx, `
		INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms)
		SELECT $1 || '-bulk-' || g, $1, 'user' || g || '@d' || (g % 50) || '.example.test', g, g
		FROM generate_series(1, $2::int) AS g`, f.project, governedUsersIndexProjectUsers)
	require.NoError(t, err)
	// Only the table's owner may ANALYZE it; the app role would be skipped
	// with a warning and the plan costed on no statistics.
	_, err = f.raw.Exec(ctx, `ANALYZE users`)
	require.NoError(t, err)

	t.Run("the domain is an index condition", func(t *testing.T) {
		const lookup = `SELECT user_id FROM agent_oauth_domain_users($1, $2::text[])`
		rows, err := app.Query(ctx, `EXPLAIN (COSTS OFF) `+lookup, f.project, []string{govDomain})
		require.NoError(t, err)
		custom, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		// The trigger runs the lookup with its arguments as parameters, which
		// a cached generic plan does not see. The statement goes unparsed by
		// the driver, which would otherwise ask for values for them.
		results, err := app.PgConn().Exec(ctx, `EXPLAIN (COSTS OFF, GENERIC_PLAN) `+lookup).ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		var generic []string
		for _, row := range results[0].Rows {
			generic = append(generic, string(row[0]))
		}
		for name, plan := range map[string][]string{"custom plan": custom, "generic plan": generic} {
			text := strings.Join(plan, "\n")
			require.Contains(t, text, "users_project_email_domain_idx", "%s:\n%s", name, text)
			require.True(t, hasIndexCondOn(plan, "email_domain"),
				"%s: email_domain must be an index condition, not a filter over the project's accounts:\n%s", name, text)
			require.NotContains(t, text, "Seq Scan on users", "%s:\n%s", name, text)
		}
	})

	t.Run("a change on no domain reads no account", func(t *testing.T) {
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		tag, err := tx.Exec(ctx, `UPDATE tenants SET status = $3 WHERE project_id = $1 AND id = $2`,
			f.project, f.tenant, service.TenantStatusSuspended)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
		require.False(t, holdsRelationLock(ctx, t, tx, "users"),
			"a tenant with no verified or primary domain governs no account by its email, so users is not read")
	})

	t.Run("a change on a domain reads the accounts once, through the index", func(t *testing.T) {
		claim := f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusPending)
		// The counters below are what this backend has not yet reported;
		// report the rest first, so they count this transaction alone.
		_, err := app.Exec(ctx, `SELECT pg_stat_force_next_flush()`)
		require.NoError(t, err)
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		tag, err := tx.Exec(ctx, `UPDATE domains SET status = $3 WHERE project_id = $1 AND id = $2`,
			f.project, claim, service.DomainStatusVerified)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
		require.True(t, holdsRelationLock(ctx, t, tx, "users"), "verifying a domain must read the accounts on it")
		var seqScans, domainIndexScans int64
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT pg_stat_get_xact_numscans('users'::regclass),
			       pg_stat_get_xact_numscans('users_project_email_domain_idx'::regclass)`,
		).Scan(&seqScans, &domainIndexScans))
		require.Zero(t, seqScans, "the trigger must not scan users")
		require.EqualValues(t, 1, domainIndexScans, "the trigger must read the accounts on the domain once")
	})
}

// holdsRelationLock reports whether the transaction holds any lock on table,
// which it does from the first statement that reads it until it ends.
func holdsRelationLock(ctx context.Context, t *testing.T, tx pgx.Tx, table string) bool {
	t.Helper()
	var held bool
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_locks
		                WHERE locktype = 'relation' AND pid = pg_backend_pid()
		                  AND relation = $1::regclass)`, table).Scan(&held))
	return held
}
