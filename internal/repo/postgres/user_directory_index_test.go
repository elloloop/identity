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

func TestPostgres_DefaultDirectoryCountIsIndexOnlyUnderRLS(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, runMigrations(dsn))
	projectID := fmt.Sprintf("person-directory-plan-%d", time.Now().UnixNano())
	repo, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectID})
	require.NoError(t, err)
	defer repo.Close()
	seedProject(ctx, t, repo, projectID)
	app, err := pgx.Connect(ctx, provisionRLSAppRole(ctx, t, dsn))
	require.NoError(t, err)
	defer func() { _ = app.Close(ctx) }()
	var super, bypass bool
	require.NoError(t, app.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass))
	require.False(t, super || bypass)
	_, err = app.Exec(ctx, `SELECT set_config($1, $2, false)`, rlsGUC, projectID)
	require.NoError(t, err)
	const people = 2000
	_, err = app.Exec(ctx, `INSERT INTO users (id, project_id, email, kind, owner_user_id, is_anonymous, created_at_ms, updated_at_ms)
		SELECT $1 || '-' || g, $1, CASE WHEN g <= $2 THEN 'person' || g || '@example.test' ELSE '' END,
		CASE WHEN g > $2 AND g <= $2*2 THEN 'agent' ELSE 'person' END,
		CASE WHEN g > $2 AND g <= $2*2 THEN 'owner' ELSE '' END,
		g > $2*2, g, g FROM generate_series(1, $2::int*3) AS g`, projectID, people)
	require.NoError(t, err)
	owner, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = owner.Close(ctx) }()
	_, err = owner.Exec(ctx, `VACUUM ANALYZE users`)
	require.NoError(t, err)
	query, args := repo.countUsersQuery(service.UserListFilter{})
	var count int
	require.NoError(t, app.QueryRow(ctx, query, args...).Scan(&count))
	require.Equal(t, people, count)
	rows, err := app.Query(ctx, `EXPLAIN (ANALYZE, COSTS OFF) `+query, args...)
	require.NoError(t, err)
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	text := strings.Join(plan, "\n")
	require.Contains(t, text, "Index Only Scan using users_project_created_id_person_idx", "plan:\n%s", text)
	require.Contains(t, text, "Heap Fetches: 0", "plan:\n%s", text)
	require.True(t, hasIndexCondOn(plan, "project_id"), "plan:\n%s", text)
}
