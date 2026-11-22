package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestGuardianDeletionReceiptRollsBackWithErasure(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx := context.Background()
	repo, err := New(ctx, Config{DSN: dsn, ProjectID: "receipt-rollback", AutoMigrate: true})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	seedProject(ctx, t, repo, "receipt-rollback")
	guardian, err := repo.CreateUser(ctx, &service.User{Email: "guardian@example.test", Status: service.StatusActive})
	require.NoError(t, err)
	child, err := repo.CreateUser(ctx, &service.User{Username: "child.example", Status: service.StatusActive})
	require.NoError(t, err)
	require.NoError(t, repo.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child}))
	_, err = repo.pool.Exec(ctx, `CREATE FUNCTION reject_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rollback'; END; $$`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = repo.pool.Exec(context.Background(), `DROP FUNCTION reject_erasure() CASCADE`) })
	_, err = repo.pool.Exec(ctx, `CREATE TRIGGER reject_erasure BEFORE DELETE ON users FOR EACH ROW WHEN (OLD.project_id='receipt-rollback') EXECUTE FUNCTION reject_erasure()`)
	require.NoError(t, err)
	require.Error(t, repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1000))
	completed, err := repo.HasGuardianDeletionReceipt(ctx, guardian, child)
	require.NoError(t, err)
	require.False(t, completed)
	user, err := repo.GetUser(ctx, child)
	require.NoError(t, err)
	require.NotNil(t, user)
	edge, err := repo.GetGuardianEdge(ctx, guardian, child)
	require.NoError(t, err)
	require.NotNil(t, edge)
	_, err = repo.pool.Exec(ctx, `DROP TRIGGER reject_erasure ON users`)
	require.NoError(t, err)
	require.NoError(t, repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1001))
	completed, err = repo.HasGuardianDeletionReceipt(ctx, guardian, child)
	require.NoError(t, err)
	require.True(t, completed)
}
