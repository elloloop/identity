package sqlite

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestGuardianDeletionReceiptRollsBackWithErasure(t *testing.T) {
	repo := newTestRepo(t, "receipt-rollback")
	ctx := context.Background()
	guardian, err := repo.CreateUser(ctx, &service.User{Email: "guardian@example.test", Status: service.StatusActive})
	require.NoError(t, err)
	child, err := repo.CreateUser(ctx, &service.User{Username: "child.example", Status: service.StatusActive})
	require.NoError(t, err)
	require.NoError(t, repo.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child}))
	_, err = repo.db.Exec(ctx, `CREATE TRIGGER reject_erasure BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'fixture rollback'); END`)
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
	_, err = repo.db.Exec(ctx, `DROP TRIGGER reject_erasure`)
	require.NoError(t, err)
	require.NoError(t, repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1001))
	completed, err = repo.HasGuardianDeletionReceipt(ctx, guardian, child)
	require.NoError(t, err)
	require.True(t, completed)
}
