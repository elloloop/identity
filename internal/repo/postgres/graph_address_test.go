package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/graph"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
)

// TestPostgres_GraphUserWritesHoldOneAccountPerAddress pins the rule that an
// address another account keeps as a recovery email is no account's primary
// email on the graph write path too: ExecuteAtomic's user create and update,
// and through them an admin's InviteUser. The conformance suite cannot reach
// that path, since the other drivers' ExecuteAtomic writes nothing.
func TestPostgres_GraphUserWritesHoldOneAccountPerAddress(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres graph address test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	projectID := fmt.Sprintf("graph-address-%d", time.Now().UnixNano())
	repo, err := New(ctx, Config{DSN: dsn, MaxConns: 4, ConnTimeout: 5 * time.Second, AutoMigrate: true, ProjectID: projectID})
	require.NoError(t, err)
	defer repo.Close()
	seedProject(ctx, t, repo, projectID)

	holder, err := repo.CreateUser(ctx, &service.User{Email: "holder@example.com", Status: "active", Role: "member"})
	require.NoError(t, err)
	require.NoError(t, repo.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: holder, Email: "spare@example.net", VerifiedAt: 1}, 5))
	other, err := repo.CreateUser(ctx, &service.User{Email: "other@example.com", Status: "active", Role: "member"})
	require.NoError(t, err)

	_, err = repo.ExecuteAtomic(ctx, projectID, "actor", []graph.Operation{{
		Type: graph.OpCreateNode, TypeID: dbTypeUser, Data: map[string]any{dbUfEmail: "Spare@example.net", dbUfName: "Taker"},
	}})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "create on a recovery email")
	_, err = repo.ExecuteAtomic(ctx, projectID, "actor", []graph.Operation{{
		Type: graph.OpUpdateNode, TypeID: dbTypeUser, NodeID: other, Patch: map[string]any{dbUfEmail: "spare@example.net"},
	}})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "update onto a recovery email")
	got, err := repo.GetUser(ctx, other)
	require.NoError(t, err)
	require.Equal(t, "other@example.com", got.Email, "a refused update changed nothing")
	_, err = repo.ExecuteAtomic(ctx, projectID, "actor", []graph.Operation{{
		Type: graph.OpUpdateNode, TypeID: dbTypeUser, NodeID: other, Patch: map[string]any{dbUfName: "Renamed"},
	}})
	require.NoError(t, err, "an update that sets no email takes no address")

	admin, err := repo.CreateUser(ctx, &service.User{Email: "admin@example.com", Status: "active", Role: "admin"})
	require.NoError(t, err)
	logger := zap.NewNop()
	svc := service.NewAdminService(repo, repo, projectID, audit.NewLogger(nil, projectID, logger), &config.Config{}, email.NewLogOnly(logger), logger)
	_, err = svc.InviteUser(ctx, admin, service.SessionSignIn{}, "spare@example.net", "Invitee", "member", "", 0, false)
	require.ErrorIs(t, err, service.ErrAlreadyExists, "an invitation of a recovery email")
	taken, err := repo.FindUserByEmail(ctx, "spare@example.net")
	require.NoError(t, err)
	require.Nil(t, taken, "no account was made on the recovery email")
	_, err = svc.InviteUser(ctx, admin, service.SessionSignIn{}, "invitee@example.com", "Invitee", "member", "", 0, false)
	require.NoError(t, err, "an invitation of a free address")
}
