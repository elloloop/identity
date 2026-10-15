package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAgentCreationReceiptFailureRollsBackSubject(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx := context.Background()
	repo, err := New(ctx, Config{DSN: dsn, ProjectID: "receipt-rollback", AutoMigrate: true})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	seedProject(ctx, t, repo, "receipt-rollback")
	owner, err := repo.CreateUser(ctx, &service.User{Status: service.StatusActive, Role: service.RoleMember})
	require.NoError(t, err)
	_, err = repo.pool.Exec(ctx, `CREATE FUNCTION reject_test_agent_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'receipt unavailable'; END; $$;
 CREATE TRIGGER reject_test_agent_receipt BEFORE INSERT ON agent_creation_receipts FOR EACH ROW WHEN(NEW.project_id='receipt-rollback') EXECUTE FUNCTION reject_test_agent_receipt();`)
	require.NoError(t, err)
	remove := func() {
		_, dropErr := repo.pool.Exec(ctx, `DROP TRIGGER IF EXISTS reject_test_agent_receipt ON agent_creation_receipts; DROP FUNCTION IF EXISTS reject_test_agent_receipt();`)
		require.NoError(t, dropErr)
	}
	t.Cleanup(remove)
	request := service.AgentCreation{CallerID: owner, RequestID: "lost-response", Fingerprint: strings.Repeat("a", 64), OwnerLimit: 1, Agent: &service.User{Kind: service.UserKindAgent, OwnerUserID: owner, Status: service.StatusActive, Role: service.RoleMember}}
	_, _, err = repo.CreateAgent(ctx, request)
	require.Error(t, err)
	count, err := repo.CountUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: owner})
	require.NoError(t, err)
	require.Zero(t, count)
	remove()
	_, created, err := repo.CreateAgent(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
}
