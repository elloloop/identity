package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAgentCreationReceiptFailureRollsBackSubject(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, "agent-receipt-rollback")
	owner, err := repo.CreateUser(ctx, &service.User{Status: service.StatusActive, Role: service.RoleMember})
	require.NoError(t, err)
	_, err = repo.db.Exec(ctx, `CREATE TRIGGER reject_receipt BEFORE INSERT ON agent_creation_receipts BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END;`)
	require.NoError(t, err)
	request := service.AgentCreation{CallerID: owner, RequestID: "lost-response", Fingerprint: strings.Repeat("a", 64), OwnerLimit: 1, Agent: &service.User{Kind: service.UserKindAgent, OwnerUserID: owner, Status: service.StatusActive, Role: service.RoleMember}}
	_, _, err = repo.CreateAgent(ctx, request)
	require.Error(t, err)
	count, err := repo.CountUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: owner})
	require.NoError(t, err)
	require.Zero(t, count)
	_, err = repo.db.Exec(ctx, `DROP TRIGGER reject_receipt`)
	require.NoError(t, err)
	_, created, err := repo.CreateAgent(ctx, request)
	require.NoError(t, err)
	require.True(t, created)
}

func TestAgentCreationAcrossIndependentSQLiteConnections(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Path: filepath.Join(t.TempDir(), "identity.sqlite"), ProjectID: "receipt-concurrent"}
	first, err := New(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(first.Close)
	require.NoError(t, first.EnsureDefaultProject(ctx, cfg.ProjectID, "Example"))
	second, err := New(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(second.Close)
	owner, err := first.CreateUser(ctx, &service.User{Status: service.StatusActive, Role: service.RoleMember})
	require.NoError(t, err)
	request := service.AgentCreation{CallerID: owner, RequestID: "stable-key", Fingerprint: strings.Repeat("a", 64), OwnerLimit: 1, Agent: &service.User{Kind: service.UserKindAgent, OwnerUserID: owner, Status: service.StatusActive, Role: service.RoleMember}}
	type result struct {
		agent   *service.User
		created bool
		err     error
	}
	results := make(chan result, 12)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			repo := first
			if i%2 == 1 {
				repo = second
			}
			a, c, e := repo.CreateAgent(ctx, request)
			results <- result{a, c, e}
		})
	}
	wg.Wait()
	close(results)
	id := ""
	created := 0
	for result := range results {
		require.NoError(t, result.err)
		if id == "" {
			id = result.agent.ID
		}
		require.Equal(t, id, result.agent.ID)
		if result.created {
			created++
		}
	}
	require.Equal(t, 1, created)
}
