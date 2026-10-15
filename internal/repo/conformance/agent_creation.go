package conformance

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func runAgentCreationConformance(t *testing.T, driver Driver) {
	t.Helper()
	ctx := context.Background()
	person := func(t *testing.T, repo service.Repository, name string) string {
		t.Helper()
		id, err := repo.CreateUser(ctx, &service.User{Name: name, Role: service.RoleAdmin, Status: service.StatusActive})
		require.NoError(t, err)
		return id
	}
	fixture := func(t *testing.T) (service.Repository, service.AgentCreation, string) {
		t.Helper()
		repo := driver.NewRepo(t)
		owner := person(t, repo, "Owner")
		caller := person(t, repo, "Caller")
		request := service.AgentCreation{CallerID: caller, RequestID: "retry-key", Fingerprint: strings.Repeat("a", 64), OwnerLimit: 1, Agent: &service.User{Kind: service.UserKindAgent, OwnerUserID: owner, Status: service.StatusActive, Role: service.RoleMember, Name: "Helper"}}
		return repo, request, owner
	}
	t.Run(driver.Name+"/AgentCreation", func(t *testing.T) {
		t.Run("ReplayAndConflictAtCapacity", func(t *testing.T) {
			repo, request, _ := fixture(t)
			first, created, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			require.True(t, created)
			require.NoError(t, repo.UpdateUser(ctx, first.ID, map[string]any{"name": "Updated profile"}))
			replay, created, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			require.False(t, created)
			require.Equal(t, first.ID, replay.ID)
			require.Equal(t, "Updated profile", replay.Name)
			conflict := request
			conflict.Fingerprint = strings.Repeat("b", 64)
			_, _, err = repo.CreateAgent(ctx, conflict)
			require.ErrorIs(t, err, service.ErrAlreadyExists)
			other := request
			other.RequestID = "new-key"
			_, _, err = repo.CreateAgent(ctx, other)
			require.ErrorIs(t, err, service.ErrAgentLimitReached)
		})
		t.Run("ConcurrentLostResponse", func(t *testing.T) {
			repo, request, _ := fixture(t)
			const workers = 16
			type result struct {
				agent   *service.User
				created bool
				err     error
			}
			results := make(chan result, workers)
			var wg sync.WaitGroup
			for range workers {
				wg.Go(func() { a, c, e := repo.CreateAgent(ctx, request); results <- result{a, c, e} })
			}
			wg.Wait()
			close(results)
			id := ""
			createdCount := 0
			for result := range results {
				require.NoError(t, result.err)
				if id == "" {
					id = result.agent.ID
				}
				require.Equal(t, id, result.agent.ID)
				if result.created {
					createdCount++
				}
			}
			require.Equal(t, 1, createdCount)
			users, err := repo.ListUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: request.Agent.OwnerUserID})
			require.NoError(t, err)
			require.Len(t, users, 1)
		})
		t.Run("ConcurrentCapacity", func(t *testing.T) {
			repo, request, _ := fixture(t)
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := range 8 {
				wg.Go(func() {
					copy := request
					copy.RequestID = fmt.Sprintf("key-%d", i)
					_, _, err := repo.CreateAgent(ctx, copy)
					errs <- err
				})
			}
			wg.Wait()
			close(errs)
			created := 0
			for err := range errs {
				if err == nil {
					created++
				} else {
					require.ErrorIs(t, err, service.ErrAgentLimitReached)
				}
			}
			require.Equal(t, 1, created)
		})
		t.Run("ReplayRacesOwnershipChange", func(t *testing.T) {
			repo, request, owner := fixture(t)
			agent, _, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			recipient := person(t, repo, "Recipient")
			start := make(chan struct{})
			replayDone := make(chan error, 1)
			go func() { <-start; _, _, replayErr := repo.CreateAgent(ctx, request); replayDone <- replayErr }()
			close(start)
			changed, err := repo.SetAgentOwnership(ctx, agent.ID, owner, recipient, "", 1)
			require.NoError(t, err)
			require.True(t, changed)
			if replayErr := <-replayDone; replayErr != nil {
				require.ErrorIs(t, replayErr, service.ErrPermissionDenied)
			}
			changed, err = repo.SetAgentOwnership(ctx, agent.ID, recipient, owner, "", 2)
			require.NoError(t, err)
			require.True(t, changed)
			_, _, err = repo.CreateAgent(ctx, request)
			require.ErrorIs(t, err, service.ErrPermissionDenied)
		})

		t.Run("MixedKeyedAndIndependentCapacity", func(t *testing.T) {
			repo, request, _ := fixture(t)
			var wg sync.WaitGroup
			results := make(chan error, 16)
			for i := range 16 {
				wg.Go(func() {
					copy := request
					if i%2 == 0 {
						copy.RequestID = ""
					}
					_, _, err := repo.CreateAgent(ctx, copy)
					results <- err
				})
			}
			wg.Wait()
			close(results)
			for err := range results {
				if err != nil {
					require.ErrorIs(t, err, service.ErrAgentLimitReached)
				}
			}
			count, err := repo.CountUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: request.Agent.OwnerUserID})
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
		t.Run("ReplayRacesAccountMerge", func(t *testing.T) {
			repo, request, owner := fixture(t)
			_, _, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			survivor := person(t, repo, "Survivor")
			start := make(chan struct{})
			done := make(chan error, 1)
			go func() { <-start; _, _, err := repo.CreateAgent(ctx, request); done <- err }()
			close(start)
			require.NoError(t, repo.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: owner, AtMs: 1}))
			if replayErr := <-done; replayErr != nil {
				require.ErrorIs(t, replayErr, service.ErrPermissionDenied)
			}
			_, _, err = repo.CreateAgent(ctx, request)
			require.ErrorIs(t, err, service.ErrPermissionDenied)
		})

		changes := map[string]func(*testing.T, service.Repository, service.AgentCreation, string, string){
			"TransferAwayAndBack": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				other := person(t, r, "Recipient")
				ok, err := r.SetAgentOwnership(ctx, id, owner, other, "", 1)
				require.NoError(t, err)
				require.True(t, ok)
				ok, err = r.SetAgentOwnership(ctx, id, other, owner, "", 2)
				require.NoError(t, err)
				require.True(t, ok)
			},
			"AcceptedTransferAndBack": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				other := person(t, r, "Recipient")
				ok, err := r.SetAgentOwnership(ctx, id, owner, owner, other, 1)
				require.NoError(t, err)
				require.True(t, ok)
				ok, err = r.SettleAgentTransfer(ctx, id, other, true, 2)
				require.NoError(t, err)
				require.True(t, ok)
				ok, err = r.SetAgentOwnership(ctx, id, other, owner, "", 3)
				require.NoError(t, err)
				require.True(t, ok)
			},
			"DeactivateReactivate": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				require.NoError(t, r.UpdateUser(ctx, id, map[string]any{"status": service.StatusDeactivated}))
				require.NoError(t, r.UpdateUser(ctx, id, map[string]any{"status": service.StatusActive}))
			},
			"OwnerDeactivateReactivate": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				require.NoError(t, r.UpdateUser(ctx, owner, map[string]any{"status": service.StatusDeactivated}))
				require.NoError(t, r.UpdateUser(ctx, owner, map[string]any{"status": service.StatusActive}))
			},
			"CallerAdminRevokedRestored": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				require.NoError(t, r.UpdateUser(ctx, q.CallerID, map[string]any{"role": service.RoleMember}))
				require.NoError(t, r.UpdateUser(ctx, q.CallerID, map[string]any{"role": service.RoleAdmin}))
			},
			"DeletedSubject": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				require.NoError(t, r.DeleteUser(ctx, id))
			},
			"MergedOwner": func(t *testing.T, r service.Repository, q service.AgentCreation, id, owner string) {
				t.Helper()
				survivor := person(t, r, "Survivor")
				require.NoError(t, r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: owner, AtMs: 3}))
			},
		}
		for name, change := range changes {
			t.Run(name, func(t *testing.T) {
				repo, request, owner := fixture(t)
				agent, _, err := repo.CreateAgent(ctx, request)
				require.NoError(t, err)
				change(t, repo, request, agent.ID, owner)
				_, _, err = repo.CreateAgent(ctx, request)
				require.ErrorIs(t, err, service.ErrPermissionDenied)
			})
		}
		t.Run("PendingOfferDoesNotInvalidate", func(t *testing.T) {
			repo, request, owner := fixture(t)
			agent, _, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			recipient := person(t, repo, "Recipient")
			ok, err := repo.SetAgentOwnership(ctx, agent.ID, owner, owner, recipient, 1)
			require.NoError(t, err)
			require.True(t, ok)
			replay, created, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			require.False(t, created)
			require.Equal(t, agent.ID, replay.ID)
		})
		t.Run("CallerIsolation", func(t *testing.T) {
			repo, request, owner := fixture(t)
			request.OwnerLimit = 5
			first, _, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			request.CallerID = owner
			other, created, err := repo.CreateAgent(ctx, request)
			require.NoError(t, err)
			require.True(t, created)
			require.NotEqual(t, first.ID, other.ID)
		})
		t.Run("CurrentAuthorityAndNoPartialCreation", func(t *testing.T) {
			repo, request, owner := fixture(t)
			require.NoError(t, repo.UpdateUser(ctx, request.CallerID, map[string]any{"role": service.RoleMember}))
			_, _, err := repo.CreateAgent(ctx, request)
			require.ErrorIs(t, err, service.ErrPermissionDenied)
			agents, err := repo.ListUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: owner})
			require.NoError(t, err)
			require.Empty(t, agents)
		})
		if driver.BindProject != nil {
			t.Run("ProjectIsolation", func(t *testing.T) {
				repo, request, _ := fixture(t)
				first, _, err := repo.CreateAgent(ctx, request)
				require.NoError(t, err)
				other := driver.BindProject(t, repo, "receipt-other-project")
				request.CallerID = person(t, other, "Caller")
				request.Agent = &service.User{Kind: service.UserKindAgent, OwnerUserID: request.CallerID, Status: service.StatusActive, Role: service.RoleMember, Name: "Helper"}
				agent, created, err := other.CreateAgent(ctx, request)
				require.NoError(t, err)
				require.True(t, created)
				require.NotEqual(t, first.ID, agent.ID)
			})
		}
	})
}
