package conformance

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func runMachineKeyChallenges(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/MachineKeyChallenges", func(t *testing.T) {
		ctx := context.Background()
		fresh := func(t *testing.T) (machineFixture, *service.AgentMachineChallenge) {
			t.Helper()
			fixture := seedAgentMachine(ctx, t, driver.NewRepo(t))
			now := time.Now().UnixMilli()
			challenge := &service.AgentMachineChallenge{ID: "challenge", MachineID: fixture.machine.ID, Operation: service.AgentMachineRoster, Binding: strings.Repeat("a", 64), PublicKey: strings.Repeat("b", 64), Message: "issuer/project/machine/operation/nonce", CreatedAtMs: now, ExpiresAtMs: now + service.AgentMachineChallengeLifetimeMs}
			return fixture, challenge
		}
		t.Run("AtomicConsumptionAndIsolation", func(t *testing.T) {
			f, c := fresh(t)
			require.NoError(t, f.repo.CreateAgentMachineChallenge(ctx, c))
			require.ErrorIs(t, f.repo.CreateAgentMachineChallenge(ctx, c), service.ErrAlreadyExists)
			stored, err := f.repo.GetAgentMachineChallenge(ctx, c.ID)
			require.NoError(t, err)
			require.Equal(t, c, stored)
			stored.Message = "caller mutation"
			stored, err = f.repo.GetAgentMachineChallenge(ctx, c.ID)
			require.NoError(t, err)
			require.Equal(t, c.Message, stored.Message)
			consumed, err := f.repo.ConsumeAgentMachineChallenge(ctx, c.ID, c.CreatedAtMs-1)
			require.NoError(t, err)
			require.False(t, consumed)
			if driver.BindProject != nil {
				other := driver.BindProject(t, f.base, "other-machine-project").(service.AgentMachineRepository)
				hidden, err := other.GetAgentMachineChallenge(ctx, c.ID)
				require.NoError(t, err)
				require.Nil(t, hidden)
				used, err := other.ConsumeAgentMachineChallenge(ctx, c.ID, c.CreatedAtMs)
				require.NoError(t, err)
				require.False(t, used)
			}
			results := make(chan bool, 16)
			failures := make(chan error, 16)
			var group sync.WaitGroup
			for range 16 {
				group.Go(func() {
					used, err := f.repo.ConsumeAgentMachineChallenge(ctx, c.ID, c.CreatedAtMs)
					results <- used
					failures <- err
				})
			}
			group.Wait()
			close(results)
			close(failures)
			for err := range failures {
				require.NoError(t, err)
			}
			successes := 0
			for used := range results {
				if used {
					successes++
				}
			}
			require.Equal(t, 1, successes)
			stored, err = f.repo.GetAgentMachineChallenge(ctx, c.ID)
			require.NoError(t, err)
			require.Nil(t, stored)
		})
		t.Run("ExpiryCapAndRevocation", func(t *testing.T) {
			f, c := fresh(t)
			require.ErrorIs(t, f.repo.CreateAgentMachineChallenge(ctx, nil), service.ErrInvalidArgument)
			for i := range service.MaxAgentMachineChallenges {
				copy := *c
				copy.ID = fmt.Sprintf("challenge-%d", i)
				require.NoError(t, f.repo.CreateAgentMachineChallenge(ctx, &copy))
			}
			require.ErrorIs(t, f.repo.CreateAgentMachineChallenge(ctx, c), service.ErrAgentMachineChallengeLimit)
			consumed, err := f.repo.ConsumeAgentMachineChallenge(ctx, "challenge-0", c.ExpiresAtMs)
			require.NoError(t, err)
			require.False(t, consumed)
			c.CreatedAtMs = c.ExpiresAtMs
			c.ExpiresAtMs += service.AgentMachineChallengeLifetimeMs
			require.NoError(t, f.repo.CreateAgentMachineChallenge(ctx, c))
			gone, err := f.repo.GetAgentMachineChallenge(ctx, "challenge-0")
			require.NoError(t, err)
			require.Nil(t, gone)
			_, err = f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: f.machine.OwnerID, AtMs: c.CreatedAtMs})
			require.NoError(t, err)
			c.ID = "after-revoke"
			require.ErrorIs(t, f.repo.CreateAgentMachineChallenge(ctx, c), service.ErrAgentOAuthGrant)
		})

		t.Run("BoundedSweepPreservesLiveChallengesAndDurableGrants", func(t *testing.T) {
			f, c := fresh(t)
			grant := f.ensure(ctx, t, "durable-child")
			for _, id := range []string{"expired-a", "expired-b"} {
				copy := *c
				copy.ID = id
				require.NoError(t, f.repo.CreateAgentMachineChallenge(ctx, &copy))
			}
			live := *c
			live.ID = "live"
			live.CreatedAtMs++
			live.ExpiresAtMs++
			require.NoError(t, f.repo.CreateAgentMachineChallenge(ctx, &live))
			require.ErrorIs(t, f.repo.DeleteExpiredAgentMachineChallenges(ctx, c.ExpiresAtMs, 0), service.ErrInvalidArgument)
			require.NoError(t, f.repo.DeleteExpiredAgentMachineChallenges(ctx, c.ExpiresAtMs, 1))
			remaining := 0
			for _, id := range []string{"expired-a", "expired-b"} {
				stored, err := f.repo.GetAgentMachineChallenge(ctx, id)
				require.NoError(t, err)
				if stored != nil {
					remaining++
				}
			}
			require.Equal(t, 1, remaining)
			require.NoError(t, f.repo.DeleteExpiredAgentMachineChallenges(ctx, c.ExpiresAtMs, 100))
			stored, err := f.repo.GetAgentMachineChallenge(ctx, live.ID)
			require.NoError(t, err)
			require.Equal(t, &live, stored)
			durable, err := f.oauth.GetAgentAuthorization(ctx, grant.ID)
			require.NoError(t, err)
			require.Equal(t, grant, durable)
		})
		if driver.Reopen != nil {
			t.Run("SurvivesRestartWithoutReplay", func(t *testing.T) {
				f, c := fresh(t)
				require.NoError(t, f.repo.CreateAgentMachineChallenge(ctx, c))
				reopened := driver.Reopen(t, f.base).(service.AgentMachineRepository)
				stored, err := reopened.GetAgentMachineChallenge(ctx, c.ID)
				require.NoError(t, err)
				require.Equal(t, c, stored)
				used, err := reopened.ConsumeAgentMachineChallenge(ctx, c.ID, c.CreatedAtMs)
				require.NoError(t, err)
				require.True(t, used)
				used, err = reopened.ConsumeAgentMachineChallenge(ctx, c.ID, c.CreatedAtMs)
				require.NoError(t, err)
				require.False(t, used)
			})
		}
	})
}
