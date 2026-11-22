package conformance

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func runReauthenticationConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/ReauthenticationBindingAndSingleUse", func(t *testing.T) {
		ctx := context.Background()
		repo := driver.NewRepo(t)
		user, err := repo.CreateUser(ctx, &service.User{Email: "parent@example.test", Status: service.StatusActive})
		require.NoError(t, err)
		record := &service.PasskeyChallengeRecord{UserID: user, Challenge: "challenge", ChallengeType: "authentication", Action: "account.pin.set", ResourceID: user, CreatedAt: 1000, ExpiresAt: 3000}
		id, err := repo.CreatePasskeyChallenge(ctx, record)
		require.NoError(t, err)
		read, err := repo.GetPasskeyChallenge(ctx, id)
		require.NoError(t, err)
		require.Equal(t, record, read)
		for _, binding := range [][3]string{{"other", record.Action, user}, {user, "other", user}, {user, record.Action, "other"}} {
			won, err := repo.ConsumeReauthenticationChallenge(ctx, id, binding[0], binding[1], binding[2], 2000)
			require.NoError(t, err)
			require.False(t, won)
		}
		for _, at := range []int64{999, 3000} {
			won, err := repo.ConsumeReauthenticationChallenge(ctx, id, user, record.Action, user, at)
			require.NoError(t, err)
			require.False(t, won)
		}
		var count atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				won, err := repo.ConsumeReauthenticationChallenge(ctx, id, user, record.Action, user, 2000)
				if err != nil {
					t.Errorf("consume: %v", err)
				}
				if won {
					count.Add(1)
				}
			})
		}
		wg.Wait()
		require.Equal(t, int32(1), count.Load())
		read, err = repo.GetPasskeyChallenge(ctx, id)
		require.NoError(t, err)
		require.Nil(t, read)
	})
	t.Run(driver.Name+"/ReauthenticationProjectIsolation", func(t *testing.T) {
		if driver.BindProject == nil {
			t.Skip("driver does not expose project binding")
		}
		base := driver.NewRepo(t)
		a := driver.BindProject(t, base, "reauth-a")
		b := driver.BindProject(t, base, "reauth-b")
		ctx := context.Background()
		id, err := a.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{UserID: "parent", Challenge: "challenge", ChallengeType: "authentication", Action: "account.pin.set", ResourceID: "parent", CreatedAt: 1000, ExpiresAt: 3000})
		require.NoError(t, err)
		won, err := b.ConsumeReauthenticationChallenge(ctx, id, "parent", "account.pin.set", "parent", 2000)
		require.NoError(t, err)
		require.False(t, won)
		won, err = a.ConsumeReauthenticationChallenge(ctx, id, "parent", "account.pin.set", "parent", 2000)
		require.NoError(t, err)
		require.True(t, won)
	})
}
