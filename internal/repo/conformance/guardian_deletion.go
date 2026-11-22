package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func guardianDeletionPair(t *testing.T, repo service.Repository) (string, string) {
	t.Helper()
	ctx := context.Background()
	guardian, err := repo.CreateUser(ctx, &service.User{Email: "guardian@example.test", Status: service.StatusActive})
	require.NoError(t, err)
	child, err := repo.CreateUser(ctx, &service.User{Username: "child.example", Status: service.StatusActive})
	require.NoError(t, err)
	require.NoError(t, repo.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 1}))
	return guardian, child
}

func runGuardianDeletionConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/GuardianDeletionReceipt", func(t *testing.T) {
		repo := driver.NewRepo(t)
		guardian, child := guardianDeletionPair(t, repo)
		ctx := context.Background()
		require.NoError(t, repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1000))
		if driver.Reopen != nil {
			repo = driver.Reopen(t, repo)
		}
		found, err := repo.HasGuardianDeletionReceipt(ctx, guardian, child)
		require.NoError(t, err)
		require.True(t, found)
		remaining, err := repo.GetUser(ctx, child)
		require.NoError(t, err)
		require.Nil(t, remaining)
		edge, err := repo.GetGuardianEdge(ctx, guardian, child)
		require.NoError(t, err)
		require.Nil(t, edge)
		for _, binding := range [][2]string{{"other", child}, {guardian, "other"}, {child, guardian}} {
			found, err := repo.HasGuardianDeletionReceipt(ctx, binding[0], binding[1])
			require.NoError(t, err)
			require.False(t, found)
		}
		if driver.BindProject != nil {
			other := driver.BindProject(t, repo, "other-erasure-project")
			found, err := other.HasGuardianDeletionReceipt(ctx, guardian, child)
			require.NoError(t, err)
			require.False(t, found)
		}
	})
	t.Run(driver.Name+"/OrdinaryDeletionHasNoGuardianReceipt", func(t *testing.T) {
		repo := driver.NewRepo(t)
		guardian, child := guardianDeletionPair(t, repo)
		ctx := context.Background()
		require.NoError(t, repo.DeleteUser(ctx, child))
		found, err := repo.HasGuardianDeletionReceipt(ctx, guardian, child)
		require.NoError(t, err)
		require.False(t, found)
		require.ErrorIs(t, repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1000), service.ErrPermissionDenied)
	})
	for _, denial := range []string{"revoked", "withdrawn", "guardian inactive", "foreign actor"} {
		t.Run(driver.Name+"/GuardianDeletionDenies/"+denial, func(t *testing.T) {
			repo := driver.NewRepo(t)
			guardian, child := guardianDeletionPair(t, repo)
			ctx := context.Background()
			switch denial {
			case "revoked":
				require.NoError(t, repo.DeleteGuardianEdge(ctx, guardian, child))
			case "withdrawn":
				require.NoError(t, repo.UpdateUser(ctx, child, map[string]any{"status": service.StatusPendingParentalConsent}))
			case "guardian inactive":
				require.NoError(t, repo.UpdateUser(ctx, guardian, map[string]any{"status": service.StatusDeactivated}))
			case "foreign actor":
				guardian = "other"
			}
			require.ErrorIs(t, repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1000), service.ErrPermissionDenied)
			found, err := repo.HasGuardianDeletionReceipt(ctx, guardian, child)
			require.NoError(t, err)
			require.False(t, found)
			remaining, err := repo.GetUser(ctx, child)
			require.NoError(t, err)
			require.NotNil(t, remaining)
		})
	}
	t.Run(driver.Name+"/CompetingGuardianDeletion", func(t *testing.T) {
		repo := driver.NewRepo(t)
		guardian, child := guardianDeletionPair(t, repo)
		ctx := context.Background()
		other, err := repo.CreateUser(ctx, &service.User{Email: "other@example.test", Status: service.StatusActive})
		require.NoError(t, err)
		require.NoError(t, repo.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: other, ChildUserID: child, CreatedAtMs: 1}))
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, actor := range []string{guardian, other} {
			wg.Go(func() { results[i] = repo.DeleteUserWithGuardianReceipt(ctx, child, actor, 1000) })
		}
		wg.Wait()
		wins := 0
		for i, actor := range []string{guardian, other} {
			found, err := repo.HasGuardianDeletionReceipt(ctx, actor, child)
			require.NoError(t, err)
			if results[i] == nil {
				wins++
				require.True(t, found)
			} else {
				require.True(t, errors.Is(results[i], service.ErrPermissionDenied), "unexpected deletion error: %v", results[i])
				require.False(t, found)
			}
		}
		require.Equal(t, 1, wins)
	})
	for _, operation := range []string{"edge removal", "consent withdrawal"} {
		t.Run(driver.Name+"/GuardianDeletionRaces/"+operation, func(t *testing.T) {
			repo := driver.NewRepo(t)
			guardian, child := guardianDeletionPair(t, repo)
			ctx := context.Background()
			var deletion, revocation error
			var wg sync.WaitGroup
			wg.Go(func() { deletion = repo.DeleteUserWithGuardianReceipt(ctx, child, guardian, 1000) })
			wg.Go(func() {
				if operation == "edge removal" {
					revocation = repo.DeleteGuardianEdge(ctx, guardian, child)
				} else {
					revocation = repo.UpdateUser(ctx, child, map[string]any{"status": service.StatusPendingParentalConsent})
				}
			})
			wg.Wait()
			completed, err := repo.HasGuardianDeletionReceipt(ctx, guardian, child)
			require.NoError(t, err)
			remaining, err := repo.GetUser(ctx, child)
			require.NoError(t, err)
			if deletion == nil {
				require.True(t, completed)
				require.Nil(t, remaining)
			} else {
				require.NoError(t, revocation)
				require.ErrorIs(t, deletion, service.ErrPermissionDenied)
				require.False(t, completed)
				require.NotNil(t, remaining)
			}
		})
	}
}
