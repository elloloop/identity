package postgres

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestPostgres_PhoneClaimTakeoverReleaseAndMergeDoNotDeadlock races a
// takeover of a number against its holder releasing it and against a merge
// of the holder: each takes the claims before the user rows, so none waits
// on another in a cycle (a deadlock would surface as SQLSTATE 40P01).
func TestPostgres_PhoneClaimTakeoverReleaseAndMergeDoNotDeadlock(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres phone-claim race test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	projectID := fmt.Sprintf("phone-claim-race-%d", time.Now().UnixNano())
	repo, err := New(ctx, Config{DSN: dsn, MaxConns: 8, ConnTimeout: 5 * time.Second, AutoMigrate: true, ProjectID: projectID})
	require.NoError(t, err)
	defer repo.Close()
	seedProject(ctx, t, repo, projectID)

	newUser := func(name string) string {
		id, err := repo.CreateUser(ctx, &service.User{Email: name + "@example.com", Status: "active", Role: "member"})
		require.NoError(t, err)
		return id
	}
	const number = "+14155550146"
	for i := range 40 {
		holder, taker, survivor := newUser(fmt.Sprintf("holder-%d", i)), newUser(fmt.Sprintf("taker-%d", i)), newUser(fmt.Sprintf("survivor-%d", i))
		at := int64(1_000 + i*10)
		_, err := repo.ClaimPhoneNumber(ctx, holder, number, at, 0)
		require.NoError(t, err)

		var wg sync.WaitGroup
		errs := make([]error, 3)
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, errs[0] = repo.ClaimPhoneNumber(ctx, taker, number, at+1, at+2)
		}()
		go func() {
			defer wg.Done()
			errs[1] = repo.ReleasePhoneNumber(ctx, holder, at+1)
		}()
		go func() {
			defer wg.Done()
			errs[2] = repo.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: holder, MovePhone: true, RecoveryEmailsMax: 5, AtMs: at + 1})
		}()
		wg.Wait()
		require.NoError(t, errs[0], "takeover, round %d", i)
		require.NoError(t, errs[1], "release, round %d", i)
		if errs[2] != nil {
			// The merge read the holder's phone after the takeover or the
			// release cleared it, so its MovePhone no longer holds.
			require.ErrorIs(t, errs[2], service.ErrMergeConflict, "merge, round %d", i)
		}
		require.NoError(t, repo.ReleasePhoneNumber(ctx, taker, at+3))
		require.NoError(t, repo.ReleasePhoneNumber(ctx, survivor, at+3))
	}
}
