//go:build realentdb

package entdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestRealEntDB_ConsumeRefreshTokenByHash_TwoReplicas_SingleWinner is
// the real-server regression test for issue #24 — the refresh-token
// consume transition must be atomic across replicas backed by the
// same EntDB tenant.
//
// Two Repository instances are constructed against the same tenant id
// to mimic two identity-server replicas sharing one backend. Both
// race to rotate the same unconsumed token via
// ConsumeRefreshTokenByHash. Exactly one repository must win; the
// other must observe service.ErrUnauthenticated — equivalent to "the
// other replica already rotated this token, treat as a replay." The
// final row state must have a non-zero consumed_at_ms.
//
// Without the SDK's UpdateIf precondition the previous
// read-then-write flow let both replicas observe consumed_at_ms=0,
// both proceed to mint new tokens, and both write the consumed state
// — a refresh-rotation double-spend that pairs every refresh request
// with N new access/refresh pairs.
func TestRealEntDB_ConsumeRefreshTokenByHash_TwoReplicas_SingleWinner(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset — skipping real EntDB refresh-token race test")
	}

	// Each replica gets its own SDK client so the redirect-cache and
	// connection state are independent — closer to a real two-process
	// deployment than two repositories sharing one *sdk.DbClient.
	clientA, err := sdk.NewClient(addr)
	require.NoError(t, err)
	clientB, err := sdk.NewClient(addr)
	require.NoError(t, err)
	require.NoError(t, clientA.Connect(context.Background()))
	require.NoError(t, clientB.Connect(context.Background()))
	t.Cleanup(func() { _ = clientA.Close() })
	t.Cleanup(func() { _ = clientB.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := fmt.Sprintf("rt-race-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, clientA, tenantID)

	replicaA := NewRepository(clientA, tenantID)
	replicaB := NewRepository(clientB, tenantID)

	// Seed an unconsumed refresh token through replicaA. The two
	// replicas read the same row by token_hash afterwards.
	userID, err := replicaA.CreateUser(ctx, &service.User{
		Email:     "rt-race@example.com",
		Name:      "RT Race",
		Status:    "active",
		Role:      "member",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	tokenHash := fmt.Sprintf("rt-race-token-%d", time.Now().UnixNano())
	now := time.Now()
	_, err = replicaA.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
		TokenHash:  tokenHash,
		UserID:     userID,
		ExpiresAt:  now.Add(time.Hour).UnixMilli(),
		CreatedAt:  now.UnixMilli(),
		LastUsedAt: now.UnixMilli(),
	})
	require.NoError(t, err)

	// Drive ConsumeRefreshTokenByHash from BOTH replicas in parallel.
	// release is a barrier so both goroutines start the call as close
	// to simultaneously as the goroutine scheduler allows; the
	// server-side CAS precondition does the rest of the work.
	type outcome struct {
		who string
		err error
	}
	results := make(chan outcome, 2)
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	consume := func(label string, repo service.Repository) {
		defer wg.Done()
		<-release
		results <- outcome{
			who: label,
			err: repo.ConsumeRefreshTokenByHash(ctx, tokenHash, time.Now().UnixMilli()),
		}
	}
	go consume("A", replicaA)
	go consume("B", replicaB)
	close(release)
	wg.Wait()
	close(results)

	winners := 0
	losers := 0
	for r := range results {
		switch {
		case r.err == nil:
			winners++
			t.Logf("replica %s: won", r.who)
		case errors.Is(r.err, service.ErrUnauthenticated):
			losers++
			t.Logf("replica %s: lost (ErrUnauthenticated)", r.who)
		default:
			t.Fatalf("replica %s: unexpected error: %v", r.who, r.err)
		}
	}
	require.Equal(t, 1, winners, "exactly one replica must win the consume race")
	require.Equal(t, 1, losers, "the other replica must observe ErrUnauthenticated")

	// Sanity: the row really did transition. Read via the non-winning
	// replica's view so we also confirm cross-replica read-after-write
	// visibility of the consumed state.
	got, err := replicaB.FindRefreshTokenByHashIncludingConsumed(ctx, tokenHash)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotZero(t, got.ConsumedAtMs, "final refresh-token row must have non-zero consumed_at_ms")
}
