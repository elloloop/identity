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

// TestRealEntDB_ConsumeQrLoginSession_TwoReplicas_SingleWinner is the
// real-server regression test for issue #14 — the QR-login consume
// transition must be atomic across replicas backed by the same EntDB
// tenant.
//
// Two Repository instances are constructed against the same tenant id
// to mimic two identity-server replicas sharing one backend. Both
// race to consume the same approved session via
// ConsumeQrLoginSession. Exactly one repository must win; the other
// must observe ErrQrLoginNotPending — equivalent to "the other replica
// already minted tokens for this session, don't double-mint." The
// final row state must be status="consumed".
//
// Without the SDK's UpdateIf precondition the previous read-then-write
// flow let both replicas observe status="approved", both proceed to
// mint tokens, and both write status="consumed" — a token-issuance
// double-spend.
func TestRealEntDB_ConsumeQrLoginSession_TwoReplicas_SingleWinner(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset — skipping real EntDB QR race test")
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

	tenantID := fmt.Sprintf("qr-race-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, clientA, tenantID)

	replicaA := NewRepository(clientA, tenantID)
	replicaB := NewRepository(clientB, tenantID)

	// Seed an approved session through replicaA. The two replicas read
	// the same row by node id afterwards.
	userID, err := replicaA.CreateUser(ctx, &service.User{
		Email:     "qr-race@example.com",
		Name:      "QR Race",
		Status:    "active",
		Role:      "member",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	sessionID := fmt.Sprintf("qr-race-session-%d", time.Now().UnixNano())
	nodeID, err := replicaA.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
		SessionID:      sessionID,
		Status:         "approved",
		UserID:         userID,
		PollSecretHash: "hash",
		ExpiresAt:      time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt:      time.Now().UnixMilli(),
		UpdatedAt:      time.Now().UnixMilli(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, nodeID)

	// Drive ConsumeQrLoginSession from BOTH replicas in parallel.
	// release is a barrier so both goroutines start the call as close
	// to simultaneously as the goroutine scheduler allows; the
	// server-side precondition does the rest of the work.
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
			err: repo.ConsumeQrLoginSession(ctx, nodeID, time.Now().UnixMilli()),
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
		case errors.Is(r.err, service.ErrQrLoginNotPending):
			losers++
			t.Logf("replica %s: lost (ErrQrLoginNotPending)", r.who)
		default:
			t.Fatalf("replica %s: unexpected error: %v", r.who, r.err)
		}
	}
	require.Equal(t, 1, winners, "exactly one replica must win the consume race")
	require.Equal(t, 1, losers, "the other replica must observe ErrQrLoginNotPending")

	// Sanity: the row really did transition. Read via the non-winning
	// replica so we also confirm cross-replica read-after-write
	// visibility on the consumed state.
	got, err := replicaB.FindQrLoginSession(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "consumed", got.Status, "final session status must be consumed")
}
