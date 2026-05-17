//go:build realentdb

// Real-EntDB test for the Session repository surface added by H2
// (refresh-token revocation, mode=session). Drives
// CreateSession / GetSessionBySid / RevokeSession /
// RevokeSessionsForUser against a live EntDB gRPC server.
//
// Build tag `realentdb` gates this off the default unit test job.

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/repo/entdb"
	"github.com/elloloop/identity/internal/service"
)

func TestRealEntDB_Session_CRUDAndRevoke(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset — skipping realentdb session")
	}

	client, err := sdk.NewClient(addr)
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tenantID := fmt.Sprintf("realentdb-sess-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, client, tenantID)
	repo := entdb.NewRepository(client, tenantID)
	now := time.Now()

	userID, err := repo.CreateUser(ctx, &service.User{
		Email: fmt.Sprintf("u-%d@example.com", now.UnixNano()),
		Name:  "User", Role: "member", Status: "active",
		PasswordHash: "h", CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	sidA := fmt.Sprintf("sess-a-%d", now.UnixNano())
	sidB := fmt.Sprintf("sess-b-%d", now.UnixNano())

	_, err = repo.CreateSession(ctx, &service.SessionRecord{
		SID: sidA, UserID: userID, CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	_, err = repo.CreateSession(ctx, &service.SessionRecord{
		SID: sidB, UserID: userID, CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)

	// Duplicate sid → service.ErrAlreadyExists (pre-check in repo.go
	// translates the EntDB unique-key collision into the canonical
	// service-layer sentinel).
	_, err = repo.CreateSession(ctx, &service.SessionRecord{
		SID: sidA, UserID: userID, CreatedAtMs: now.UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	// Round-trip via GetSessionBySid.
	got, err := repo.GetSessionBySid(ctx, sidA)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, userID, got.UserID)
	require.Zero(t, got.RevokedAtMs)

	// RevokeSession marks one session revoked.
	revokeAtMs := time.Now().UnixMilli()
	require.NoError(t, repo.RevokeSession(ctx, sidA, revokeAtMs))
	got, err = repo.GetSessionBySid(ctx, sidA)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, revokeAtMs, got.RevokedAtMs)

	// Idempotent revoke: the original timestamp survives.
	require.NoError(t, repo.RevokeSession(ctx, sidA, revokeAtMs+1000))
	got, err = repo.GetSessionBySid(ctx, sidA)
	require.NoError(t, err)
	require.Equal(t, revokeAtMs, got.RevokedAtMs)

	// RevokeSessionsForUser kills the remaining session(s).
	bulkAtMs := time.Now().UnixMilli()
	require.NoError(t, repo.RevokeSessionsForUser(ctx, userID, bulkAtMs))
	gotB, err := repo.GetSessionBySid(ctx, sidB)
	require.NoError(t, err)
	require.NotNil(t, gotB)
	require.Equal(t, bulkAtMs, gotB.RevokedAtMs)

	// Unknown sid is a successful no-op for revoke.
	require.NoError(t, repo.RevokeSession(ctx, "no-such-sid", bulkAtMs))
	miss, err := repo.GetSessionBySid(ctx, "no-such-sid")
	require.NoError(t, err)
	require.Nil(t, miss)
}
