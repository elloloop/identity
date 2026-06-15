//go:build realpostgres

// Real-Postgres test for the Session repository surface added by H2
// (refresh-token revocation, mode=session).
//
// Build tag `realpostgres` gates this off the default unit test job.
// Migration 0008_add_sessions ships in this PR and AutoMigrate is on
// so the test exercises the schema-create path too.

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
)

func TestRealPostgres_Session_CRUDAndRevoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN unset — skipping realpostgres session")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	projectID := "realpg-sess-" + time.Now().Format("150405.000000")
	cfg := postgres.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   projectID,
	}
	repo, err := postgres.New(ctx, cfg)
	require.NoError(t, err)

	// Seed the projects(id) row the project_id FK (migration 0015) needs.
	_, err = postgres.NewProjectStore(repo).EnsureDefaultProject(
		ctx, projectID, "scope-"+projectID, "realpg-sess",
	)
	require.NoError(t, err)

	now := time.Now()
	userID, err := repo.CreateUser(ctx, &service.User{
		Email: "u-" + time.Now().Format("150405.000000") + "@example.com",
		Name:  "User", Role: "member", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	sidA := "sess-a-" + time.Now().Format("150405.000000")
	sidB := "sess-b-" + time.Now().Format("150405.000000")

	_, err = repo.CreateSession(ctx, &service.SessionRecord{
		SID: sidA, UserID: userID, CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	_, err = repo.CreateSession(ctx, &service.SessionRecord{
		SID: sidB, UserID: userID, CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)

	// Duplicate sid → ErrAlreadyExists via wrapPgErr / isUniqueViolation.
	_, err = repo.CreateSession(ctx, &service.SessionRecord{
		SID: sidA, UserID: userID, CreatedAtMs: now.UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

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

	// Unknown sid revoke is a no-op.
	require.NoError(t, repo.RevokeSession(ctx, "no-such-sid", bulkAtMs))
	miss, err := repo.GetSessionBySid(ctx, "no-such-sid")
	require.NoError(t, err)
	require.Nil(t, miss)
}
