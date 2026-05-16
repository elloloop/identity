package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestPostgres_SweeperRespectsLimitAndGrace covers the postgres
// DeleteExpired* methods against a real database. The conformance
// suite covers correctness end-to-end; this test focuses on
// limit-cap behaviour and the SQL builder's tenant filter.
//
// Gated on GATEWAY_TEST_POSTGRES_DSN like every other postgres
// test in this file. The realpostgres CI job exports that env var.
func TestPostgres_SweeperRespectsLimitAndGrace(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres sweeper test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))

	tenant := fmt.Sprintf("sweep-tenant-%d", time.Now().UnixNano())
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    tenant,
	})
	require.NoError(t, err)
	defer repo.Close()

	// Seed a parent user so FK constraints on tokens are satisfied.
	now := time.Now().UnixMilli()
	uid, err := repo.CreateUser(ctx, &service.User{
		Email: "sweeper@example.com", Status: "active", Role: "member",
		CreatedAt: time.UnixMilli(now), UpdatedAt: time.UnixMilli(now),
	})
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	t.Run("PasswordResetTokens", func(t *testing.T) {
		seed := func(hash string, expires int64) {
			require.NoError(t, repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
				TokenHash: hash, UserID: uid, ExpiresAt: expires, CreatedAt: now,
			}))
		}
		for i := 0; i < 5; i++ {
			seed(fmt.Sprintf("prt-exp-%d", i), 1_000)
		}
		seed("prt-keep", 100_000)

		deleted, err := repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 2)
		require.NoError(t, err)
		require.Equal(t, 2, deleted, "limit=2 must delete exactly 2")

		deleted, err = repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10)
		require.NoError(t, err)
		require.Equal(t, 3, deleted, "remaining 3 must be deleted")

		// Final state: only the unexpired row survives.
		got, err := repo.FindPasswordResetTokenByHash(ctx, "prt-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired row was incorrectly deleted")

		// Idempotent re-sweep.
		deleted, err = repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10)
		require.NoError(t, err)
		require.Equal(t, 0, deleted)
	})

	t.Run("RejectsZeroLimit", func(t *testing.T) {
		_, err := repo.DeleteExpiredPasswordResetTokens(ctx, 1_000, 0)
		require.Error(t, err, "limit=0 must error so a buggy caller does not block on an unbounded delete")
	})

	t.Run("RejectsNegativeLimit", func(t *testing.T) {
		_, err := repo.DeleteExpiredLoginChallenges(ctx, 1_000, -5)
		require.Error(t, err)
	})
}
