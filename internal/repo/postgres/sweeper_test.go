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

		// tenant-shard-db v1.14.0's OpDeleteWhere (#540) does not return
		// a deleted-row count, so the Repository.DeleteExpired* contract
		// now returns only error. Infer "rows deleted" by counting the
		// rows that survive each sweep with a separate query against the
		// same table.
		count := func(hashPrefix string) int {
			var n int
			require.NoError(t, repo.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM password_reset_tokens WHERE tenant_id=$1 AND token_hash LIKE $2`,
				tenant, hashPrefix+"%",
			).Scan(&n))
			return n
		}

		require.Equal(t, 5, count("prt-exp-"), "seed must produce 5 expired rows")
		require.NoError(t, repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 2))
		require.Equal(t, 3, count("prt-exp-"), "limit=2 must delete exactly 2 expired rows")

		require.NoError(t, repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10))
		require.Equal(t, 0, count("prt-exp-"), "remaining 3 expired rows must be deleted")

		// Final state: only the unexpired row survives.
		got, err := repo.FindPasswordResetTokenByHash(ctx, "prt-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired row was incorrectly deleted")

		// Idempotent re-sweep.
		require.NoError(t, repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10))
	})

	t.Run("RejectsZeroLimit", func(t *testing.T) {
		err := repo.DeleteExpiredPasswordResetTokens(ctx, 1_000, 0)
		require.Error(t, err, "limit=0 must error so a buggy caller does not block on an unbounded delete")
	})

	t.Run("RejectsNegativeLimit", func(t *testing.T) {
		err := repo.DeleteExpiredLoginChallenges(ctx, 1_000, -5)
		require.Error(t, err)
	})
}
