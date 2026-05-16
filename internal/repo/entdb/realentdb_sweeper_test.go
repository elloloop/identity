//go:build realentdb

package entdb

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestRealEntDB_SweeperEndToEnd covers the five DeleteExpired* methods
// against a live tenant-shard-db server. The conformance suite
// (TestConformance in realentdb_conformance_test.go) already exercises
// the happy path generically; this test focuses on:
//
//   - the FilterLt boundary (rows at exactly beforeMs survive — the
//     filter is strict less-than, not less-than-or-equal),
//   - the per-tick limit cap (the issue body specifies "respects the
//     limit strictly"),
//   - the idempotent re-sweep on an already-clean partition.
//
// Gated on GATEWAY_ENTDB_ADDRESS like every other real-EntDB test in
// this package. The Conformance / entdb CI matrix entry exports that
// env var.
func TestRealEntDB_SweeperEndToEnd(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset — skipping real EntDB sweeper test")
	}

	client, err := sdk.NewClient(addr)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, client.Connect(ctx))
	t.Cleanup(func() { _ = client.Close() })

	tenantID := fmt.Sprintf("realentdb-sweep-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, client, tenantID)
	repo := NewRepository(client, tenantID)

	// Seed a parent user — EntDB does not enforce the FK constraint
	// the way Postgres does, but the sweep targets all carry a
	// user_id and the test reads more like the production flow when
	// there's a real user behind the tokens.
	now := time.Now()
	uid, err := repo.CreateUser(ctx, &service.User{
		Email:        "sweeper@example.com",
		Name:         "Sweeper",
		Role:         "member",
		Status:       "active",
		PasswordHash: "hash",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	t.Run("PasswordResetTokens", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			require.NoError(t, repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
				TokenHash: fmt.Sprintf("prt-exp-%d", i),
				UserID:    uid,
				ExpiresAt: 1_000,
				CreatedAt: 500,
			}))
		}
		// Boundary row: ExpiresAt == beforeMs survives (strict <).
		require.NoError(t, repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
			TokenHash: "prt-edge", UserID: uid, ExpiresAt: 2_000, CreatedAt: 500,
		}))
		require.NoError(t, repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
			TokenHash: "prt-keep", UserID: uid, ExpiresAt: 100_000, CreatedAt: 500,
		}))

		// limit=2 deletes exactly 2 of the 3 expired rows.
		n, err := repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 2)
		require.NoError(t, err)
		require.Equal(t, 2, n, "limit=2 must delete exactly 2 rows")

		// Second sweep at the same beforeMs cleans up the third.
		n, err = repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10)
		require.NoError(t, err)
		require.Equal(t, 1, n, "remaining expired row must be deleted")

		// Boundary + unexpired rows survive.
		got, err := repo.FindPasswordResetTokenByHash(ctx, "prt-edge")
		require.NoError(t, err)
		require.NotNil(t, got, "row at the boundary (ExpiresAt == beforeMs) was incorrectly deleted")
		got, err = repo.FindPasswordResetTokenByHash(ctx, "prt-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired row was incorrectly deleted")

		// Idempotent re-sweep.
		n, err = repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10)
		require.NoError(t, err)
		require.Equal(t, 0, n)
	})

	t.Run("PasskeyChallenges", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			_, err := repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
				Challenge:     fmt.Sprintf("pkc-exp-%d", i),
				ChallengeType: "registration",
				ExpiresAt:     1_000,
				CreatedAt:     500,
			})
			require.NoError(t, err)
		}
		keepID, err := repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
			Challenge:     "pkc-keep",
			ChallengeType: "registration",
			ExpiresAt:     100_000,
			CreatedAt:     500,
		})
		require.NoError(t, err)

		n, err := repo.DeleteExpiredWebAuthnChallenges(ctx, 5_000, 10)
		require.NoError(t, err)
		require.Equal(t, 2, n)

		got, err := repo.GetPasskeyChallenge(ctx, keepID)
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired passkey challenge was incorrectly deleted")
	})

	t.Run("LoginChallenges", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			_, err := repo.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: fmt.Sprintf("lc-exp-%d", i),
				UserID:      uid,
				ExpiresAt:   1_000,
				CreatedAt:   500,
			})
			require.NoError(t, err)
		}
		_, err := repo.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
			ChallengeID: "lc-keep",
			UserID:      uid,
			ExpiresAt:   100_000,
			CreatedAt:   500,
		})
		require.NoError(t, err)

		n, err := repo.DeleteExpiredLoginChallenges(ctx, 5_000, 10)
		require.NoError(t, err)
		require.Equal(t, 2, n)

		got, err := repo.GetLoginChallengeByChallengeID(ctx, "lc-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired login challenge was incorrectly deleted")
	})

	t.Run("EmailVerificationTokens", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			require.NoError(t, repo.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
				TokenHash: fmt.Sprintf("evt-exp-%d", i),
				UserID:    uid,
				Email:     "sweeper@example.com",
				ExpiresAt: 1_000,
				CreatedAt: 500,
			}))
		}
		require.NoError(t, repo.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
			TokenHash: "evt-keep", UserID: uid, Email: "sweeper@example.com",
			ExpiresAt: 100_000, CreatedAt: 500,
		}))

		n, err := repo.DeleteExpiredEmailVerificationTokens(ctx, 5_000, 10)
		require.NoError(t, err)
		require.Equal(t, 2, n)

		got, err := repo.FindEmailVerificationTokenByHash(ctx, "evt-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired email verification token was incorrectly deleted")
	})

	t.Run("EmailChangeTokens", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			require.NoError(t, repo.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
				TokenHash: fmt.Sprintf("ect-exp-%d", i), UserID: uid,
				OldEmail: "old@x", NewEmail: "new@x",
				ExpiresAt: 1_000, CreatedAt: 500,
			}))
		}
		require.NoError(t, repo.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
			TokenHash: "ect-keep", UserID: uid,
			OldEmail: "old@x", NewEmail: "new@x",
			ExpiresAt: 100_000, CreatedAt: 500,
		}))

		n, err := repo.DeleteExpiredEmailChangeTokens(ctx, 5_000, 10)
		require.NoError(t, err)
		require.Equal(t, 2, n)

		got, err := repo.FindEmailChangeTokenByHash(ctx, "ect-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired email change token was incorrectly deleted")
	})

	t.Run("RejectsNonPositiveLimit", func(t *testing.T) {
		_, err := repo.DeleteExpiredPasswordResetTokens(ctx, 1, 0)
		require.Error(t, err, "limit=0 must error so a buggy caller does not block on an unbounded delete")
		_, err = repo.DeleteExpiredLoginChallenges(ctx, 1, -5)
		require.Error(t, err)
	})
}
