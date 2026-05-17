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
//   - the per-tick limit cap (the v1.14.0 OpDeleteWhere honours
//     Postgres DELETE … LIMIT semantics),
//   - the idempotent re-sweep on an already-clean partition.
//
// tenant-shard-db v1.14.0's OpDeleteWhere primitive (#540) does not
// return a deleted-row count, so the assertions infer "rows deleted"
// from the rows that survive each sweep. The boundary and unexpired
// checks are the load-bearing assertions for the strict-< filter and
// the limit cap.
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

		// First sweep with limit=2 should leave one of the three
		// expired rows behind. We can't query the count of expired
		// rows directly (the SDK doesn't expose a COUNT helper), so
		// the assertion is "at least one of prt-exp-0/1/2 still
		// exists" after the limit-2 sweep, AND boundary + unexpired
		// survive.
		require.NoError(t, repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 2))

		stillThere := 0
		for i := 0; i < 3; i++ {
			got, err := repo.FindPasswordResetTokenByHash(ctx, fmt.Sprintf("prt-exp-%d", i))
			require.NoError(t, err)
			if got != nil {
				stillThere++
			}
		}
		require.Equal(t, 1, stillThere, "limit=2 sweep must leave exactly one expired row behind")

		// Second sweep at the same beforeMs cleans up the third.
		require.NoError(t, repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10))
		for i := 0; i < 3; i++ {
			got, err := repo.FindPasswordResetTokenByHash(ctx, fmt.Sprintf("prt-exp-%d", i))
			require.NoError(t, err)
			require.Nil(t, got, "expired row prt-exp-%d should be gone after full sweep", i)
		}

		// Boundary + unexpired rows survive.
		got, err := repo.FindPasswordResetTokenByHash(ctx, "prt-edge")
		require.NoError(t, err)
		require.NotNil(t, got, "row at the boundary (ExpiresAt == beforeMs) was incorrectly deleted")
		got, err = repo.FindPasswordResetTokenByHash(ctx, "prt-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired row was incorrectly deleted")

		// Idempotent re-sweep — boundary + unexpired still survive.
		require.NoError(t, repo.DeleteExpiredPasswordResetTokens(ctx, 2_000, 10))
		got, err = repo.FindPasswordResetTokenByHash(ctx, "prt-edge")
		require.NoError(t, err)
		require.NotNil(t, got)
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

		require.NoError(t, repo.DeleteExpiredWebAuthnChallenges(ctx, 5_000, 10))

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

		require.NoError(t, repo.DeleteExpiredLoginChallenges(ctx, 5_000, 10))

		got, err := repo.GetLoginChallengeByChallengeID(ctx, "lc-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired login challenge was incorrectly deleted")
		for i := 0; i < 2; i++ {
			got, err := repo.GetLoginChallengeByChallengeID(ctx, fmt.Sprintf("lc-exp-%d", i))
			require.NoError(t, err)
			require.Nil(t, got, "expired login challenge %d should be gone", i)
		}
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

		require.NoError(t, repo.DeleteExpiredEmailVerificationTokens(ctx, 5_000, 10))

		got, err := repo.FindEmailVerificationTokenByHash(ctx, "evt-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired email verification token was incorrectly deleted")
		for i := 0; i < 2; i++ {
			got, err := repo.FindEmailVerificationTokenByHash(ctx, fmt.Sprintf("evt-exp-%d", i))
			require.NoError(t, err)
			require.Nil(t, got, "expired evt-exp-%d should be gone", i)
		}
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

		require.NoError(t, repo.DeleteExpiredEmailChangeTokens(ctx, 5_000, 10))

		got, err := repo.FindEmailChangeTokenByHash(ctx, "ect-keep")
		require.NoError(t, err)
		require.NotNil(t, got, "unexpired email change token was incorrectly deleted")
		for i := 0; i < 2; i++ {
			got, err := repo.FindEmailChangeTokenByHash(ctx, fmt.Sprintf("ect-exp-%d", i))
			require.NoError(t, err)
			require.Nil(t, got, "expired ect-exp-%d should be gone", i)
		}
	})

	t.Run("RejectsNonPositiveLimit", func(t *testing.T) {
		err := repo.DeleteExpiredPasswordResetTokens(ctx, 1, 0)
		require.Error(t, err, "limit=0 must error so a buggy caller does not block on an unbounded delete")
		err = repo.DeleteExpiredLoginChallenges(ctx, 1, -5)
		require.Error(t, err)
	})
}
