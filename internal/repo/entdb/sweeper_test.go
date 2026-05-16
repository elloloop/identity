package entdb

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// TestSweepers_DeleteExpiredOnMemoryClient is the in-memory backstop
// for the EntDB sweeper: it runs the five DeleteExpired* methods
// against the memoryEntClient fake (which mirrors the real SDK
// scope's deleteExpired behaviour). The conformance suite repeats
// these assertions end-to-end against the real EntDB server when
// GATEWAY_ENTDB_ADDRESS is set (Conformance / entdb in CI).
func TestSweepers_DeleteExpiredOnMemoryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name      string
		seed      func(c *memoryEntClient, hash string, expiresAt int64)
		callSweep func(r *entRepository, beforeMs int64, limit int) (int, error)
	}{
		{
			name: "WebAuthnChallenges",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.PasskeyChallenge{
					Challenge: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) (int, error) {
				return r.DeleteExpiredWebAuthnChallenges(ctx, beforeMs, limit)
			},
		},
		{
			name: "EmailVerificationTokens",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.EmailVerificationToken{
					TokenHash: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) (int, error) {
				return r.DeleteExpiredEmailVerificationTokens(ctx, beforeMs, limit)
			},
		},
		{
			name: "PasswordResetTokens",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.PasswordResetToken{
					TokenHash: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) (int, error) {
				return r.DeleteExpiredPasswordResetTokens(ctx, beforeMs, limit)
			},
		},
		{
			name: "EmailChangeTokens",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.EmailChangeToken{
					TokenHash: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) (int, error) {
				return r.DeleteExpiredEmailChangeTokens(ctx, beforeMs, limit)
			},
		},
		{
			name: "LoginChallenges",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.LoginChallenge{
					ChallengeId: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) (int, error) {
				return r.DeleteExpiredLoginChallenges(ctx, beforeMs, limit)
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newMemoryEntClient()
			repo := &entRepository{client: c, tenantID: "t"}

			tt.seed(c, "exp-1", 1_000)
			tt.seed(c, "exp-2", 2_000)
			tt.seed(c, "keep", 100_000)

			// Sweep beforeMs below the earliest expired row deletes
			// nothing.
			n, err := tt.callSweep(repo, 500, 10)
			if err != nil {
				t.Fatalf("sweep below earliest: %v", err)
			}
			if n != 0 {
				t.Fatalf("sweep below earliest deleted %d, want 0", n)
			}

			// limit=1 caps the batch to a single deletion.
			n, err = tt.callSweep(repo, 10_000, 1)
			if err != nil {
				t.Fatalf("limit=1 sweep: %v", err)
			}
			if n != 1 {
				t.Fatalf("limit=1 sweep deleted %d, want 1", n)
			}
			if got := len(c.store); got != 2 {
				t.Fatalf("after limit=1 sweep: %d rows left, want 2", got)
			}

			// Final sweep removes the second expired row; unexpired
			// survives.
			n, err = tt.callSweep(repo, 10_000, 10)
			if err != nil {
				t.Fatalf("final sweep: %v", err)
			}
			if n != 1 {
				t.Fatalf("final sweep deleted %d, want 1", n)
			}
			if _, ok := c.store["keep"]; !ok {
				t.Fatal("unexpired row was deleted by the sweeper")
			}

			// Idempotent re-sweep.
			n, err = tt.callSweep(repo, 10_000, 10)
			if err != nil {
				t.Fatalf("idempotent re-sweep: %v", err)
			}
			if n != 0 {
				t.Fatalf("idempotent re-sweep deleted %d, want 0", n)
			}
		})
	}
}

// TestSweepers_RejectsNonPositiveLimit guards the same invariant the
// postgres backend enforces: a sweeper batch with no cap could hold a
// transaction open over an unbounded result set, so an accidentally
// non-positive batch size surfaces as an error rather than a silent
// "delete everything." The five methods all dispatch through the same
// entClient.deleteExpired path, so one example per call is enough.
func TestSweepers_RejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &entRepository{client: newMemoryEntClient(), tenantID: "t"}

	for _, limit := range []int{0, -1} {
		if _, err := repo.DeleteExpiredWebAuthnChallenges(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredWebAuthnChallenges limit=%d: want error, got nil", limit)
		}
		if _, err := repo.DeleteExpiredEmailVerificationTokens(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredEmailVerificationTokens limit=%d: want error, got nil", limit)
		}
		if _, err := repo.DeleteExpiredPasswordResetTokens(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredPasswordResetTokens limit=%d: want error, got nil", limit)
		}
		if _, err := repo.DeleteExpiredEmailChangeTokens(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredEmailChangeTokens limit=%d: want error, got nil", limit)
		}
		if _, err := repo.DeleteExpiredLoginChallenges(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredLoginChallenges limit=%d: want error, got nil", limit)
		}
	}
}

// TestSweepers_UnsupportedTypeAtDispatch keeps the dispatch table
// honest: every type wired into the five entRepository sweepers must
// also be listed in expiresAtSweepSpec. The check is at the dispatch
// boundary rather than via the entRepository because the type-switch
// failure surfaces as a clear "unsupported message type" rather than
// a SDK-level "unknown field id" error.
func TestSweepers_UnsupportedTypeAtDispatch(t *testing.T) {
	t.Parallel()
	if _, _, ok := expiresAtSweepSpec(&schemapb.User{}); ok {
		t.Fatal("expiresAtSweepSpec accepted *schemapb.User; only the five sweep targets should match")
	}
	for _, w := range []proto.Message{
		&schemapb.PasskeyChallenge{},
		&schemapb.EmailVerificationToken{},
		&schemapb.PasswordResetToken{},
		&schemapb.EmailChangeToken{},
		&schemapb.LoginChallenge{},
	} {
		if _, _, ok := expiresAtSweepSpec(w); !ok {
			t.Fatalf("expiresAtSweepSpec rejected %T; expected ok", w)
		}
	}
}
