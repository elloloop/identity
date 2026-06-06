package entdb

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// TestSweepers_DeleteExpiredOnMemoryClient is the in-memory backstop
// for the EntDB sweeper: it runs the DeleteExpired* methods
// against the memoryEntClient fake (which mirrors the real SDK
// scope's deleteExpired behaviour). The conformance suite repeats
// these assertions end-to-end against the real EntDB server when
// GATEWAY_ENTDB_ADDRESS is set (Conformance / entdb in CI).
//
// tenant-shard-db v1.14.0's OpDeleteWhere primitive (#540) does not
// return a deleted-row count, so the assertions probe the rows that
// remain in the in-memory store rather than checking a numeric
// return.
func TestSweepers_DeleteExpiredOnMemoryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name      string
		seed      func(c *memoryEntClient, hash string, expiresAt int64)
		callSweep func(r *entRepository, beforeMs int64, limit int) error
	}{
		{
			name: "WebAuthnChallenges",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.PasskeyChallenge{
					Challenge: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
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
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
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
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
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
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
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
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
				return r.DeleteExpiredLoginChallenges(ctx, beforeMs, limit)
			},
		},
		{
			name: "QrLoginSessions",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.QrLoginSession{
					SessionId: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
				return r.DeleteExpiredQrLoginSessions(ctx, beforeMs, limit)
			},
		},
		{
			// Invitations are the one user-keyed ephemeral the
			// cross-driver conformance suite cannot seed (Repository has
			// no invitation create method), so this in-memory case is the
			// only seeded-then-swept coverage for the invitation sweep.
			name: "Invitations",
			seed: func(c *memoryEntClient, key string, expiresAt int64) {
				c.store[key] = storedNode{msg: &schemapb.UserInvitation{
					TokenHash: key, ExpiresAt: expiresAt,
				}}
			},
			callSweep: func(r *entRepository, beforeMs int64, limit int) error {
				return r.DeleteExpiredInvitations(ctx, beforeMs, limit)
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

			// Sweep below the earliest expired row deletes nothing.
			if err := tt.callSweep(repo, 500, 10); err != nil {
				t.Fatalf("sweep below earliest: %v", err)
			}
			if got := len(c.store); got != 3 {
				t.Fatalf("after below-cutoff sweep: %d rows left, want 3", got)
			}

			// limit=1 caps the batch to a single deletion. Two ticks
			// at limit=1 drain both expired rows.
			if err := tt.callSweep(repo, 10_000, 1); err != nil {
				t.Fatalf("limit=1 sweep: %v", err)
			}
			if got := len(c.store); got != 2 {
				t.Fatalf("after limit=1 sweep: %d rows left, want 2", got)
			}

			if err := tt.callSweep(repo, 10_000, 1); err != nil {
				t.Fatalf("limit=1 second sweep: %v", err)
			}
			if got := len(c.store); got != 1 {
				t.Fatalf("after second limit=1 sweep: %d rows left, want 1", got)
			}
			if _, ok := c.store["keep"]; !ok {
				t.Fatal("unexpired row was deleted by the sweeper")
			}

			// Idempotent re-sweep on a clean backlog.
			if err := tt.callSweep(repo, 10_000, 10); err != nil {
				t.Fatalf("idempotent re-sweep: %v", err)
			}
			if got := len(c.store); got != 1 {
				t.Fatalf("after idempotent re-sweep: %d rows left, want 1", got)
			}
		})
	}
}

// TestSweepers_RejectsNonPositiveLimit guards the same invariant the
// postgres backend enforces: a sweeper batch with no cap could hold a
// transaction open over an unbounded result set, so an accidentally
// non-positive batch size surfaces as an error rather than a silent
// "delete everything." The methods all dispatch through the same
// entClient.deleteExpired path, so one example per call is enough.
func TestSweepers_RejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &entRepository{client: newMemoryEntClient(), tenantID: "t"}

	for _, limit := range []int{0, -1} {
		if err := repo.DeleteExpiredWebAuthnChallenges(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredWebAuthnChallenges limit=%d: want error, got nil", limit)
		}
		if err := repo.DeleteExpiredEmailVerificationTokens(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredEmailVerificationTokens limit=%d: want error, got nil", limit)
		}
		if err := repo.DeleteExpiredPasswordResetTokens(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredPasswordResetTokens limit=%d: want error, got nil", limit)
		}
		if err := repo.DeleteExpiredEmailChangeTokens(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredEmailChangeTokens limit=%d: want error, got nil", limit)
		}
		if err := repo.DeleteExpiredLoginChallenges(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredLoginChallenges limit=%d: want error, got nil", limit)
		}
		if err := repo.DeleteExpiredQrLoginSessions(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredQrLoginSessions limit=%d: want error, got nil", limit)
		}
		if err := repo.DeleteExpiredInvitations(ctx, 1, limit); err == nil {
			t.Fatalf("DeleteExpiredInvitations limit=%d: want error, got nil", limit)
		}
	}
}

// TestExpiresAtSweepSpec pins the (type id, expires_at field id)
// table the sweeper's DeleteWhere Filter depends on. The values must
// match the proto schema (proto/identity/schema/schema.proto):
// drifting the field id silently breaks the sweep against a real
// EntDB while the in-memory tests stay green because the fake uses
// proto reflection instead of the numeric field id. Pin both
// directions (every sweep target maps; non-sweep types return
// ok=false).
func TestExpiresAtSweepSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		witness         proto.Message
		wantType, wantF int
		wantOK          bool
	}{
		{&schemapb.PasskeyChallenge{}, 21, 4, true},
		{&schemapb.PasswordResetToken{}, 19, 3, true},
		{&schemapb.EmailVerificationToken{}, 29, 4, true},
		{&schemapb.EmailChangeToken{}, 30, 5, true},
		{&schemapb.LoginChallenge{}, 25, 3, true},
		{&schemapb.QrLoginSession{}, 22, 8, true},
		{&schemapb.UserInvitation{}, 27, 6, true},
		// A non-sweep type must return ok=false so a new sweeper
		// target can never silently skip — the calling code reports
		// an "unsupported message type" error.
		{&schemapb.User{}, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%T", tc.witness), func(t *testing.T) {
			typeID, fieldID, ok := expiresAtSweepSpec(tc.witness)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if typeID != tc.wantType {
				t.Fatalf("typeID = %d, want %d", typeID, tc.wantType)
			}
			if fieldID != tc.wantF {
				t.Fatalf("fieldID = %d, want %d", fieldID, tc.wantF)
			}
		})
	}
}
