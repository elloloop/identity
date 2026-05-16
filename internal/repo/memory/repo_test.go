package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// TestConformance runs the driver-agnostic conformance suite against
// the in-memory Repository implementation. CI's `Conformance / memory`
// matrix entry invokes this test.
func TestConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, conformance.Driver{
		Name: "memory",
		NewRepo: func(_ *testing.T) service.Repository {
			return memory.New()
		},
	})
}

func TestRefreshTokenDeleteAndCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := memory.New()
	id1, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: "u-1", TokenHash: "hash-1"})
	if err != nil {
		t.Fatalf("CreateRefreshToken 1: %v", err)
	}
	id2, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: "u-1", TokenHash: "hash-2"})
	if err != nil {
		t.Fatalf("CreateRefreshToken 2: %v", err)
	}
	if _, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: "u-2", TokenHash: "hash-3"}); err != nil {
		t.Fatalf("CreateRefreshToken 3: %v", err)
	}

	if got := repo.CountRefreshTokensForUser("u-1"); got != 2 {
		t.Fatalf("count before delete = %d", got)
	}
	if err := repo.DeleteRefreshToken(ctx, id1); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	if got := repo.CountRefreshTokensForUser("u-1"); got != 1 {
		t.Fatalf("count after single delete = %d", got)
	}
	if got, err := repo.FindRefreshTokenByHash(ctx, "hash-2"); err != nil || got == nil || got.NodeID != id2 {
		t.Fatalf("remaining token = %+v err=%v", got, err)
	}
	if err := repo.DeleteRefreshTokensForUser(ctx, "u-1"); err != nil {
		t.Fatalf("DeleteRefreshTokensForUser: %v", err)
	}
	if got := repo.CountRefreshTokensForUser("u-1"); got != 0 {
		t.Fatalf("count after user delete = %d", got)
	}
	if got := repo.CountRefreshTokensForUser("u-2"); got != 1 {
		t.Fatalf("other user count = %d", got)
	}
}

// TestSweepers_RespectLimit asserts that the memory driver's
// DeleteExpired* methods stop after limit rows. The conformance suite
// covers happy-path correctness; this test focuses on the limit cap
// (which is the property a buggy sweep is most likely to break).
func TestSweepers_RespectLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name string
		seed func(repo *memory.Repo, hash string)
		// pass-through sweep call so we can index by name
		sweep func(repo *memory.Repo, ctx context.Context, beforeMs int64, limit int) (int, error)
	}{
		{
			name: "PasswordResetTokens",
			seed: func(repo *memory.Repo, hash string) {
				_ = repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
					TokenHash: hash, UserID: "u", ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) (int, error) {
				return r.DeleteExpiredPasswordResetTokens(c, b, l)
			},
		},
		{
			name: "EmailVerificationTokens",
			seed: func(repo *memory.Repo, hash string) {
				_ = repo.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
					TokenHash: hash, UserID: "u", Email: "x@y", ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) (int, error) {
				return r.DeleteExpiredEmailVerificationTokens(c, b, l)
			},
		},
		{
			name: "EmailChangeTokens",
			seed: func(repo *memory.Repo, hash string) {
				_ = repo.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
					TokenHash: hash, UserID: "u", OldEmail: "o", NewEmail: "n",
					ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) (int, error) {
				return r.DeleteExpiredEmailChangeTokens(c, b, l)
			},
		},
		{
			name: "LoginChallenges",
			seed: func(repo *memory.Repo, hash string) {
				_, _ = repo.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
					ChallengeID: hash, UserID: "u", ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) (int, error) {
				return r.DeleteExpiredLoginChallenges(c, b, l)
			},
		},
		{
			name: "WebAuthnChallenges",
			seed: func(repo *memory.Repo, hash string) {
				_, _ = repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
					Challenge: hash, ChallengeType: "registration",
					ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) (int, error) {
				return r.DeleteExpiredWebAuthnChallenges(c, b, l)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := memory.New()
			// Seed 5 expired rows.
			for i := 0; i < 5; i++ {
				tc.seed(repo, tc.name+"-h-"+itoaSmall(i))
			}
			deleted, err := tc.sweep(repo, ctx, 200, 2)
			if err != nil {
				t.Fatalf("sweep limit=2: %v", err)
			}
			if deleted != 2 {
				t.Fatalf("deleted = %d, want 2 (limit cap)", deleted)
			}
			deleted, err = tc.sweep(repo, ctx, 200, 10)
			if err != nil {
				t.Fatalf("sweep limit=10: %v", err)
			}
			if deleted != 3 {
				t.Fatalf("deleted = %d, want 3 (remaining)", deleted)
			}
		})
	}
}

// itoaSmall converts a small positive int (0..9 is plenty for the
// loop counter that uses it) to a single-digit string.
func itoaSmall(n int) string {
	if n < 0 || n > 9 {
		return "?"
	}
	return string([]byte{byte('0' + n)})
}

func TestTotpDeleteAndDBStubBehavior(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := memory.New()
	id, err := repo.CreateTotpCredential(ctx, &service.TotpCredRecord{UserID: "u-1", SecretEncrypted: "cipher", Verified: true})
	if err != nil {
		t.Fatalf("CreateTotpCredential: %v", err)
	}
	if err := repo.DeleteTotpCredential(ctx, id); err != nil {
		t.Fatalf("DeleteTotpCredential: %v", err)
	}
	got, err := repo.GetTotpCredential(ctx, "u-1")
	if err != nil {
		t.Fatalf("GetTotpCredential: %v", err)
	}
	if got != nil {
		t.Fatalf("deleted credential = %+v", got)
	}

	if _, err := repo.GetNode(ctx, "tenant", "actor", 1, "node"); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("GetNode error = %v", err)
	}
	if _, err := repo.SearchNodes(ctx, "tenant", "actor", 1, "query"); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("SearchNodes error = %v", err)
	}
	result, err := repo.ExecuteAtomic(ctx, "tenant", "actor", nil)
	if err != nil {
		t.Fatalf("ExecuteAtomic: %v", err)
	}
	if result == nil || !result.Success || !result.Applied {
		t.Fatalf("ExecuteAtomic result = %+v", result)
	}
	if edges, err := repo.GetEdgesFrom(ctx, "tenant", "actor", "node", 1); err != nil || edges != nil {
		t.Fatalf("GetEdgesFrom edges=%v err=%v", edges, err)
	}
	if edges, err := repo.GetEdgesTo(ctx, "tenant", "actor", "node", 1); err != nil || edges != nil {
		t.Fatalf("GetEdgesTo edges=%v err=%v", edges, err)
	}
}
