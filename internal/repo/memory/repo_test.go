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
//
// tenant-shard-db v1.14.0's OpDeleteWhere (#540) does not return a
// deleted-row count, so the Repository contract returns only error
// and the test infers the cap from the count of rows that remain
// after each sweep.
func TestSweepers_RespectLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name      string
		seed      func(repo *memory.Repo, hash string)
		sweep     func(repo *memory.Repo, ctx context.Context, beforeMs int64, limit int) error
		remaining func(repo *memory.Repo) int
	}{
		{
			name: "PasswordResetTokens",
			seed: func(repo *memory.Repo, hash string) {
				_ = repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
					TokenHash: hash, UserID: "u", ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) error {
				return r.DeleteExpiredPasswordResetTokens(c, b, l)
			},
			remaining: func(r *memory.Repo) int { return r.CountPasswordResetTokens() },
		},
		{
			name: "EmailVerificationTokens",
			seed: func(repo *memory.Repo, hash string) {
				_ = repo.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
					TokenHash: hash, UserID: "u", Email: "x@y", ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) error {
				return r.DeleteExpiredEmailVerificationTokens(c, b, l)
			},
			remaining: func(r *memory.Repo) int { return r.CountEmailVerificationTokens() },
		},
		{
			name: "EmailChangeTokens",
			seed: func(repo *memory.Repo, hash string) {
				_ = repo.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
					TokenHash: hash, UserID: "u", OldEmail: "o", NewEmail: "n",
					ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) error {
				return r.DeleteExpiredEmailChangeTokens(c, b, l)
			},
			remaining: func(r *memory.Repo) int { return r.CountEmailChangeTokens() },
		},
		{
			name: "LoginChallenges",
			seed: func(repo *memory.Repo, hash string) {
				_, _ = repo.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
					ChallengeID: hash, UserID: "u", ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) error {
				return r.DeleteExpiredLoginChallenges(c, b, l)
			},
			remaining: func(r *memory.Repo) int { return r.CountLoginChallenges() },
		},
		{
			name: "WebAuthnChallenges",
			seed: func(repo *memory.Repo, hash string) {
				_, _ = repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
					Challenge: hash, ChallengeType: "registration",
					ExpiresAt: 100, CreatedAt: 50,
				})
			},
			sweep: func(r *memory.Repo, c context.Context, b int64, l int) error {
				return r.DeleteExpiredWebAuthnChallenges(c, b, l)
			},
			remaining: func(r *memory.Repo) int { return r.CountPasskeyChallenges() },
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
			if got := tc.remaining(repo); got != 5 {
				t.Fatalf("after seed: remaining = %d, want 5", got)
			}
			if err := tc.sweep(repo, ctx, 200, 2); err != nil {
				t.Fatalf("sweep limit=2: %v", err)
			}
			if got := tc.remaining(repo); got != 3 {
				t.Fatalf("after sweep limit=2: remaining = %d, want 3 (2 deleted)", got)
			}
			if err := tc.sweep(repo, ctx, 200, 10); err != nil {
				t.Fatalf("sweep limit=10: %v", err)
			}
			if got := tc.remaining(repo); got != 0 {
				t.Fatalf("after sweep limit=10: remaining = %d, want 0 (3 deleted)", got)
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

// TestDeleteUser_CascadesEveryUserOwnedType seeds exactly one row of
// every user-owned type the memory driver tracks — including the
// short-lived, hash/id-keyed artifacts (password-reset / email-verify /
// email-change tokens, passkey + login challenges, qr sessions, oauth
// one-time codes) that the conformance suite no longer seeds — then
// calls DeleteUser and asserts each row is gone. This pins the per-map
// delete bodies in Repo.DeleteUser that those ephemeral types exercise.
func TestDeleteUser_CascadesEveryUserOwnedType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.New()

	// The user node itself.
	if _, err := repo.CreateUser(ctx, &service.User{Email: "u@e.com", Status: "active"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := repo.FindUserByEmail(ctx, "u@e.com")
	if err != nil || u == nil {
		t.Fatalf("FindUserByEmail: u=%+v err=%v", u, err)
	}
	userID := u.ID

	// Durable, user_id-indexed types.
	if _, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: userID, TokenHash: "rt"}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if _, err := repo.CreateSession(ctx, &service.SessionRecord{SID: "sid", UserID: userID, CreatedAtMs: 1}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := repo.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{CredentialID: "cid", UserID: userID, PublicKey: "pk"}); err != nil {
		t.Fatalf("CreatePasskeyCredential: %v", err)
	}
	if _, err := repo.CreateTotpCredential(ctx, &service.TotpCredRecord{UserID: userID, SecretEncrypted: "cipher", Verified: true}); err != nil {
		t.Fatalf("CreateTotpCredential: %v", err)
	}
	if _, err := repo.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{UserID: userID, CodeHash: "rch"}); err != nil {
		t.Fatalf("CreateRecoveryCode: %v", err)
	}
	if err := repo.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: userID, Provider: "google", ProviderUserID: "sub-1"}); err != nil {
		t.Fatalf("CreateOAuthIdentity: %v", err)
	}
	if err := repo.CreateIdentityVerification(ctx, &service.IdentityVerificationRecord{VerificationID: "v-1", UserID: userID, Status: service.IDVStatusPending, CreatedAt: 1}); err != nil {
		t.Fatalf("CreateIdentityVerification: %v", err)
	}
	if _, err := repo.AddOrganizationMember(ctx, &service.OrganizationMembership{OrganizationID: "org-1", UserID: userID, Role: "member"}); err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}

	// Ephemeral, hash/id-keyed types the conformance suite no longer
	// seeds — these are the per-map bodies under test here.
	if err := repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{TokenHash: "prt", UserID: userID, ExpiresAt: 100, CreatedAt: 1}); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}
	if err := repo.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{TokenHash: "evt", UserID: userID, Email: "u@e.com", ExpiresAt: 100, CreatedAt: 1}); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	if err := repo.CreateEmailChangeToken(ctx, &service.EmailChangeToken{TokenHash: "ect", UserID: userID, OldEmail: "u@e.com", NewEmail: "n@e.com", ExpiresAt: 100, CreatedAt: 1}); err != nil {
		t.Fatalf("CreateEmailChangeToken: %v", err)
	}
	if _, err := repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{Challenge: "pkc", UserID: userID, ChallengeType: "registration", ExpiresAt: 100, CreatedAt: 1}); err != nil {
		t.Fatalf("CreatePasskeyChallenge: %v", err)
	}
	pkChalID, err := repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{Challenge: "pkc2", UserID: userID, ChallengeType: "authentication", ExpiresAt: 100, CreatedAt: 1})
	if err != nil {
		t.Fatalf("CreatePasskeyChallenge 2: %v", err)
	}
	loginChalID, err := repo.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{ChallengeID: "lc", UserID: userID, ExpiresAt: 100, CreatedAt: 1})
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	if _, err := repo.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{SessionID: "qr", UserID: userID, Status: "approved", ExpiresAt: 100, CreatedAt: 1}); err != nil {
		t.Fatalf("CreateQrLoginSession: %v", err)
	}
	if _, err := repo.CreateOAuthOneTimeCode(ctx, &service.OAuthOneTimeCodeRecord{CodeHash: "otc", UserID: userID, ExpiresAt: 100, CreatedAt: 1}); err != nil {
		t.Fatalf("CreateOAuthOneTimeCode: %v", err)
	}

	// Delete the user and cascade everything it owns.
	if err := repo.DeleteUser(ctx, userID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// User node gone.
	if got, err := repo.GetUser(ctx, userID); err != nil || got != nil {
		t.Fatalf("user must be deleted: got=%+v err=%v", got, err)
	}
	// Durable types gone.
	if got, err := repo.FindRefreshTokenByHash(ctx, "rt"); err != nil || got != nil {
		t.Fatalf("refresh token must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.GetSessionBySid(ctx, "sid"); err != nil || got != nil {
		t.Fatalf("session must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.GetPasskeyCredentialByCredID(ctx, "cid"); err != nil || got != nil {
		t.Fatalf("passkey credential must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.GetTotpCredential(ctx, userID); err != nil || got != nil {
		t.Fatalf("totp credential must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.FindRecoveryCodeByHash(ctx, userID, "rch"); err != nil || got != nil {
		t.Fatalf("recovery code must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.ListOAuthIdentitiesForUser(ctx, userID); err != nil || len(got) != 0 {
		t.Fatalf("oauth identities must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.GetLatestIdentityVerificationForUser(ctx, userID); err != nil || got != nil {
		t.Fatalf("identity verification must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.ListOrganizationsForUser(ctx, userID); err != nil || len(got) != 0 {
		t.Fatalf("org membership must be deleted: got=%+v err=%v", got, err)
	}

	// Ephemeral types gone — the per-map bodies under test.
	if got, err := repo.FindPasswordResetTokenByHash(ctx, "prt"); err != nil || got != nil {
		t.Fatalf("password reset token must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.FindEmailVerificationTokenByHash(ctx, "evt"); err != nil || got != nil {
		t.Fatalf("email verification token must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.FindEmailChangeTokenByHash(ctx, "ect"); err != nil || got != nil {
		t.Fatalf("email change token must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.GetPasskeyChallenge(ctx, pkChalID); err != nil || got != nil {
		t.Fatalf("passkey challenge must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.GetLoginChallengeByChallengeID(ctx, "lc"); err != nil || got != nil {
		t.Fatalf("login challenge must be deleted: got=%+v err=%v", got, err)
	}
	_ = loginChalID
	if got, err := repo.FindQrLoginSession(ctx, "qr"); err != nil || got != nil {
		t.Fatalf("qr login session must be deleted: got=%+v err=%v", got, err)
	}
	if got, err := repo.ConsumeOAuthOneTimeCode(ctx, "otc", 1); !errors.Is(err, service.ErrOAuthCodeInvalid) || got != nil {
		t.Fatalf("oauth one-time code must be deleted: got=%+v err=%v", got, err)
	}
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
