package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runIdempotencyConformance asserts that mutations targeting a row that
// does not exist are no-ops, not errors. Deletes are idempotent by
// convention (RevokeSession on an unknown sid is already a no-op in the
// CRUD suite), and an update whose target was concurrently deleted must
// not blow up a caller. A backend that errors here diverges from the
// memory/postgres reference and forces callers into existence-checks.
func runIdempotencyConformance(t *testing.T, driver Driver) {
	t.Helper()

	const missing = "no-such-node-00000000"

	t.Run(driver.Name+"/Idempotency", func(t *testing.T) {
		t.Run("Delete_NonExistent_NoError", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if err := r.DeleteRefreshToken(ctx, missing); err != nil {
				t.Errorf("DeleteRefreshToken(missing): want nil, got %v", err)
			}
			if err := r.DeleteLoginChallenge(ctx, missing); err != nil {
				t.Errorf("DeleteLoginChallenge(missing): want nil, got %v", err)
			}
			if err := r.DeletePasskeyChallenge(ctx, missing); err != nil {
				t.Errorf("DeletePasskeyChallenge(missing): want nil, got %v", err)
			}
			if err := r.DeleteTotpCredential(ctx, missing); err != nil {
				t.Errorf("DeleteTotpCredential(missing): want nil, got %v", err)
			}
		})

		// NOTE: Update of a non-existent row is deliberately NOT asserted.
		// The differential suite found the backends genuinely disagree on
		// this unspecified case — postgres silently no-ops, while memory
		// ("not found") and entdb ("ACCESS_DENIED" / "not found") error —
		// and the service layer never updates a row it didn't just read,
		// so there is no contract to pin. Asserting either behavior would
		// fail a legitimate backend.

		t.Run("DeleteForUser_NoRows_NoError", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "idemp-empty@example.com")
			if err := r.DeleteRefreshTokensForUser(ctx, uid); err != nil {
				t.Errorf("DeleteRefreshTokensForUser(no rows): want nil, got %v", err)
			}
			if err := r.DeleteRecoveryCodesForUser(ctx, uid); err != nil {
				t.Errorf("DeleteRecoveryCodesForUser(no rows): want nil, got %v", err)
			}
			if err := r.DeleteTotpCredentialsForUser(ctx, uid); err != nil {
				t.Errorf("DeleteTotpCredentialsForUser(no rows): want nil, got %v", err)
			}
		})

		// A consumed-then-reconsumed / revoke-on-missing flow must report
		// the domain sentinel, not a transport error.
		t.Run("ConsumeMissing_DomainSentinel", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.ConsumeOAuthOneTimeCode(ctx, "no-such-code", 100); !errors.Is(err, service.ErrOAuthCodeInvalid) {
				t.Errorf("ConsumeOAuthOneTimeCode(missing): want ErrOAuthCodeInvalid, got %v", err)
			}
			if err := r.RevokeSession(ctx, "no-such-sid", 100); err != nil {
				t.Errorf("RevokeSession(missing): want nil no-op, got %v", err)
			}
		})
	})
}
