package entdb

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// TestSweepers_ReturnErrSweepNotImplemented locks in the contract
// the background sweeper goroutine relies on: every DeleteExpired*
// method on the EntDB driver returns service.ErrSweepNotImplemented
// so the sweeper logs once and moves on. When the v1.12 migration
// (issue #82) lands and the methods grow real implementations, this
// test fails — and that failure points at the file that holds the
// real implementation.
func TestSweepers_ReturnErrSweepNotImplemented(t *testing.T) {
	t.Parallel()
	r := &entRepository{tenantID: "t"}
	ctx := context.Background()

	cases := map[string]func() (int, error){
		"WebAuthnChallenges":      func() (int, error) { return r.DeleteExpiredWebAuthnChallenges(ctx, 0, 1) },
		"EmailVerificationTokens": func() (int, error) { return r.DeleteExpiredEmailVerificationTokens(ctx, 0, 1) },
		"PasswordResetTokens":     func() (int, error) { return r.DeleteExpiredPasswordResetTokens(ctx, 0, 1) },
		"EmailChangeTokens":       func() (int, error) { return r.DeleteExpiredEmailChangeTokens(ctx, 0, 1) },
		"LoginChallenges":         func() (int, error) { return r.DeleteExpiredLoginChallenges(ctx, 0, 1) },
	}

	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			n, err := fn()
			if !errors.Is(err, service.ErrSweepNotImplemented) {
				t.Fatalf("err = %v, want service.ErrSweepNotImplemented", err)
			}
			if n != 0 {
				t.Fatalf("deleted = %d, want 0 on a stub", n)
			}
		})
	}
}
