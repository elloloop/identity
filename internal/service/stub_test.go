package service

import (
	"context"
	"errors"
	"testing"
)

// TestStubRepository_ReturnsServiceUnavailable confirms every
// StubRepository / StubDB method returns ErrServiceUnavailable (the
// sentinel the service layer maps to "persistence is the stub" at the
// readiness endpoint). The stub is what wires up when the deployer has
// not configured a real backend; sending real reads/writes against it
// must fail closed, not silently appear to succeed.
//
// Listed exhaustively so a newly-added stub method that forgets the
// sentinel surfaces here rather than as a silent persistence-less
// success in production.
func TestStubRepository_ReturnsServiceUnavailable(t *testing.T) {
	r := StubRepository{}
	ctx := context.Background()

	type unaryCheck struct {
		name string
		call func() error
	}
	checks := []unaryCheck{
		{"UpdateInvitation", func() error { return errOf(r.UpdateInvitation(ctx, "id", nil)) }},
		{"UpdateQrLoginSession", func() error { return r.UpdateQrLoginSession(ctx, "id", nil) }},
		{"ConsumeQrLoginSession", func() error { return r.ConsumeQrLoginSession(ctx, "id", 0) }},
		{"IncrementEmailLoginCodeAttempts", func() error { return r.IncrementEmailLoginCodeAttempts(ctx, "e@x") }},
		{"DeleteTotpCredential", func() error { return r.DeleteTotpCredential(ctx, "uid") }},
		{"SetUserIDVVerified", func() error { return r.SetUserIDVVerified(ctx, "uid", 0) }},
		{"CreateIdentityVerification", func() error { return r.CreateIdentityVerification(ctx, nil) }},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if err := c.call(); !errors.Is(err, ErrServiceUnavailable) {
				t.Errorf("%s: err = %v, want ErrServiceUnavailable", c.name, err)
			}
		})
	}

	type stringErrCheck struct {
		name string
		call func() (string, error)
	}
	stringErrChecks := []stringErrCheck{
		{"CreateOAuthOneTimeCode", func() (string, error) { return r.CreateOAuthOneTimeCode(ctx, nil) }},
		{"UpsertEmailLoginCode", func() (string, error) { return r.UpsertEmailLoginCode(ctx, nil) }},
		{"CreateMagicLinkToken", func() (string, error) { return r.CreateMagicLinkToken(ctx, nil) }},
		{"CreateTotpCredential", func() (string, error) { return r.CreateTotpCredential(ctx, nil) }},
	}
	for _, c := range stringErrChecks {
		t.Run(c.name, func(t *testing.T) {
			id, err := c.call()
			if id != "" {
				t.Errorf("%s: id = %q, want empty", c.name, id)
			}
			if !errors.Is(err, ErrServiceUnavailable) {
				t.Errorf("%s: err = %v, want ErrServiceUnavailable", c.name, err)
			}
		})
	}

	t.Run("ConsumeOAuthOneTimeCode_nil_record", func(t *testing.T) {
		rec, err := r.ConsumeOAuthOneTimeCode(ctx, "h", 0)
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("ConsumeOAuthOneTimeCode: rec=%v err=%v", rec, err)
		}
	})
	t.Run("FindEmailLoginCodeByEmail_nil_record", func(t *testing.T) {
		rec, err := r.FindEmailLoginCodeByEmail(ctx, "e@x")
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("FindEmailLoginCodeByEmail: rec=%v err=%v", rec, err)
		}
	})
	t.Run("ConsumeEmailLoginCode_nil_record", func(t *testing.T) {
		rec, err := r.ConsumeEmailLoginCode(ctx, "e@x", 0)
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("ConsumeEmailLoginCode: rec=%v err=%v", rec, err)
		}
	})
	t.Run("ConsumeMagicLinkToken_nil_record", func(t *testing.T) {
		rec, err := r.ConsumeMagicLinkToken(ctx, "h", 0)
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("ConsumeMagicLinkToken: rec=%v err=%v", rec, err)
		}
	})
	t.Run("GetTotpCredential_nil_record", func(t *testing.T) {
		rec, err := r.GetTotpCredential(ctx, "uid")
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("GetTotpCredential: rec=%v err=%v", rec, err)
		}
	})
	t.Run("UpdateTotpCredential_returns_sentinel", func(t *testing.T) {
		err := r.UpdateTotpCredential(ctx, "id", nil)
		if !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("UpdateTotpCredential: err=%v", err)
		}
	})
	t.Run("GetIdentityVerification_nil_record", func(t *testing.T) {
		rec, err := r.GetIdentityVerification(ctx, "id")
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("GetIdentityVerification: rec=%v err=%v", rec, err)
		}
	})
	t.Run("GetLatestIdentityVerificationForUser_nil_record", func(t *testing.T) {
		rec, err := r.GetLatestIdentityVerificationForUser(ctx, "uid")
		if rec != nil || !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("GetLatestIdentityVerificationForUser: rec=%v err=%v", rec, err)
		}
	})
}

// errOf is a helper so the unaryCheck signature stays uniform even for
// methods that already return error directly.
func errOf(e error) error { return e }
