package service

import (
	"context"
	"errors"
	"testing"
)

const consentPolicyVersion = "children-privacy-notice-v1"

// adultFactors selects which strong verified factors a seeded consenting adult
// carries.
type adultFactors struct {
	phoneVerified bool
	idvVerified   bool
	passkey       bool
}

// seedConsentingAdult seeds an active adult account with the given password
// hash and strong verified factors.
func seedConsentingAdult(t *testing.T, repo *fakeRepo, email, pwHash string, f adultFactors) *User {
	t.Helper()
	u := seedUser(repo, email, pwHash, StatusActive)
	u.PhoneVerified = f.phoneVerified
	u.IDVVerified = f.idvVerified
	if f.passkey {
		repo.mu.Lock()
		id := nextNodeID()
		repo.passkeyCreds[id] = &PasskeyCredRecord{
			NodeID: id, CredentialID: "cred-" + u.ID, UserID: u.ID, PublicKey: "pk",
		}
		repo.mu.Unlock()
	}
	return u
}

func seedChildPendingConsent(repo *fakeRepo, email string) *User {
	return seedUser(repo, email, "", StatusPendingParentalConsent)
}

// TestGrantParentalConsent_RequiresBothFactors is the core control: consent is
// granted ONLY when the consenting adult BOTH re-authenticates (step-up) AND
// holds a strong verified factor. Each failure mode is isolated so the table
// pins exactly which check rejected.
func TestGrantParentalConsent_RequiresBothFactors(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)

	cases := []struct {
		name         string
		factors      adultFactors
		adultNoPass  bool   // seed the adult with no password hash
		stepUp       string // password presented at consent time
		wantErr      error
		wantFailStep string
	}{
		{
			name:         "no verified factor is rejected even with correct step-up",
			factors:      adultFactors{}, // none
			stepUp:       strongPW,
			wantErr:      ErrParentalConsentFactorMissing,
			wantFailStep: "verified_factor",
		},
		{
			name:         "correct step-up but no factor: verified phone missing etc.",
			factors:      adultFactors{},
			stepUp:       strongPW,
			wantErr:      ErrParentalConsentFactorMissing,
			wantFailStep: "verified_factor",
		},
		{
			name:         "has factor but wrong step-up password is rejected",
			factors:      adultFactors{phoneVerified: true},
			stepUp:       "wrong-password",
			wantErr:      ErrParentalConsentStepUpFailed,
			wantFailStep: "step_up",
		},
		{
			name:         "has factor but empty step-up password is rejected",
			factors:      adultFactors{phoneVerified: true},
			stepUp:       "",
			wantErr:      ErrParentalConsentStepUpFailed,
			wantFailStep: "step_up",
		},
		{
			name:         "adult with no password cannot step up (passkey-only account)",
			factors:      adultFactors{passkey: true},
			adultNoPass:  true,
			stepUp:       strongPW,
			wantErr:      ErrParentalConsentStepUpFailed,
			wantFailStep: "step_up",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			writer := newRecordingAuditWriter()
			svc := newTestAuthServiceWithAudit(t, repo, writer)

			hash := pwHash
			if tc.adultNoPass {
				hash = ""
			}
			adult := seedConsentingAdult(t, repo, "adult@example.com", hash, tc.factors)
			child := seedChildPendingConsent(repo, "child@example.com")

			rec, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, tc.stepUp, "1.2.3.4", "agent/1.0")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if rec != nil {
				t.Fatalf("no record must be returned on rejection, got %#v", rec)
			}

			// The child MUST NOT be activated on a rejected grant.
			got, _ := repo.GetUser(ctx, child.ID)
			if got.Status != StatusPendingParentalConsent {
				t.Fatalf("child status = %q, want %q (must stay gated)", got.Status, StatusPendingParentalConsent)
			}
			// No consent record persisted.
			if active, _ := repo.GetActiveParentalConsentForChild(ctx, child.ID); active != nil {
				t.Fatalf("no consent record must be written on rejection, got %#v", active)
			}
			// The rejected attempt is audit-logged so a spoof attempt is visible.
			if n := writer.countByEventTypeAndDetail("parental_consent_granted", "step", tc.wantFailStep); n != 1 {
				t.Fatalf("expected 1 failed-grant audit event with step=%q, got %d", tc.wantFailStep, n)
			}
		})
	}
}

// TestGrantParentalConsent_SuccessPerFactor proves that ANY single strong
// factor (plus step-up) suffices, and that the exact factor set present is
// snapshotted onto the record.
func TestGrantParentalConsent_SuccessPerFactor(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)

	cases := []struct {
		name        string
		factors     adultFactors
		wantFactors string
	}{
		{"verified phone only", adultFactors{phoneVerified: true}, "verified_phone"},
		{"passkey only", adultFactors{passkey: true}, "passkey"},
		{"identity verification only", adultFactors{idvVerified: true}, "identity_verification"},
		{"all three", adultFactors{phoneVerified: true, idvVerified: true, passkey: true}, "identity_verification,passkey,verified_phone"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			writer := newRecordingAuditWriter()
			svc := newTestAuthServiceWithAudit(t, repo, writer)
			adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, tc.factors)
			child := seedChildPendingConsent(repo, "child@example.com")

			rec, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "1.2.3.4", "agent/1.0")
			if err != nil {
				t.Fatalf("GrantParentalConsent: %v", err)
			}
			if rec.ConsentingUserID != adult.ID || rec.ChildUserID != child.ID {
				t.Fatalf("record parties = (%q,%q), want (%q,%q)", rec.ConsentingUserID, rec.ChildUserID, adult.ID, child.ID)
			}
			if rec.PolicyVersion != consentPolicyVersion {
				t.Fatalf("policy version = %q, want %q", rec.PolicyVersion, consentPolicyVersion)
			}
			if !rec.SteppedUp {
				t.Fatalf("record must mark stepped_up=true")
			}
			if rec.Factors != tc.wantFactors {
				t.Fatalf("factors = %q, want %q", rec.Factors, tc.wantFactors)
			}
			if rec.ConsentIP != "1.2.3.4" || rec.ConsentUserAgent != "agent/1.0" {
				t.Fatalf("consent ip/ua not recorded: %q %q", rec.ConsentIP, rec.ConsentUserAgent)
			}

			// The consent gate is exited: child -> active.
			got, _ := repo.GetUser(ctx, child.ID)
			if got.Status != StatusActive {
				t.Fatalf("child status = %q, want %q", got.Status, StatusActive)
			}
			// The record is persisted and active.
			active, _ := repo.GetActiveParentalConsentForChild(ctx, child.ID)
			if active == nil || active.ConsentID != rec.ConsentID {
				t.Fatalf("active consent record not persisted: %#v", active)
			}
			// A successful grant is audit-logged with the policy version.
			if n := writer.countByEventTypeAndDetail("parental_consent_granted", "policy_version", consentPolicyVersion); n != 1 {
				t.Fatalf("expected 1 successful-grant audit event, got %d", n)
			}
		})
	}
}

func TestGrantParentalConsent_InputAndStateGuards(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)

	t.Run("missing policy version is rejected", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, "  ", strongPW, "", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("cannot consent for own account", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		_, err := svc.GrantParentalConsent(ctx, adult.ID, adult.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("child must exist", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		_, err := svc.GrantParentalConsent(ctx, adult.ID, "no-such-child", consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("child not pending is rejected and prevents a second grant", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")

		// First grant succeeds and activates the child.
		if _, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", ""); err != nil {
			t.Fatalf("first grant: %v", err)
		}
		// A second grant is refused: the child is no longer pending (double-grant guard).
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrParentalConsentNotPending) {
			t.Fatalf("err = %v, want ErrParentalConsentNotPending", err)
		}
	})

	t.Run("consenting adult must be active", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		adult.Status = StatusPendingParentalConsent // a gated child cannot consent for another
		child := seedChildPendingConsent(repo, "child@example.com")
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrAccountNotActive) {
			t.Fatalf("err = %v, want ErrAccountNotActive", err)
		}
	})
}

// TestGrantParentalConsent_ResumesHalfAppliedGrant proves the fail-safe
// ordering is self-healing: if a prior grant recorded consent but the status
// flip did not land, a retry completes the activation idempotently rather than
// getting stuck.
func TestGrantParentalConsent_ResumesHalfAppliedGrant(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
	child := seedChildPendingConsent(repo, "child@example.com")

	// Simulate a half-applied prior grant: record exists, child still gated.
	if err := repo.CreateParentalConsent(ctx, &ParentalConsentRecord{
		ConsentID: "pconsent_pre", ChildUserID: child.ID, ConsentingUserID: adult.ID,
		PolicyVersion: consentPolicyVersion, Factors: "verified_phone", SteppedUp: true, GrantedAt: 1,
	}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}

	rec, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
	if err != nil {
		t.Fatalf("resume grant: %v", err)
	}
	if rec.ConsentID != "pconsent_pre" {
		t.Fatalf("expected the existing record to be returned, got %q", rec.ConsentID)
	}
	got, _ := repo.GetUser(ctx, child.ID)
	if got.Status != StatusActive {
		t.Fatalf("child status = %q, want active (activation completed)", got.Status)
	}
}

func TestRevokeParentalConsent_Lifecycle(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)

	t.Run("consenter revokes: child re-gated, access cut, record revoked", func(t *testing.T) {
		repo := newFakeRepo()
		writer := newRecordingAuditWriter()
		svc := newTestAuthServiceWithAudit(t, repo, writer)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")

		if _, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", ""); err != nil {
			t.Fatalf("grant: %v", err)
		}
		// The now-active child has a live session/token.
		if _, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{TokenHash: "rt-child", UserID: child.ID, ExpiresAt: 9_000_000_000_000}); err != nil {
			t.Fatalf("seed child token: %v", err)
		}

		rec, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "changed my mind")
		if err != nil {
			t.Fatalf("RevokeParentalConsent: %v", err)
		}
		if rec.RevokedAt == 0 || rec.RevokedByUserID != adult.ID {
			t.Fatalf("record not marked revoked: %#v", rec)
		}
		// Child is re-gated.
		got, _ := repo.GetUser(ctx, child.ID)
		if got.Status != StatusPendingParentalConsent {
			t.Fatalf("child status = %q, want %q", got.Status, StatusPendingParentalConsent)
		}
		// Access cut off: refresh token gone.
		if tok, err := repo.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-child"); err != nil || tok != nil {
			t.Fatalf("child refresh token must be revoked: err=%v tok=%#v", err, tok)
		}
		// No active consent remains.
		if active, _ := repo.GetActiveParentalConsentForChild(ctx, child.ID); active != nil {
			t.Fatalf("no active consent must remain, got %#v", active)
		}
		if n := writer.countByEventType("parental_consent_revoked"); n != 1 {
			t.Fatalf("expected 1 revoke audit event, got %d", n)
		}
	})

	t.Run("only the consenting adult may revoke", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		other := seedConsentingAdult(t, repo, "other@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		if _, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", ""); err != nil {
			t.Fatalf("grant: %v", err)
		}

		_, err := svc.RevokeParentalConsent(ctx, other.ID, child.ID, "")
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("err = %v, want ErrPermissionDenied", err)
		}
		// Child stays active; consent stays active.
		got, _ := repo.GetUser(ctx, child.ID)
		if got.Status != StatusActive {
			t.Fatalf("child status = %q, want active (unauthorized revoke must not re-gate)", got.Status)
		}
		if active, _ := repo.GetActiveParentalConsentForChild(ctx, child.ID); active == nil {
			t.Fatalf("consent must remain active after an unauthorized revoke")
		}
	})

	t.Run("revoke with no active consent is not found", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		_, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}
