package service

import (
	"context"
	"errors"
	"testing"
)

const consentPolicyVersion = "children-privacy-notice-v1"

// errConsentInjected is a sentinel injected into the fake repository so a test
// can assert (via errors.Is) that the service propagated a repository failure
// unchanged through its fmt.Errorf("...: %w", err) wrappers.
var errConsentInjected = errors.New("injected consent repo error")

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

		rec, _, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "changed my mind")
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

		_, _, err := svc.RevokeParentalConsent(ctx, other.ID, child.ID, "")
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
		_, _, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

// TestDecodeConsentFactors covers the parser's edge cases directly: an empty
// string decodes to no factors, and empty tokens between commas are dropped
// rather than becoming blank factors.
func TestDecodeConsentFactors(t *testing.T) {
	if got := DecodeConsentFactors(""); got != nil {
		t.Fatalf("DecodeConsentFactors(%q) = %v, want nil", "", got)
	}

	got := DecodeConsentFactors("verified_phone,,passkey")
	want := []ParentalConsentFactor{ParentalConsentFactorVerifiedPhone, ParentalConsentFactorPasskey}
	if len(got) != len(want) {
		t.Fatalf("DecodeConsentFactors dropped-empty-token result = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("factor[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestGrantParentalConsent_ArgumentGuards pins the early argument guards that
// reject before any repository access: a caller with no session, a blank child
// id, and a consenting adult whose account does not exist.
func TestGrantParentalConsent_ArgumentGuards(t *testing.T) {
	ctx := context.Background()

	t.Run("empty consenting user id is unauthenticated", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, err := svc.GrantParentalConsent(ctx, "", "child", consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("blank child user id is invalid", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, err := svc.GrantParentalConsent(ctx, "adult", "   ", consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("consenting user not found", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		child := seedChildPendingConsent(repo, "child@example.com")
		_, err := svc.GrantParentalConsent(ctx, "ghost-adult", child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

// TestGrantParentalConsent_RepoErrorsPropagate proves every repository failure
// on the grant path surfaces to the caller (wrapped, so errors.Is still finds
// the injected sentinel) and never leaves the child activated.
func TestGrantParentalConsent_RepoErrorsPropagate(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)

	t.Run("fetch consenting user fails", func(t *testing.T) {
		repo := newFakeRepo()
		repo.getUserErr = errConsentInjected
		svc := newTestAuthService(t, repo)
		_, err := svc.GrantParentalConsent(ctx, "adult", "child", consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("verified-factor check fails when listing passkeys errors", func(t *testing.T) {
		repo := newFakeRepo()
		repo.listPasskeyCredsErr = errConsentInjected
		svc := newTestAuthService(t, repo)
		// No phone/idv factor, so the check must consult passkeys and fail there.
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{})
		child := seedChildPendingConsent(repo, "child@example.com")
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("fetch child user fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		// Fail only the child fetch so the adult fetch and factor check pass.
		repo.getUserErrByID = map[string]error{child.ID: errConsentInjected}
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("existing-consent lookup fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		repo.getActiveConsentErr = errConsentInjected
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("recording the consent fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		repo.createConsentErr = errConsentInjected
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
		got, _ := repo.GetUser(ctx, child.ID)
		if got.Status != StatusPendingParentalConsent {
			t.Fatalf("child status = %q, want gated (record write failed before the flip)", got.Status)
		}
	})

	t.Run("activating the child fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		repo.updateUserErr = errConsentInjected
		_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})
}

// TestGrantParentalConsent_ResumeActivationError covers the resume path's own
// failure mode: a half-applied prior grant is found, but re-asserting the
// status flip fails.
func TestGrantParentalConsent_ResumeActivationError(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
	child := seedChildPendingConsent(repo, "child@example.com")
	if err := repo.CreateParentalConsent(ctx, &ParentalConsentRecord{
		ConsentID: "pconsent_pre", ChildUserID: child.ID, ConsentingUserID: adult.ID,
		PolicyVersion: consentPolicyVersion, Factors: "verified_phone", SteppedUp: true, GrantedAt: 1,
	}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	repo.updateUserErr = errConsentInjected

	_, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
	if !errors.Is(err, errConsentInjected) {
		t.Fatalf("err = %v, want injected error", err)
	}
}

// TestRevokeParentalConsent_GuardsAndRepoErrors pins the revoke path's argument
// guards and its repository-failure propagation. Each repo error is injected
// after a real grant so the failure lands on exactly the revoke-time call.
func TestRevokeParentalConsent_GuardsAndRepoErrors(t *testing.T) {
	ctx := context.Background()
	pwHash := hashPW(t, strongPW)

	t.Run("empty actor id is unauthenticated", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, _, err := svc.RevokeParentalConsent(ctx, "", "child", "")
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("blank child id is invalid", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, _, err := svc.RevokeParentalConsent(ctx, "actor", "   ", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("fetch active consent fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		repo.getActiveConsentErr = errConsentInjected
		_, _, err := svc.RevokeParentalConsent(ctx, "actor", "child", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	// grantOne seeds a consenting adult + gated child, grants consent, and
	// returns the pair so a revoke-time repo error can be injected afterwards.
	grantOne := func(t *testing.T, repo *fakeRepo, svc *AuthService) (adultID, childID string) {
		t.Helper()
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		if _, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", ""); err != nil {
			t.Fatalf("grant: %v", err)
		}
		return adult.ID, child.ID
	}

	t.Run("fetch child user fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adultID, childID := grantOne(t, repo, svc)
		repo.getUserErr = errConsentInjected
		_, _, err := svc.RevokeParentalConsent(ctx, adultID, childID, "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("re-gating the child fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adultID, childID := grantOne(t, repo, svc)
		repo.updateUserErr = errConsentInjected
		_, _, err := svc.RevokeParentalConsent(ctx, adultID, childID, "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("revoking child sessions fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adultID, childID := grantOne(t, repo, svc)
		repo.deleteRefreshTokensErr = errConsentInjected
		_, _, err := svc.RevokeParentalConsent(ctx, adultID, childID, "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})

	t.Run("marking the record revoked fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adultID, childID := grantOne(t, repo, svc)
		repo.markConsentRevokedErr = errConsentInjected
		_, _, err := svc.RevokeParentalConsent(ctx, adultID, childID, "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want injected error", err)
		}
	})
}
