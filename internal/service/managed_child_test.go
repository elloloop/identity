package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/audit"
)

// managedChildFixture builds an age-gated service with an audit recorder and
// a seeded consent-capable adult (verified phone, password set).
type managedChildFixture struct {
	svc    *AuthService
	repo   *fakeRepo
	writer *recordingAuditWriter
	adult  *User
}

func newManagedChildFixture(t *testing.T, ageGate bool) *managedChildFixture {
	t.Helper()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	if ageGate {
		enableAgeGate(t, svc, false)
	}
	adult := seedConsentingAdult(t, repo, "parent@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
	return &managedChildFixture{svc: svc, repo: repo, writer: writer, adult: adult}
}

// req is a complete, valid create request. It carries NO step-up password:
// the create path asks for none, and ManagedChildAccountRequest has no field
// to put one in.
func (f *managedChildFixture) req() ManagedChildAccountRequest {
	return ManagedChildAccountRequest{
		Username:      "kid.one",
		DisplayName:   "Kid One",
		DateOfBirthMs: dobAgeMs(8),
		Password:      strongPW,
		PolicyVersion: consentPolicyVersion,
	}
}

func TestCreateManagedChildAccount_Password_HappyPath(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := context.Background()

	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "1.2.3.4", "agent/1.0")
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}

	// The child is BORN ACTIVE under guardianship — never pending consent.
	child := res.Child
	if child.Status != StatusActive {
		t.Fatalf("child status = %q, want %q (born active)", child.Status, StatusActive)
	}
	if child.Username != "kid.one" || child.Email != "" {
		t.Fatalf("child identity = username %q email %q", child.Username, child.Email)
	}
	if child.AgeBand != "CHILD" || !child.IsMinor {
		t.Fatalf("child band = %q minor=%v, want CHILD", child.AgeBand, child.IsMinor)
	}
	if res.EnrolmentTicket != "" {
		t.Fatal("password arm must not mint an enrolment ticket")
	}

	// The stored row: active, password credential set, username normalized.
	stored, err := f.repo.GetUser(ctx, child.ID)
	if err != nil || stored == nil {
		t.Fatalf("stored child: %v %#v", err, stored)
	}
	if stored.Status != StatusActive || stored.PasswordHash == "" || stored.Username != "kid.one" {
		t.Fatalf("stored child mismatch: %+v", stored)
	}

	// The guardian edge and the consent record commit with the account.
	edge, err := f.repo.GetGuardianEdge(ctx, f.adult.ID, child.ID)
	if err != nil || edge == nil {
		t.Fatalf("guardian edge missing: %v %#v", err, edge)
	}
	consent, err := f.repo.GetActiveParentalConsentForChild(ctx, child.ID)
	if err != nil || consent == nil {
		t.Fatalf("consent record missing: %v %#v", err, consent)
	}
	if consent.ConsentingUserID != f.adult.ID || consent.PolicyVersion != consentPolicyVersion {
		t.Fatalf("consent record mismatch: %+v", consent)
	}
	if consent.Factors != "verified_phone" {
		t.Fatalf("consent factors = %q, want verified_phone", consent.Factors)
	}
	// The record is honest about which control admitted it: the factor did,
	// not a password re-entry. A create-path record claiming stepped_up=true
	// would be evidence of something that never happened.
	if consent.SteppedUp {
		t.Fatal("create-path consent must record stepped_up=false: no password was proved")
	}

	// Audit: one success event, actor the guardian, target the child.
	if n := f.writer.countByEventTypeActorTarget(string(audit.EventManagedChildAccountCreated), f.adult.ID, child.ID); n != 1 {
		t.Fatalf("success audit events = %d, want 1", n)
	}
	if n := f.writer.countByEventTypeAndDetail(string(audit.EventManagedChildAccountCreated), "credential", "password"); n != 1 {
		t.Fatalf("credential detail = %d, want 1", n)
	}
	// The audit trail records what actually happened, and agrees with the
	// consent record it describes: no password was re-entered.
	if n := f.writer.countByEventTypeAndBoolDetail(
		string(audit.EventManagedChildAccountCreated), "stepped_up", false,
	); n != 1 {
		t.Fatalf("stepped_up=false detail = %d, want 1", n)
	}
	// And no refusal was recorded at all — a success must not also log a
	// failing step.
	if n := f.writer.countByEventTypeAndDetail(
		string(audit.EventManagedChildAccountCreated), "step", "step_up",
	); n != 0 {
		t.Fatalf("step_up refusals = %d, want 0: the create path has no step-up check", n)
	}
}

// TestCreateManagedChildAccount_AsksForNoStepUpPassword is the bug this change
// fixes: a parent whose account HOLDS a password hash was being asked to
// re-type it to add a child. Creating a child now requires only the mandatory
// strong verified factor, so the create succeeds with no password supplied —
// and the config flag that governs the step-up rule is irrelevant to this path
// in either position, which is what proves stepUp is no longer consulted here
// at all rather than merely being satisfied by accident.
func TestCreateManagedChildAccount_AsksForNoStepUpPassword(t *testing.T) {
	ctx := context.Background()

	for _, allowNoPassword := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_no_password=%v", allowNoPassword), func(t *testing.T) {
			t.Run("adult who holds a password", func(t *testing.T) {
				f := newManagedChildFixture(t, true)
				f.svc.cfg.GuardianStepUpAllowNoPassword = allowNoPassword
				// The precondition that used to make this fail: the account
				// really does carry a hash, so the old stepUp("") would have
				// refused it.
				if f.adult.PasswordHash == "" {
					t.Fatal("fixture adult must hold a password hash for this test to mean anything")
				}

				res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "1.2.3.4", "agent/1.0")
				if err != nil {
					t.Fatalf("CreateManagedChildAccount with no step-up password: %v", err)
				}
				if res.Child.Status != StatusActive {
					t.Fatalf("child status = %q, want active", res.Child.Status)
				}
				// The factor is what admitted the call, and the record says so.
				if res.Consent.Factors != "verified_phone" || res.Consent.SteppedUp {
					t.Fatalf("consent = factors %q stepped_up %v, want verified_phone / false",
						res.Consent.Factors, res.Consent.SteppedUp)
				}
			})

			t.Run("federated adult who holds no password", func(t *testing.T) {
				// The GuardianStepUpAllowNoPassword flag exists only because a
				// passwordless parent cannot satisfy step-up at all. With
				// step-up off this path, such a parent creates children with
				// the flag OFF too — the lockout is gone, not merely opt-out.
				f := newManagedChildFixture(t, true)
				f.svc.cfg.GuardianStepUpAllowNoPassword = allowNoPassword
				f.repo.mu.Lock()
				f.adult.PasswordHash = ""
				f.repo.mu.Unlock()

				res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", "")
				if err != nil {
					t.Fatalf("CreateManagedChildAccount (federated parent): %v", err)
				}
				if res.Consent.SteppedUp {
					t.Fatal("consent record must say stepped_up=false: no password was proved")
				}
				active, _ := f.repo.GetActiveParentalConsentForChild(ctx, res.Child.ID)
				if active == nil || active.SteppedUp {
					t.Fatalf("persisted record = %#v, want stepped_up=false", active)
				}
			})
		})
	}
}

// TestCreateManagedChildAccount_StrongFactorStaysMandatory pins the control
// that REMAINS. It is the only identity check on this path now, so a parent
// holding no strong verified factor must still be refused — whatever their
// password situation — and each single factor must be enough on its own.
func TestCreateManagedChildAccount_StrongFactorStaysMandatory(t *testing.T) {
	ctx := context.Background()

	t.Run("no factor is refused", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			hasPassword bool
		}{
			{"adult holds a password", true},
			{"federated adult holds none", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newManagedChildFixture(t, true)
				f.repo.mu.Lock()
				f.adult.PhoneVerified = false // the fixture's only factor
				if !tc.hasPassword {
					f.adult.PasswordHash = ""
				}
				f.repo.mu.Unlock()

				res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "1.2.3.4", "agent/1.0")
				if !errors.Is(err, ErrParentalConsentFactorMissing) {
					t.Fatalf("err = %v, want ErrParentalConsentFactorMissing", err)
				}
				if res != nil {
					t.Fatalf("no result on refusal, got %#v", res)
				}
				// A refusal creates nothing.
				if u, _ := f.repo.FindUserByUsername(ctx, "kid.one"); u != nil {
					t.Fatalf("refusal leaked an account: %#v", u)
				}
				if n := f.writer.countByEventTypeAndDetail(
					string(audit.EventManagedChildAccountCreated), "step", "verified_factor",
				); n != 1 {
					t.Fatalf("verified_factor audit refusals = %d, want 1", n)
				}
			})
		}
	})

	t.Run("each single factor admits", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			factors adultFactors
			want    string
		}{
			{"verified phone only", adultFactors{phoneVerified: true}, "verified_phone"},
			{"passkey only", adultFactors{passkey: true}, "passkey"},
			{"identity verification only", adultFactors{idvVerified: true}, "identity_verification"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newManagedChildFixture(t, true)
				// A second adult carrying exactly the one factor under test,
				// and no password at all — so nothing but the factor can be
				// what admits the call.
				adult := seedConsentingAdult(t, f.repo, "solo@example.com", "", tc.factors)

				res, err := f.svc.CreateManagedChildAccount(ctx, adult.ID, f.req(), "", "")
				if err != nil {
					t.Fatalf("CreateManagedChildAccount: %v", err)
				}
				if res.Consent.Factors != tc.want {
					t.Fatalf("consent factors = %q, want %q", res.Consent.Factors, tc.want)
				}
			})
		}
	})
}

// TestCreateManagedChildAccount_StepUpRemovalIsScopedToCreate is the blast
// radius. The step-up requirement came off ONE path; every other guardian
// surface still demands it, and this fails loudly if a later refactor lets the
// removal leak sideways into the operations that act on an account that
// already exists.
func TestCreateManagedChildAccount_StepUpRemovalIsScopedToCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("create needs none", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		req := ManagedChildAccountRequest{
			Username:      "kid.new",
			DisplayName:   "Kid New",
			DateOfBirthMs: dobAgeMs(8),
			Password:      strongPW,
			PolicyVersion: consentPolicyVersion,
		}
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.guardian.ID, req, "", ""); err != nil {
			t.Fatalf("CreateManagedChildAccount: %v", err)
		}
	})

	t.Run("GrantParentalConsent still demands it", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		pending := seedChildPendingConsent(f.repo, "pending@example.com")

		for _, stepUp := range []string{"", "not-the-password"} {
			_, err := f.svc.GrantParentalConsent(ctx, f.guardian.ID, pending.ID, consentPolicyVersion, stepUp, "", "")
			if !errors.Is(err, ErrParentalConsentStepUpFailed) {
				t.Fatalf("stepUp=%q: err = %v, want ErrParentalConsentStepUpFailed", stepUp, err)
			}
		}
		rec, err := f.svc.GrantParentalConsent(ctx, f.guardian.ID, pending.ID, consentPolicyVersion, strongPW, "", "")
		if err != nil || !rec.SteppedUp {
			t.Fatalf("correct password: err = %v, want nil and stepped_up=true", err)
		}
	})
}

// TestGuardianManagementOps_StillDemandStepUpAfterCreateChange is the other
// half of the blast radius, and the one that would be catastrophic to break
// silently: the step-up came off CreateManagedChildAccount only. Every
// guardian management operation acts on an account that already exists — a
// stolen session clearing one of them takes a child over, locks them out or
// erases them — so each still refuses without the password, and still works
// with it.
func TestGuardianManagementOps_StillDemandStepUpAfterCreateChange(t *testing.T) {
	ctx := context.Background()
	for _, op := range allGuardianOps() {
		t.Run(op.name, func(t *testing.T) {
			for _, stepUp := range []string{"", "not-the-password"} {
				f := newGuardianFixture(ctx, t)
				if err := op.call(f, f.guardian.ID, f.child.ID, stepUp); !errors.Is(err, ErrParentalConsentStepUpFailed) {
					t.Fatalf("stepUp=%q: err = %v, want ErrParentalConsentStepUpFailed", stepUp, err)
				}
			}
			f := newGuardianFixture(ctx, t)
			if err := op.call(f, f.guardian.ID, f.child.ID, strongPW); err != nil {
				t.Fatalf("correct password: err = %v, want nil", err)
			}
		})
	}
}

func TestCreateManagedChildAccount_PasskeyEnrolment_HappyPath(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := context.Background()

	req := f.req()
	req.Password = ""
	req.PasskeyEnrolment = true
	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	if res.EnrolmentTicket == "" {
		t.Fatal("passkey_enrolment arm must mint an enrolment ticket")
	}
	// No password credential on the child.
	stored, _ := f.repo.GetUser(ctx, res.Child.ID)
	if stored.PasswordHash != "" {
		t.Fatal("enrolment-arm child must have no password hash")
	}
	// The ticket verifies and names the child.
	childID, err := f.svc.VerifyPasskeyEnrolmentTicket(ctx, res.EnrolmentTicket)
	if err != nil || childID != res.Child.ID {
		t.Fatalf("VerifyPasskeyEnrolmentTicket = %q, %v; want %q", childID, err, res.Child.ID)
	}
	if n := f.writer.countByEventTypeAndDetail(string(audit.EventManagedChildAccountCreated), "credential", "passkey_enrolment"); n != 1 {
		t.Fatalf("credential detail = %d, want 1", n)
	}
}

func TestCreateManagedChildAccount_Refusals(t *testing.T) {
	cases := []struct {
		name         string
		gate         bool
		mutateAdult  func(u *User)
		callerID     string // overrides the fixture adult when non-empty
		mutateReq    func(r *ManagedChildAccountRequest)
		wantErr      error
		wantFailStep string // "" = refusal is not audit-recorded by design
	}{
		{
			name:      "caller account missing",
			callerID:  "no-such-user",
			mutateReq: func(r *ManagedChildAccountRequest) {},
			wantErr:   ErrNotFound,
		},
		{
			name: "caller deactivated",
			mutateAdult: func(u *User) {
				u.Status = "deactivated"
			},
			mutateReq:    func(r *ManagedChildAccountRequest) {},
			wantErr:      ErrAccountNotActive,
			wantFailStep: "caller_inactive",
		},
		{
			name: "caller is a minor",
			gate: true,
			mutateAdult: func(u *User) {
				u.DateOfBirthMs = dobAgeMs(10)
			},
			mutateReq:    func(r *ManagedChildAccountRequest) {},
			wantErr:      ErrPermissionDenied,
			wantFailStep: "caller_minor",
		},
		{
			name: "no strong verified factor",
			mutateAdult: func(u *User) {
				u.PhoneVerified = false
			},
			mutateReq:    func(r *ManagedChildAccountRequest) {},
			wantErr:      ErrParentalConsentFactorMissing,
			wantFailStep: "verified_factor",
		},
		{
			name: "username too short",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.Username = "ab"
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "username bad characters",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.Username = "kid one!"
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "date of birth missing",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.DateOfBirthMs = 0
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "date of birth in the future",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.DateOfBirthMs = time.Now().AddDate(1, 0, 0).UnixMilli()
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "date of birth implausibly old",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.DateOfBirthMs = time.Now().AddDate(-200, 0, 0).UnixMilli()
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "adult-band date of birth",
			gate: true,
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.DateOfBirthMs = dobAgeMs(30)
			},
			wantErr:      ErrManagedChildNotMinor,
			wantFailStep: "band",
		},
		{
			name: "both credentials set",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.PasskeyEnrolment = true // password already set
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "neither credential set",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.Password = ""
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "policy version missing",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.PolicyVersion = ""
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "weak child password",
			mutateReq: func(r *ManagedChildAccountRequest) {
				r.Password = "weak"
			},
			wantErr: ErrWeakPassword,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedChildFixture(t, tc.gate)
			if tc.mutateAdult != nil {
				tc.mutateAdult(f.adult)
			}
			req := f.req()
			tc.mutateReq(&req)
			callerID := f.adult.ID
			if tc.callerID != "" {
				callerID = tc.callerID
			}

			res, err := f.svc.CreateManagedChildAccount(context.Background(), callerID, req, "1.2.3.4", "agent/1.0")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if res != nil {
				t.Fatalf("no result on refusal, got %#v", res)
			}
			// A refusal must create NOTHING: no account resolves by username,
			// the guardian holds no edge, no consent exists.
			if u, _ := f.repo.FindUserByUsername(context.Background(), normalizeUsername(req.Username)); u != nil {
				t.Fatalf("refusal leaked an account: %#v", u)
			}
			if edges, _ := f.repo.ListChildrenOfGuardian(context.Background(), f.adult.ID, 100, 0); len(edges) != 0 {
				t.Fatalf("refusal leaked guardian edges: %#v", edges)
			}
			if tc.wantFailStep != "" {
				if n := f.writer.countByEventTypeAndDetail(string(audit.EventManagedChildAccountCreated), "step", tc.wantFailStep); n != 1 {
					t.Fatalf("failure audit step %q count = %d, want 1", tc.wantFailStep, n)
				}
			}
			// No refusal on this path can be attributed to a step-up any
			// more — the check is gone, so an audit record naming it would be
			// describing a control that never ran.
			if n := f.writer.countByEventTypeAndDetail(
				string(audit.EventManagedChildAccountCreated), "step", "step_up",
			); n != 0 {
				t.Fatalf("create recorded %d step_up refusals; that check no longer exists here", n)
			}
		})
	}
}

func TestCreateManagedChildAccount_DuplicateUsername_LeavesNothing(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := context.Background()

	if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", ""); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Same username (different case — normalization makes it the same
	// account): refused with AlreadyExists, and the store carries exactly the
	// first child.
	req := f.req()
	req.Username = "Kid.One"
	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
	if res != nil {
		t.Fatalf("no result on duplicate, got %#v", res)
	}
	children, _ := f.repo.ListChildrenOfGuardian(ctx, f.adult.ID, 100, 0)
	if len(children) != 1 {
		t.Fatalf("guardian children = %d, want 1", len(children))
	}
	if n := f.writer.countByEventTypeAndDetail(string(audit.EventManagedChildAccountCreated), "step", "duplicate_username"); n != 1 {
		t.Fatalf("duplicate_username audit count = %d, want 1", n)
	}
}

// TestCreateManagedChildAccount_AccessModes pins that this is NOT self-signup:
// the project access mode never gates the parent-creates-child flow — invite
// and closed projects allow it. The guard is the calling adult's standing.
func TestCreateManagedChildAccount_AccessModes(t *testing.T) {
	for _, mode := range []string{"invite", "closed"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedChildFixture(t, true)
			cfg, err := ParseProjectConfig(`{"access":{"mode":"` + mode + `"}}`)
			if err != nil {
				t.Fatalf("ParseProjectConfig: %v", err)
			}
			ctx := WithProjectScope(context.Background(), &ProjectScope{
				ProjectID: "project-a",
				Access:    cfg.Access,
			})
			res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", "")
			if err != nil {
				t.Fatalf("CreateManagedChildAccount under mode %q: %v", mode, err)
			}
			if res.Child.Status != StatusActive {
				t.Fatalf("child status = %q, want active", res.Child.Status)
			}
		})
	}
}

// TestCreateManagedChildAccount_GateOff pins the gate-off contract: the DOB is
// still required (a managed child account without one is never valid), the
// band fields stay unknown, and the account is still born active.
func TestCreateManagedChildAccount_GateOff(t *testing.T) {
	f := newManagedChildFixture(t, false) // age gate OFF
	ctx := context.Background()

	req := f.req()
	req.DateOfBirthMs = dobAgeMs(8)
	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	if res.Child.Status != StatusActive || res.Child.AgeBand != "" || res.Child.IsMinor {
		t.Fatalf("gate-off child: status=%q band=%q minor=%v", res.Child.Status, res.Child.AgeBand, res.Child.IsMinor)
	}
	if res.Child.DateOfBirthMs != req.DateOfBirthMs {
		t.Fatalf("dob not stored: %d", res.Child.DateOfBirthMs)
	}

	// Even an adult-age DOB is accepted with the gate off (there are no
	// thresholds to classify against); a missing one is still refused.
	req2 := f.req()
	req2.Username = "grown.kid"
	req2.DateOfBirthMs = dobAgeMs(30)
	if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req2, "", ""); err != nil {
		t.Fatalf("gate-off adult-age dob: %v", err)
	}
	req3 := f.req()
	req3.Username = "no.dob"
	req3.DateOfBirthMs = 0
	if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req3, "", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("gate-off missing dob: err = %v, want ErrInvalidArgument", err)
	}
}

// TestCreateManagedChildAccount_MarketValidation runs under a project with
// per-jurisdiction thresholds: the child band derives from the market, an
// unconfigured market is refused, and the consent record snapshots the
// resolved market.
func TestCreateManagedChildAccount_MarketValidation(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := jurisdictionScope(t, jurisdictionsUSDefaultJSON)

	// Age 13: TEEN under US (child_max 12), CHILD under IN (child_max 17).
	req := f.req()
	req.DateOfBirthMs = dobAgeMs(13)
	req.Market = "in" // canonicalized on store
	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	if res.Child.Market != "IN" || res.Child.AgeBand != "CHILD" {
		t.Fatalf("child market=%q band=%q, want IN/CHILD", res.Child.Market, res.Child.AgeBand)
	}
	if res.Consent.Market != "IN" {
		t.Fatalf("consent market snapshot = %q, want IN", res.Consent.Market)
	}

	req2 := f.req()
	req2.Username = "kid.two"
	req2.Market = "BR" // not configured in this project
	if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req2, "", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unconfigured market: err = %v, want ErrInvalidArgument", err)
	}

	// Consent market falls back to the project default when the child carries
	// no market of its own.
	req3 := f.req()
	req3.Username = "kid.three"
	req3.DateOfBirthMs = dobAgeMs(10)
	res3, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req3, "", "")
	if err != nil {
		t.Fatalf("no-market create: %v", err)
	}
	if res3.Consent.Market != "US" {
		t.Fatalf("consent market snapshot = %q, want project default US", res3.Consent.Market)
	}
}

// TestManagedChild_UsernameLogin_EndToEnd: the created child signs in with
// its username (case-insensitively) through PasswordLogin and gets a session;
// a wrong password gets the uniform invalid-credentials refusal.
func TestManagedChild_UsernameLogin_EndToEnd(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := context.Background()
	// The PRODUCTION default (GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL defaults
	// true). A managed child structurally has no address to verify, so a gate
	// that fired on it would make the parent-set password permanently
	// unusable on every stock deployment.
	f.svc.cfg.AuthRequireVerifiedEmail = true

	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	login, err := f.svc.PasswordLogin(ctx, "Kid.One", strongPW, "1.2.3.4", "agent/1.0")
	if err != nil {
		t.Fatalf("PasswordLogin by username: %v", err)
	}
	if login.User.ID != res.Child.ID {
		t.Fatalf("login user = %q, want child %q", login.User.ID, res.Child.ID)
	}
	if login.AccessToken == "" || login.RefreshToken == "" {
		t.Fatal("username login must issue a token pair")
	}

	if _, err := f.svc.PasswordLogin(ctx, "kid.one", "wrong-password", "", ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong password: err = %v, want uniform ErrUnauthenticated", err)
	}
	// An unknown username and a syntactically impossible one get the SAME
	// refusal as the wrong password (uniform invalid-credentials path).
	for _, identifier := range []string{"no.such.kid", "!!"} {
		if _, err := f.svc.PasswordLogin(ctx, identifier, strongPW, "", ""); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("identifier %q: err = %v, want ErrUnauthenticated", identifier, err)
		}
	}
}

// ── Passkey enrolment tickets ───────────────────────────────────────────

func TestPasskeyEnrolmentTicket_RoundTrip(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := context.Background()

	req := f.req()
	req.Password = ""
	req.PasskeyEnrolment = true
	res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	childID, err := f.svc.VerifyPasskeyEnrolmentTicket(ctx, res.EnrolmentTicket)
	if err != nil || childID != res.Child.ID {
		t.Fatalf("verify = %q, %v; want %q", childID, err, res.Child.ID)
	}

	// Wrong purpose: a dob_completion ticket must not enrol a passkey.
	dobTicket, err := f.svc.mintPurposeTicket(ctx, res.Child.ID, tokenPurposeDOBCompletion, dobCompletionTicketTTL)
	if err != nil {
		t.Fatalf("mint dob ticket: %v", err)
	}
	if _, err := f.svc.VerifyPasskeyEnrolmentTicket(ctx, dobTicket); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong-purpose ticket: err = %v, want ErrUnauthenticated", err)
	}

	// Garbage and empty are refused identically.
	for _, bad := range []string{"", "not-a-jwt"} {
		if _, err := f.svc.VerifyPasskeyEnrolmentTicket(ctx, bad); err == nil {
			t.Fatalf("ticket %q must be refused", bad)
		}
	}

	// Project mismatch: a ticket minted under one project never verifies
	// under another.
	otherProjectCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-b"})
	if _, err := f.svc.VerifyPasskeyEnrolmentTicket(otherProjectCtx, res.EnrolmentTicket); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("cross-project ticket: err = %v, want ErrUnauthenticated", err)
	}

	// Expired: a negative TTL mints an already-expired ticket.
	expired, err := f.svc.mintPurposeTicket(ctx, res.Child.ID, tokenPurposePasskeyEnrolment, -time.Minute)
	if err != nil {
		t.Fatalf("mint expired: %v", err)
	}
	if _, err := f.svc.VerifyPasskeyEnrolmentTicket(ctx, expired); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired ticket: err = %v, want ErrUnauthenticated", err)
	}
}

func TestValidateUsernameFormat(t *testing.T) {
	for _, tc := range []struct {
		username string
		wantErr  bool
	}{
		{"kid.one", false},
		{"kid_one-2", false},
		{"abc", false},
		{strings.Repeat("a", 32), false},
		{"ab", true},                    // too short
		{strings.Repeat("a", 33), true}, // too long
		{"", true},
		{"kid one", true},         // space
		{"kid@example.com", true}, // no '@' in usernames
		{"kid€", true},            // non-ascii
	} {
		err := validateUsernameFormat(normalizeUsername(tc.username))
		if (err != nil) != tc.wantErr {
			t.Errorf("username %q: err = %v, wantErr %v", tc.username, err, tc.wantErr)
		}
	}
	// Normalization: uppercase folds to lowercase.
	if got := normalizeUsername("  Kid.One "); got != "kid.one" {
		t.Errorf("normalizeUsername = %q, want kid.one", got)
	}
}

// TestCreateManagedChildAccount_RepoFailuresAndBranches covers the storage
// failures and the two branches the happy-path tests do not reach: the
// racing-unique-index arm, and the data-minimization drop on the create path.
func TestCreateManagedChildAccount_RepoFailuresAndBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("caller lookup fails", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		f.repo.getUserErr = errConsentInjected
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("factor lookup fails", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		f.repo.listPasskeyCredsErr = errConsentInjected
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("username pre-check fails", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		f.repo.findUserByUsernameErr = errConsentInjected
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("transaction fails", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		f.repo.createManagedChildErr = errConsentInjected
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("a racing create loses the unique index", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		// The pre-check passes and the transaction then hits the index — the
		// arm a concurrent create takes. It must answer exactly as the
		// pre-check does, disclosing nothing extra.
		f.repo.createManagedChildErr = fmt.Errorf("unique index: %w", ErrAlreadyExists)
		_, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", "")
		if !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("err = %v, want ErrAlreadyExists", err)
		}
		if n := f.writer.countByEventTypeAndDetail(
			string(audit.EventManagedChildAccountCreated), "step", "duplicate_username",
		); n != 1 {
			t.Fatalf("duplicate_username refusals = %d, want 1", n)
		}
	})

	t.Run("data minimization drops the avatar", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		f.svc.minorData = NewMinorDataMinimizer(true, f.svc.ageGate, f.svc.nowFunc)
		req := f.req()
		req.AvatarURL = "https://example.org/kid.png"

		res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
		if err != nil {
			t.Fatalf("CreateManagedChildAccount: %v", err)
		}
		if res.Child.AvatarURL != "" {
			t.Fatalf("avatar = %q, want it dropped for a minimized child", res.Child.AvatarURL)
		}
		stored, _ := f.repo.GetUser(ctx, res.Child.ID)
		if stored.AvatarURL != "" {
			t.Fatalf("stored avatar = %q, want none persisted", stored.AvatarURL)
		}
	})

	t.Run("a teen keeps their avatar", func(t *testing.T) {
		f := newManagedChildFixture(t, true)
		f.svc.minorData = NewMinorDataMinimizer(true, f.svc.ageGate, f.svc.nowFunc)
		req := f.req()
		req.Username = "kid.teen"
		req.DateOfBirthMs = dobAgeMs(15) // TEEN: minimization covers CHILD only
		req.AvatarURL = "https://example.org/teen.png"

		res, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
		if err != nil {
			t.Fatalf("CreateManagedChildAccount: %v", err)
		}
		if res.Child.AvatarURL != req.AvatarURL {
			t.Fatalf("avatar = %q, want it kept for a teen", res.Child.AvatarURL)
		}
	})
}
