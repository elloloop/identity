package service

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
)

func TestProjectGuardianPolicy_StrictBeforeChildAndConsentWrites(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "deployment policy", true: "project requires proof"}[strict], func(t *testing.T) {
			f := newManagedChildFixture(t, true)
			f.svc.cfg.GuardianStepUpAllowNoPassword = true
			f.adult.PasswordHash = ""
			ctx := WithProjectScope(context.Background(), &ProjectScope{Guardian: ProjectGuardianConfig{RequireStepUp: strict}})
			req := f.req()
			req.StepUpPassword = ""
			result, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", "")
			if strict {
				if !errors.Is(err, ErrParentalConsentStepUpFailed) {
					t.Fatalf("create: %v", err)
				}
				children, _, listErr := f.svc.ListManagedChildren(ctx, f.adult.ID, 10, "")
				if listErr != nil || len(children) != 0 {
					t.Fatalf("created child before proof: %v %v", children, listErr)
				}
				child, lookupErr := f.repo.FindUserByUsername(ctx, req.Username)
				if lookupErr != nil || child != nil {
					t.Fatalf("child row written: %v %v", child, lookupErr)
				}
			} else if err != nil || result == nil {
				t.Fatalf("unchanged deployment policy: %v", err)
			}
			pending := seedChildPendingConsent(f.repo, "pending@example.com")
			_, err = f.svc.GrantParentalConsent(ctx, f.adult.ID, pending.ID, consentPolicyVersion, "", "", "")
			if strict {
				if !errors.Is(err, ErrParentalConsentStepUpFailed) {
					t.Fatalf("consent: %v", err)
				}
				consent, _ := f.repo.GetActiveParentalConsentForChild(ctx, pending.ID)
				edge, _ := f.repo.GetGuardianEdge(ctx, f.adult.ID, pending.ID)
				if consent != nil || edge != nil || pending.Status != StatusPendingParentalConsent {
					t.Fatal("consent changed before proof")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectGuardianPolicy_PasswordProofAndIsolation(t *testing.T) {
	f := newManagedChildFixture(t, true)
	f.svc.cfg.GuardianStepUpAllowNoPassword = true
	strict := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-strict", Guardian: ProjectGuardianConfig{RequireStepUp: true}})
	for _, password := range []string{"", "wrong", strongPW} {
		admitted, proved := f.svc.stepUp(strict, f.adult, password)
		if admitted != (password == strongPW) || proved != admitted {
			t.Fatalf("proof result %v/%v", admitted, proved)
		}
	}
	f.adult.PasswordHash = ""
	ordinary := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-ordinary"})
	if admitted, _ := f.svc.stepUp(strict, f.adult, ""); admitted {
		t.Fatal("strict project admitted no proof")
	}
	if admitted, proved := f.svc.stepUp(ordinary, f.adult, ""); !admitted || proved {
		t.Fatal("strict policy leaked into another project")
	}
}

func TestProjectGuardianPolicy_KnownAdultBeforeWrites(t *testing.T) {
	for _, age := range []int{0, 8, 35} {
		t.Run(strconv.Itoa(age), func(t *testing.T) {
			f := newManagedChildFixture(t, true)
			if age > 0 {
				f.adult.DateOfBirthMs = dobAgeMs(age)
			}
			ctx := WithProjectScope(context.Background(), &ProjectScope{Guardian: ProjectGuardianConfig{RequireStepUp: true, RequireAdultProfile: true}})
			result, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", "")
			if age != 35 {
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("create accepted unknown/minor: %v", err)
				}
				if age == 0 && f.writer.countByEventTypeAndDetail(string(audit.EventManagedChildAccountCreated), "step", "adult_profile") != 1 {
					t.Fatal("missing adult profile creation refusal audit")
				}
				stored, _ := f.repo.FindUserByUsername(ctx, f.req().Username)
				if stored != nil {
					t.Fatal("created before adult check")
				}
			} else if err != nil || !result.Consent.SteppedUp {
				t.Fatalf("adult with proof: %v", err)
			}
			pending := seedChildPendingConsent(f.repo, "pending@example.test")
			_, err = f.svc.GrantParentalConsent(ctx, f.adult.ID, pending.ID, consentPolicyVersion, strongPW, "", "")
			if age != 35 {
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("consent accepted unknown/minor: %v", err)
				}
				if f.writer.countByEventTypeAndDetail(string(audit.EventParentalConsentGranted), "step", "adult_profile") != 1 {
					t.Fatal("missing adult profile consent refusal audit")
				}
				consent, _ := f.repo.GetActiveParentalConsentForChild(ctx, pending.ID)
				edge, _ := f.repo.GetGuardianEdge(ctx, f.adult.ID, pending.ID)
				if consent != nil || edge != nil || pending.Status != StatusPendingParentalConsent {
					t.Fatal("changed before adult check")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectGuardianPolicy_ManagementUsesBothGuards(t *testing.T) {
	ctx := WithProjectScope(context.Background(), &ProjectScope{Guardian: ProjectGuardianConfig{RequireStepUp: true, RequireAdultProfile: true}})
	f := newGuardianFixture(ctx, t)
	if _, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unknown adult profile: %v", err)
	}
	if f.writer.countByEventTypeAndDetail(string(audit.EventGuardianChildProfileViewed), "step", "adult_profile") != 1 {
		t.Fatal("missing adult profile management refusal audit")
	}
	f.guardian.DateOfBirthMs = dobAgeMs(35)
	f.guardian.PasswordHash = ""
	f.svc.cfg.GuardianStepUpAllowNoPassword = true
	if _, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, "", "", ""); !errors.Is(err, ErrParentalConsentStepUpFailed) {
		t.Fatalf("no fresh proof: %v", err)
	}
	f.guardian.PasswordHash = hashPW(t, strongPW)
	if _, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); err != nil {
		t.Fatal(err)
	}
	f.guardian.Kind = UserKindAgent
	if _, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("agent profile: %v", err)
	}
}

func TestProjectGuardianPolicy_DefaultAndUnscopedAdmission(t *testing.T) {
	for _, scope := range []*ProjectScope{nil, {ProjectID: testConfig().DefaultProjectID}} {
		f := newManagedChildFixture(t, true)
		f.svc.cfg.GuardianStepUpAllowNoPassword = true
		projectID := f.svc.cfg.DefaultProjectID
		projects := &fakeActiveProjects{active: map[string]*AdminProject{projectID: {ID: projectID, Guardian: ProjectGuardianConfig{RequireStepUp: true, RequireAdultProfile: true}}}}
		f.svc.WithActiveProjects(projects)
		ctx := context.Background()
		if scope != nil {
			ctx = WithProjectScope(ctx, scope)
		}
		req := f.req()
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", ""); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("unknown profile through default/native path: %v", err)
		}
		f.adult.DateOfBirthMs = dobAgeMs(35)
		f.adult.PasswordHash = ""
		req.StepUpPassword = ""
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", ""); !errors.Is(err, ErrParentalConsentStepUpFailed) {
			t.Fatalf("passwordless default/native path: %v", err)
		}
		child := seedChildPendingConsent(f.repo, "pending@example.test")
		if _, err := f.svc.GrantParentalConsent(ctx, f.adult.ID, child.ID, consentPolicyVersion, "", "", ""); !errors.Is(err, ErrParentalConsentStepUpFailed) {
			t.Fatalf("consent default/native path: %v", err)
		}
		seedGuardianEdge(ctx, t, f.repo, f.adult.ID, child.ID)
		if _, err := f.svc.GetManagedChildProfile(ctx, f.adult.ID, child.ID, "", "", ""); !errors.Is(err, ErrParentalConsentStepUpFailed) {
			t.Fatalf("management default/native path: %v", err)
		}
		if stored, _ := f.repo.FindUserByUsername(ctx, req.Username); stored != nil {
			t.Fatal("child written without proof")
		}
		if consent, _ := f.repo.GetActiveParentalConsentForChild(ctx, child.ID); consent != nil {
			t.Fatal("consent written without proof")
		}
		projects.err = ErrServiceUnavailable
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", ""); !errors.Is(err, ErrServiceUnavailable) {
			t.Fatalf("policy error failed open: %v", err)
		}
		projects.err = nil
		delete(projects.active, projectID)
		if _, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, req, "", ""); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("missing project failed open: %v", err)
		}
	}
}

func TestProjectGuardianPolicy_DoesNotObstructConsentWithdrawal(t *testing.T) {
	f := newManagedChildFixture(t, true)
	ctx := context.Background()
	created, err := f.svc.CreateManagedChildAccount(ctx, f.adult.ID, f.req(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.adult.PasswordHash = ""
	f.adult.DateOfBirthMs = 0
	ctx = WithProjectScope(ctx, &ProjectScope{Guardian: ProjectGuardianConfig{RequireStepUp: true, RequireAdultProfile: true}})
	_, childStatus, err := f.svc.RevokeParentalConsent(ctx, f.adult.ID, created.Child.ID, "withdrawal")
	if err != nil || childStatus != StatusPendingParentalConsent {
		t.Fatalf("withdrawal blocked: %s %v", childStatus, err)
	}
	edge, err := f.repo.GetGuardianEdge(ctx, f.adult.ID, created.Child.ID)
	if err != nil || edge != nil {
		t.Fatal("withdrawal did not remove guardian access")
	}
}

func TestProjectGuardianPolicy_DefaultJurisdictionsRemainConsistent(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	f.child.DateOfBirthMs = dobAgeMs(19)
	projectID := f.svc.cfg.DefaultProjectID
	policy := ProjectJurisdictionsConfig{Default: "EX", Thresholds: map[string]JurisdictionThresholds{"EX": {ChildMaxAge: 12, AdultAge: 21}}}
	f.svc.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{projectID: {ID: projectID, Jurisdictions: policy}}})
	child, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
	if err != nil || !child.IsMinor {
		t.Fatalf("default route stamped another policy: %v %v", child, err)
	}
	creator := newManagedChildFixture(t, true)
	creator.svc.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{creator.svc.cfg.DefaultProjectID: {ID: creator.svc.cfg.DefaultProjectID, Jurisdictions: policy}}})
	req := creator.req()
	req.Market = "ZZ"
	if _, err := creator.svc.CreateManagedChildAccount(ctx, creator.adult.ID, req, "", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unknown project market accepted: %v", err)
	}
}
