package service

import (
	"context"
	"errors"
	"strconv"
	"testing"
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
