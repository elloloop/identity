package service

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
	"go.uber.org/zap"
)

func TestManagedChildAuthorization_LivePairAndProject(t *testing.T) {
	f := newDirectoryFixture(t)
	repo := f.repos.project(dirTestProjectA)
	auth := newTestAuthService(t, repo)
	auth.defaultRepo = f.repos
	enableAgeGate(t, auth, false)
	svc := NewManagedChildAuthorizationService(f.store, auth)
	key := f.mint(t, dirTestProjectA, CredentialKindManagedChildReader)
	child := seedPerson(repo, "child@example.test")
	child.DateOfBirthMs = dobAgeMs(8)
	guardian := seedPerson(repo, "guardian@example.test")
	guardian.DateOfBirthMs = dobAgeMs(35)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
	if err := repo.UpsertGuardianEdge(ctx, &GuardianEdge{ChildUserID: child.ID, GuardianUserID: guardian.ID}); err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		allowed, err := svc.GetManagedChildAuthorization(ctx, key.RawKey, child.ID, guardian.ID)
		if err != nil || allowed != want {
			t.Fatalf("allowed=%v want=%v err=%v", allowed, want, err)
		}
	}
	check(true)
	siblingKey := f.mint(t, dirTestProjectB, CredentialKindManagedChildReader)
	siblingCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectB})
	if allowed, err := svc.GetManagedChildAuthorization(siblingCtx, siblingKey.RawKey, child.ID, guardian.ID); allowed || err != nil {
		t.Fatalf("cross-project rows leaked: %v %v", allowed, err)
	}
	strictMarket := WithProjectScope(ctx, &ProjectScope{ProjectID: dirTestProjectA, Jurisdictions: ProjectJurisdictionsConfig{Default: "EX", Thresholds: map[string]JurisdictionThresholds{"EX": {ChildMaxAge: 12, AdultAge: 21}}}})
	guardian.DateOfBirthMs = dobAgeMs(19)
	if allowed, err := svc.GetManagedChildAuthorization(strictMarket, key.RawKey, child.ID, guardian.ID); allowed || err != nil {
		t.Fatalf("ignored project adult threshold: %v %v", allowed, err)
	}
	guardian.DateOfBirthMs = dobAgeMs(35)
	repo.getGuardianEdgeErr = ErrServiceUnavailable
	if allowed, err := svc.GetManagedChildAuthorization(ctx, key.RawKey, child.ID, guardian.ID); allowed || !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("edge error: %v %v", allowed, err)
	}
	repo.getGuardianEdgeErr = nil
	repo.getUsersByIDsErr = ErrServiceUnavailable
	if allowed, err := svc.GetManagedChildAuthorization(ctx, key.RawKey, child.ID, guardian.ID); allowed || !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("account read error: %v %v", allowed, err)
	}
	repo.getUsersByIDsErr = nil
	for _, status := range []string{StatusDeactivated, "suspended", StatusPendingDeletion, StatusPendingParentalConsent} {
		child.Status = status
		check(false)
		child.Status = StatusActive
		guardian.Status = status
		check(false)
		guardian.Status = StatusActive
	}
	child.Kind = UserKindAgent
	check(false)
	child.Kind = UserKindPerson
	guardian.Kind = UserKindAgent
	check(false)
	guardian.Kind = UserKindPerson
	child.IsAnonymous = true
	check(false)
	child.IsAnonymous = false
	guardian.MergedIntoUserID = "replacement"
	check(false)
	guardian.MergedIntoUserID = ""
	guardian.DateOfBirthMs = 0
	check(false)
	guardian.DateOfBirthMs = dobAgeMs(8)
	check(false)
	guardian.DateOfBirthMs = dobAgeMs(35)
	child.DateOfBirthMs = dobAgeMs(25)
	check(false)
	child.DateOfBirthMs = dobAgeMs(8)
	child.DateOfBirthMs = 0
	check(false)
	child.DateOfBirthMs = dobAgeMs(8)
	for _, scope := range []*ProjectScope{nil, {}, {ProjectID: dirTestProjectB}} {
		callCtx := context.Background()
		if scope != nil {
			callCtx = WithProjectScope(callCtx, scope)
		}
		allowed, err := svc.GetManagedChildAuthorization(callCtx, key.RawKey, child.ID, guardian.ID)
		if allowed || !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("wrong project authorized: %v %v", allowed, err)
		}
	}
	for _, pair := range [][2]string{{"missing", guardian.ID}, {child.ID, "missing"}, {child.ID, child.ID}} {
		allowed, err := svc.GetManagedChildAuthorization(ctx, key.RawKey, pair[0], pair[1])
		if allowed || err != nil {
			t.Fatalf("invalid pair: %v %v", allowed, err)
		}
	}
	if err := repo.DeleteGuardianEdge(ctx, guardian.ID, child.ID); err != nil {
		t.Fatal(err)
	}
	check(false)
}

func TestManagedChildAuthorization_CredentialFailures(t *testing.T) {
	f := newDirectoryFixture(t)
	auth := newTestAuthService(t, f.repos.project(dirTestProjectA))
	auth.defaultRepo = f.repos
	svc := NewManagedChildAuthorizationService(f.store, auth)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
	valid := f.mint(t, dirTestProjectA, CredentialKindManagedChildReader)
	wrongKind := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader)
	for _, key := range []string{"", "bad", "unknown.secret", valid.PublicID + ".wrong", wrongKind.RawKey} {
		allowed, err := svc.GetManagedChildAuthorization(ctx, key, "child", "guardian")
		if allowed || !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("key accepted: %v %v", allowed, err)
		}
	}
	if err := f.admin.AdminRevokeProjectCredential(ctx, dirTestSecret, dirTestProjectA, valid.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := svc.GetManagedChildAuthorization(ctx, valid.RawKey, "child", "guardian"); allowed || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked: %v %v", allowed, err)
	}
	fresh := f.mint(t, dirTestProjectA, CredentialKindManagedChildReader)
	f.store.suspended[dirTestProjectA] = true
	if allowed, err := svc.GetManagedChildAuthorization(ctx, fresh.RawKey, "child", "guardian"); allowed || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("suspended project: %v %v", allowed, err)
	}
	delete(f.store.suspended, dirTestProjectA)
	f.store.lookupErr = ErrServiceUnavailable
	if allowed, err := svc.GetManagedChildAuthorization(ctx, fresh.RawKey, "child", "guardian"); allowed || !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("credential lookup error: %v %v", allowed, err)
	}
	f.store.lookupErr = nil
	if allowed, err := svc.GetManagedChildAuthorization(ctx, fresh.RawKey, "", "guardian"); allowed || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed: %v %v", allowed, err)
	}
	if NewManagedChildAuthorizationService(nil, auth) != nil {
		t.Fatal("enabled without credential store")
	}
}

func TestManagedChildAuthorization_AuditScopeAndDecision(t *testing.T) {
	for _, scenario := range []string{"allowed", "no_edge", credentialRefusedSecretMismatch, credentialRefusedRevoked, credentialRefusedOtherProject} {
		t.Run(scenario, func(t *testing.T) {
			f := newDirectoryFixture(t)
			repo := f.repos.project(dirTestProjectA)
			writer := newRecordingAuditWriter()
			auth := newTestAuthServiceWithAudit(t, repo, writer)
			auth.defaultRepo = f.repos
			enableAgeGate(t, auth, false)
			auth.audit = audit.NewLogger(writer, "boot-project", zap.NewNop()).WithProjectScoper(func(ctx context.Context) (audit.NodeWriter, string) {
				return writer, ProjectScopeFromContext(ctx).ProjectID
			})
			svc := NewManagedChildAuthorizationService(f.store, auth)
			minted := f.mint(t, dirTestProjectA, CredentialKindManagedChildReader)
			child := seedPerson(repo, "child@example.test")
			child.DateOfBirthMs = dobAgeMs(8)
			parent := seedPerson(repo, "parent@example.test")
			parent.DateOfBirthMs = dobAgeMs(35)
			ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
			key := minted.RawKey
			if scenario != "no_edge" {
				seedGuardianEdge(ctx, t, repo, parent.ID, child.ID)
			}
			switch scenario {
			case credentialRefusedSecretMismatch:
				key = minted.PublicID + ".wrong"
			case credentialRefusedRevoked:
				if err := f.admin.AdminRevokeProjectCredential(ctx, dirTestSecret, dirTestProjectA, minted.ID); err != nil {
					t.Fatal(err)
				}
			case credentialRefusedOtherProject:
				ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: dirTestProjectB})
			}
			allowed, err := svc.GetManagedChildAuthorization(ctx, key, child.ID, parent.ID)
			refusal := scenario != "allowed" && scenario != "no_edge"
			if refusal && !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("refusal: %v", err)
			}
			if !refusal && err != nil {
				t.Fatal(err)
			}
			if len(writer.events) != 1 || writer.events[0] != string(audit.EventManagedChildAuthorization) || writer.projects[0] != dirTestProjectA || writer.actors[0] != "credential:"+minted.ID || writer.successes[0] != (scenario == "allowed") || allowed != (scenario == "allowed") {
				t.Fatal("audit decision, actor, event or project is incorrect")
			}
			if refusal {
				if writer.targets[0] != "credential:"+minted.ID || writer.countByEventTypeAndDetail(string(audit.EventManagedChildAuthorization), "reason", scenario) != 1 {
					t.Fatal("credential refusal audit missing reason or exposes target")
				}
			} else if writer.targets[0] != child.ID {
				t.Fatal("decision audit missing child target")
			}
		})
	}
}
