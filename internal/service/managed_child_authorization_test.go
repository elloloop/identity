package service

import (
	"context"
	"errors"
	"testing"
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
