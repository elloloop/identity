package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/stretchr/testify/require"
)

func TestAccountClassificationLiveStandingOnly(t *testing.T) {
	f := newDirectoryFixture(t)
	repo := f.repos.project(dirTestProjectA)
	auth := newTestAuthService(t, repo)
	auth.defaultRepo = f.repos
	enableAgeGate(t, auth, false)
	svc := NewAccountClassificationService(f.store, auth)
	key := f.mint(t, dirTestProjectA, CredentialKindAccountClassifier)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
	adult := seedPerson(repo, "adult@example.test")
	adult.DateOfBirthMs = new(dobAgeMs(35))
	child := seedPerson(repo, "minor@example.test")
	child.DateOfBirthMs = new(dobAgeMs(8))
	check := func(id string, want AccountClassification) {
		t.Helper()
		out, err := svc.ClassifyAccounts(ctx, key.RawKey, []string{id})
		require.NoError(t, err)
		require.Equal(t, []ClassifiedAccount{{UserID: id, Classification: want}}, out)
	}
	out, err := svc.ClassifyAccounts(ctx, key.RawKey, []string{child.ID, adult.ID})
	require.NoError(t, err)
	require.Equal(t, []ClassifiedAccount{{UserID: child.ID, Classification: AccountClassificationActiveKnownMinor}, {UserID: adult.ID, Classification: AccountClassificationActiveKnownAdult}}, out)
	// A classification discloses no relationship or consent authority.
	edge, err := repo.GetGuardianEdge(ctx, adult.ID, child.ID)
	require.NoError(t, err)
	require.Nil(t, edge)
	check("missing", AccountClassificationDenied)
	for _, status := range []string{"", "unknown", StatusDeactivated, "suspended", StatusPendingDeletion, StatusPendingParentalConsent, "consent_withdrawn"} {
		child.Status = status
		check(child.ID, AccountClassificationDenied)
	}
	child.Status = StatusActive
	child.IsAnonymous = true
	check(child.ID, AccountClassificationDenied)
	child.IsAnonymous = false
	child.Kind = UserKindAgent
	check(child.ID, AccountClassificationDenied)
	child.Kind = ""
	check(child.ID, AccountClassificationDenied)
	child.Kind = "unknown_kind"
	check(child.ID, AccountClassificationDenied)
	child.Kind = UserKindPerson
	child.MergedIntoUserID = adult.ID
	check(child.ID, AccountClassificationDenied)
	child.MergedIntoUserID = ""
	for _, dob := range []*int64{nil, new(time.Now().AddDate(1, 0, 0).UnixMilli()), new(time.Now().AddDate(-151, 0, 0).UnixMilli())} {
		child.DateOfBirthMs = dob
		check(child.ID, AccountClassificationDenied)
	}
	child.DateOfBirthMs = new(dobAgeMs(16))
	check(child.ID, AccountClassificationActiveKnownMinor)
	child.DateOfBirthMs = new(dobAgeMs(19))
	check(child.ID, AccountClassificationActiveKnownAdult)
	ctx = WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA, Jurisdictions: ProjectJurisdictionsConfig{Default: "EX", Thresholds: map[string]JurisdictionThresholds{"EX": {ChildMaxAge: 12, AdultAge: 21}}}})
	check(child.ID, AccountClassificationActiveKnownMinor)
	auth.ageGate = agegate.NewNoop()
	ctx = WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
	check(adult.ID, AccountClassificationDenied)
}

func TestAccountClassificationCredentialsIsolationAndOutages(t *testing.T) {
	f := newDirectoryFixture(t)
	repo := f.repos.project(dirTestProjectA)
	auth := newTestAuthService(t, repo)
	auth.defaultRepo = f.repos
	enableAgeGate(t, auth, false)
	svc := NewAccountClassificationService(f.store, auth)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
	key := f.mint(t, dirTestProjectA, CredentialKindAccountClassifier)
	adult := seedPerson(repo, "adult@example.test")
	adult.DateOfBirthMs = new(dobAgeMs(35))
	for _, kind := range []string{CredentialKindDirectoryReader, CredentialKindManagedChildReader, CredentialKindSecret, CredentialKindPublishable, CredentialKindTenantOperator, CredentialKindTeammateKeyManager} {
		other := f.mint(t, dirTestProjectA, kind)
		out, err := svc.ClassifyAccounts(ctx, other.RawKey, []string{adult.ID})
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.Nil(t, out)
	}
	for _, raw := range []string{"", "unknown.secret", key.PublicID + ".wrong"} {
		out, err := svc.ClassifyAccounts(ctx, raw, []string{adult.ID})
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.Nil(t, out)
	}
	for _, scope := range []*ProjectScope{nil, {}, {ProjectID: dirTestProjectB}} {
		wrong := context.Background()
		if scope != nil {
			wrong = WithProjectScope(wrong, scope)
		}
		out, err := svc.ClassifyAccounts(wrong, key.RawKey, []string{adult.ID})
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.Nil(t, out)
	}
	sibling := f.mint(t, dirTestProjectB, CredentialKindAccountClassifier)
	siblingCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectB})
	out, err := svc.ClassifyAccounts(siblingCtx, sibling.RawKey, []string{adult.ID})
	require.NoError(t, err)
	require.Equal(t, AccountClassificationDenied, out[0].Classification)
	f.store.suspended[dirTestProjectA] = true
	out, err = svc.ClassifyAccounts(ctx, key.RawKey, []string{adult.ID})
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Nil(t, out)
	delete(f.store.suspended, dirTestProjectA)
	f.store.lookupErr = ErrServiceUnavailable
	out, err = svc.ClassifyAccounts(ctx, key.RawKey, []string{adult.ID})
	require.ErrorIs(t, err, ErrServiceUnavailable)
	require.Nil(t, out)
	f.store.lookupErr = nil
	repo.getUsersByIDsErr = ErrServiceUnavailable
	out, err = svc.ClassifyAccounts(ctx, key.RawKey, []string{adult.ID})
	require.ErrorIs(t, err, ErrServiceUnavailable)
	require.Nil(t, out)
	repo.getUsersByIDsErr = nil
	auth.WithActiveProjects(&fakeActiveProjects{err: ErrServiceUnavailable})
	out, err = svc.ClassifyAccounts(ctx, key.RawKey, []string{adult.ID})
	require.ErrorIs(t, err, ErrUnavailable)
	require.Nil(t, out)
	auth.WithActiveProjects(nil)
	require.NoError(t, f.admin.AdminRevokeProjectCredential(ctx, dirTestSecret, dirTestProjectA, key.ID))
	out, err = svc.ClassifyAccounts(ctx, key.RawKey, []string{adult.ID})
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Nil(t, out)
	require.Nil(t, NewAccountClassificationService(nil, auth))
	require.Nil(t, NewAccountClassificationService(f.store, nil))
}

func TestAccountClassificationExactIDBounds(t *testing.T) {
	for _, ids := range [][]string{nil, {}, {""}, {"a", "b", "c"}, {"a", "a"}, {" person"}, {"person "}, {"a\nb"}, {"a\x00b"}, {"person@example.test"}, {strings.Repeat("x", maxAccountClassificationIDBytes+1)}} {
		require.True(t, errors.Is(validateAccountClassificationIDs(ids), ErrInvalidArgument), "input must be refused")
	}
	require.NoError(t, validateAccountClassificationIDs([]string{"user-1", "user-2"}))
}

type classificationTestDeterminer struct {
	enabled bool
	result  agegate.Decision
}

func (classificationTestDeterminer) Name() string    { return "fixture" }
func (d classificationTestDeterminer) Enabled() bool { return d.enabled }
func (d classificationTestDeterminer) Determine(*int64, time.Time) agegate.Decision {
	return d.result
}

func TestAccountClassificationRequiresEnabledKnownAge(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate agegate.Determiner
	}{
		{name: "absent provider"},
		{name: "disabled provider reports adult", gate: classificationTestDeterminer{result: agegate.Decision{Band: agegate.BandAdult, HasDOB: true}}},
		{name: "adult without known DOB", gate: classificationTestDeterminer{enabled: true, result: agegate.Decision{Band: agegate.BandAdult}}},
		{name: "unknown band", gate: classificationTestDeterminer{enabled: true, result: agegate.Decision{HasDOB: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDirectoryFixture(t)
			repo := f.repos.project(dirTestProjectA)
			auth := newTestAuthService(t, repo)
			auth.defaultRepo = f.repos
			auth.ageGate = tc.gate
			user := seedPerson(repo, "adult@example.test")
			user.DateOfBirthMs = new(dobAgeMs(35))
			key := f.mint(t, dirTestProjectA, CredentialKindAccountClassifier)
			ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
			out, err := NewAccountClassificationService(f.store, auth).ClassifyAccounts(ctx, key.RawKey, []string{user.ID})
			require.NoError(t, err)
			require.Equal(t, []ClassifiedAccount{{UserID: user.ID, Classification: AccountClassificationDenied}}, out)
		})
	}
}

func TestAccountClassificationRefreshesProjectJurisdiction(t *testing.T) {
	f := newDirectoryFixture(t)
	repo := f.repos.project(dirTestProjectA)
	auth := newTestAuthService(t, repo)
	auth.defaultRepo = f.repos
	enableAgeGate(t, auth, false)
	project := &AdminProject{ID: dirTestProjectA, Jurisdictions: ProjectJurisdictionsConfig{
		Default: "EX", Thresholds: map[string]JurisdictionThresholds{"EX": {ChildMaxAge: 12, AdultAge: 21}},
	}}
	auth.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{project.ID: project}})
	user := seedPerson(repo, "profile@example.test")
	user.DateOfBirthMs = new(dobAgeMs(19))
	key := f.mint(t, dirTestProjectA, CredentialKindAccountClassifier)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectA})
	svc := NewAccountClassificationService(f.store, auth)
	out, err := svc.ClassifyAccounts(ctx, key.RawKey, []string{user.ID})
	require.NoError(t, err)
	require.Equal(t, AccountClassificationActiveKnownMinor, out[0].Classification)
	project.Jurisdictions.Thresholds["EX"] = JurisdictionThresholds{ChildMaxAge: 12, AdultAge: 18}
	out, err = svc.ClassifyAccounts(ctx, key.RawKey, []string{user.ID})
	require.NoError(t, err)
	require.Equal(t, AccountClassificationActiveKnownAdult, out[0].Classification)
}
