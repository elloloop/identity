package service

import (
	"context"
	"testing"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/stretchr/testify/require"
)

func TestGetCurrentUser_DerivesAgeFromStoredDOB(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		dob   *int64
		band  string
		minor bool
	}{
		{name: "unknown"},
		{name: "child", dob: new(dobAgeMs(8)), band: "CHILD", minor: true},
		{name: "teen", dob: new(dobAgeMs(16)), band: "TEEN", minor: true},
		{name: "adult", dob: new(dobAgeMs(30)), band: "ADULT"},
		{name: "epoch", dob: new(int64(0)), band: "ADULT"},
		{name: "historical", dob: new(dobAgeMs(100)), band: "ADULT"},
		{name: "future", dob: new(dobAgeMs(-1))},
		{name: "implausible", dob: new(dobAgeMs(agegate.MaxRecordedAgeYears + 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			enableAgeGate(t, svc, false)
			id, err := repo.CreateUser(ctx, &User{Email: "profile@example.test", Kind: UserKindPerson, Status: StatusActive, DateOfBirthMs: tc.dob})
			require.NoError(t, err)
			got, err := svc.GetCurrentUser(ctx, id)
			require.NoError(t, err)
			require.Equal(t, tc.band, got.AgeBand)
			require.Equal(t, tc.minor, got.IsMinor)
			require.Equal(t, tc.dob, got.DateOfBirthMs)
			require.Equal(t, StatusActive, got.Status)
			stored, err := repo.GetUser(ctx, id)
			require.NoError(t, err)
			require.Empty(t, stored.AgeBand)
			require.False(t, stored.IsMinor)
			require.Equal(t, tc.dob, stored.DateOfBirthMs)
		})
	}
}

func TestGetCurrentUser_UsesLiveProjectAgePolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)
	policy, err := ParseProjectConfig(jurisdictionsJSON)
	require.NoError(t, err)
	project := &AdminProject{ID: svc.cfg.DefaultProjectID, Jurisdictions: policy.Jurisdictions}
	svc.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{project.ID: project}})
	id, err := repo.CreateUser(ctx, &User{Email: "profile@example.test", Kind: UserKindPerson, Status: StatusActive, DateOfBirthMs: new(dobAgeMs(16)), Market: "IN"})
	require.NoError(t, err)
	got, err := svc.GetCurrentUser(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "CHILD", got.AgeBand)
	require.True(t, got.IsMinor)
	policy, err = ParseProjectConfig(`{"jurisdictions":{"default":"IN","thresholds":{"IN":{"child_max_age":12,"adult_age":18}}}}`)
	require.NoError(t, err)
	project.Jurisdictions = policy.Jurisdictions
	got, err = svc.GetCurrentUser(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "TEEN", got.AgeBand)
	require.True(t, got.IsMinor)
}

func TestGetCurrentUser_AgeClassificationDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	id, err := repo.CreateUser(ctx, &User{Email: "profile@example.test", DateOfBirthMs: new(dobAgeMs(30)), AgeBand: "ADULT", IsMinor: true})
	require.NoError(t, err)
	got, err := svc.GetCurrentUser(ctx, id)
	require.NoError(t, err)
	require.Empty(t, got.AgeBand)
	require.False(t, got.IsMinor)
}

func TestGetCurrentUser_ProjectPolicyUnavailableFailsClosed(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)
	svc.WithActiveProjects(&fakeActiveProjects{err: ErrServiceUnavailable})
	id, err := repo.CreateUser(context.Background(), &User{Email: "profile@example.test", DateOfBirthMs: new(dobAgeMs(30))})
	require.NoError(t, err)
	_, err = svc.GetCurrentUser(context.Background(), id)
	require.ErrorIs(t, err, ErrUnavailable)
}
