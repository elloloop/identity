package service

import (
	"context"
	"testing"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/stretchr/testify/require"
)

func TestProjectDOBPolicy_DefaultExplicitAndIsolation(t *testing.T) {
	for _, mode := range []string{"default", "explicit", "ordinary", "invalid", "unavailable", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			enableAgeGate(t, svc, false)
			projectID := svc.cfg.DefaultProjectID
			projects := &fakeActiveProjects{active: map[string]*AdminProject{
				projectID:  {ID: projectID, AgeGate: ProjectAgeGateConfig{RequireDOB: true}},
				"ordinary": {ID: "ordinary"},
			}}
			svc.WithActiveProjects(projects)
			ctx := context.Background()
			switch mode {
			case "explicit":
				ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: projectID})
			case "ordinary":
				ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: "ordinary"})
			case "invalid":
				ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: "absent"})
			case "unavailable":
				projects.err = ErrServiceUnavailable
			case "disabled":
				svc.ageGate = agegate.NewNoop()
			}
			user := seedUser(repo, "policy@example.com", hashPW(t, strongPW), "active")
			access, refresh, err := svc.issueTokens(ctx, user, "", "")
			switch mode {
			case "ordinary":
				require.NoError(t, err)
				require.NotEmpty(t, access)
				require.NotEmpty(t, refresh)
			case "invalid":
				require.ErrorIs(t, err, ErrPermissionDenied)
			case "unavailable", "disabled":
				require.ErrorIs(t, err, ErrUnavailable)
			default:
				requireDOBRefusal(t, svc, err)
			}
			if mode != "ordinary" {
				require.Empty(t, access)
				require.Empty(t, refresh)
			}
		})
	}
}

func TestProjectDOBPolicy_RefreshAndCompletionRemainScoped(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)
	projectID := svc.cfg.DefaultProjectID
	project := &AdminProject{ID: projectID}
	svc.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{projectID: project, "other": {ID: "other"}}})
	ctx := context.Background()
	seedUser(repo, "refresh-dob@example.com", hashPW(t, strongPW), "active")
	login, err := svc.PasswordLogin(ctx, "refresh-dob@example.com", strongPW, "", "")
	require.NoError(t, err)
	project.AgeGate.RequireDOB = true
	_, access, refresh, err := svc.RefreshToken(ctx, login.RefreshToken, "", "", "")
	requireDOBRefusal(t, svc, err)
	require.Empty(t, access)
	require.Empty(t, refresh)
	ticket := dobTicketFrom(t, err)
	_, err = svc.SubmitDateOfBirth(WithProjectScope(ctx, &ProjectScope{ProjectID: "other"}), ticket, new(int64(0)), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	user, err := repo.FindUserByEmail(ctx, "refresh-dob@example.com")
	require.NoError(t, err)
	require.Nil(t, user.DateOfBirthMs)
	completed, err := svc.SubmitDateOfBirth(ctx, ticket, new(int64(0)), "", "")
	require.NoError(t, err)
	require.NotEmpty(t, completed.AccessToken)
	_, access, _, err = svc.RefreshToken(ctx, login.RefreshToken, "", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, access)
}

func TestProjectDOBPolicy_SignupValidatesBeforeWrites(t *testing.T) {
	for _, dob := range []*int64{nil, new(ageGateNow.AddDate(1, 0, 0).UnixMilli()), new(ageGateNow.AddDate(-200, 0, 0).UnixMilli()), new(int64(0))} {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		enableAgeGate(t, svc, false)
		projectID := svc.cfg.DefaultProjectID
		svc.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{projectID: {ID: projectID, AgeGate: ProjectAgeGateConfig{RequireDOB: true}}}})
		result, err := svc.PasswordSignup(context.Background(), "signup-dob@example.com", strongPW, "", "", dob, "", EmailLinkParams{})
		if dob != nil && *dob == 0 {
			require.NoError(t, err)
			require.NotEmpty(t, result.AccessToken)
			continue
		}
		require.ErrorIs(t, err, ErrInvalidArgument)
		user, lookupErr := repo.FindUserByEmail(context.Background(), "signup-dob@example.com")
		require.NoError(t, lookupErr)
		require.Nil(t, user)
	}
}

func TestProjectDOBPolicy_NativeOAuthCompletion(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	projects := defaultNativeProjects()
	for _, project := range projects.active {
		project.AgeGate.RequireDOB = true
	}
	svc := newNativeTestAuthService(t, repo, signer, projects, nil)
	enableAgeGate(t, svc, false)
	token := signer.googleToken(t, "native-dob", "native-dob@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{Provider: "google", IDToken: token, Product: "acme"})
	requireDOBRefusal(t, svc, err)
	ticket := dobTicketFrom(t, err)
	scope, err := svc.resolveNativeProject(context.Background(), "acme")
	require.NoError(t, err)
	result, err := svc.SubmitDateOfBirth(WithProjectScope(context.Background(), scope), ticket, new(int64(-1000)), "", "")
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)
}

type countedActiveProjects struct {
	ActiveProjectStore
	calls int
}

func (s *countedActiveProjects) ActiveProjectByID(ctx context.Context, id string) (*AdminProject, error) {
	s.calls++
	return s.ActiveProjectStore.ActiveProjectByID(ctx, id)
}

func TestProjectDOBPolicy_OneReadPerCallAndNoCrossProjectReuse(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)
	projectID := svc.cfg.DefaultProjectID
	project := &AdminProject{ID: projectID}
	projects := &countedActiveProjects{ActiveProjectStore: &fakeActiveProjects{active: map[string]*AdminProject{projectID: project, "other": {ID: "other"}}}}
	svc.WithActiveProjects(projects)
	ctx := context.Background()
	signup, err := svc.PasswordSignup(ctx, "count@example.com", strongPW, "", "", nil, "", EmailLinkParams{})
	require.NoError(t, err)
	require.Equal(t, 1, projects.calls)
	_, _, _, err = svc.RefreshToken(ctx, signup.RefreshToken, "", "", "")
	require.NoError(t, err)
	require.Equal(t, 2, projects.calls)
	project.AgeGate.RequireDOB = true
	_, err = svc.PasswordLogin(ctx, "count@example.com", strongPW, "", "")
	requireDOBRefusal(t, svc, err)
	require.Equal(t, 3, projects.calls)
	_, err = svc.SubmitDateOfBirth(ctx, dobTicketFrom(t, err), new(int64(0)), "", "")
	require.NoError(t, err)
	require.Equal(t, 4, projects.calls)
	scoped, err := svc.activeProjectPolicyContext(ctx)
	require.NoError(t, err)
	require.Equal(t, 5, projects.calls)
	_, err = svc.activeProjectPolicyContext(scoped)
	require.NoError(t, err)
	require.Equal(t, 5, projects.calls)
	_, err = svc.activeProjectPolicyContext(WithProjectScope(scoped, &ProjectScope{ProjectID: "other"}))
	require.NoError(t, err)
	require.Equal(t, 6, projects.calls)
	_, err = svc.activeProjectPolicyContext(ctx)
	require.NoError(t, err)
	require.Equal(t, 7, projects.calls)
}

func TestProjectDOBPolicy_ImplausibleStoredDateCannotAdmitAdult(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	for _, dob := range []int64{ageGateNow.AddDate(-200, 0, 0).UnixMilli(), ageGateNow.AddDate(1, 0, 0).UnixMilli()} {
		user := &User{ID: "invalid-age", Status: StatusActive, Kind: UserKindPerson, DateOfBirthMs: new(dob)}
		require.False(t, svc.isKnownAdultPerson(context.Background(), user))
		access, refresh, err := svc.issueTokens(context.Background(), user, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument)
		require.Empty(t, access)
		require.Empty(t, refresh)
	}
}

func TestOptionalDOBSignupRejectsFutureBeforeWrites(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	_, err := svc.PasswordSignup(context.Background(), "future@example.com", strongPW, "", "", new(svc.nowFunc().AddDate(1, 0, 0).UnixMilli()), "", EmailLinkParams{})
	require.ErrorIs(t, err, ErrInvalidArgument)
	user, err := repo.FindUserByEmail(context.Background(), "future@example.com")
	require.NoError(t, err)
	require.Nil(t, user)
}
