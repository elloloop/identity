package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/passwords"
)

// managedMembershipsMock is a ManagedMembershipReader that answers what the
// test programs and counts its reads.
type managedMembershipsMock struct {
	get   func(projectID, tenantID, userID string) (*TenantMembership, error)
	reads int
}

func (m *managedMembershipsMock) GetMembership(_ context.Context, projectID, tenantID, userID string) (*TenantMembership, error) {
	m.reads++
	return m.get(projectID, tenantID, userID)
}

func membershipIn(status string) func(string, string, string) (*TenantMembership, error) {
	return func(projectID, tenantID, userID string) (*TenantMembership, error) {
		return &TenantMembership{ProjectID: projectID, TenantID: tenantID, UserID: userID, Status: status}, nil
	}
}

// managedTenantsMock is a ManagedTenantStatusReader that answers what the
// test programs.
type managedTenantsMock struct {
	status func(projectID, tenantID string) (string, error)
}

func (m *managedTenantsMock) GetTenantStatus(_ context.Context, projectID, tenantID string) (string, error) {
	return m.status(projectID, tenantID)
}

func tenantIn(status string) *managedTenantsMock {
	return &managedTenantsMock{status: func(string, string) (string, error) { return status, nil }}
}

func TestRefuseManagedAccount(t *testing.T) {
	readErr := errors.New("db down")
	setUp := time.Now().UnixMilli()
	for name, tc := range map[string]struct {
		user    User
		reader  *managedMembershipsMock
		tenants *managedTenantsMock
		want    error
		reads   int
	}{
		"personal account, never read": {user: User{Status: StatusActive}, reader: &managedMembershipsMock{}, reads: 0},
		"active and set up":            {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, reads: 1},
		"suspended membership":         {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: membershipIn(MembershipStatusSuspended)}, want: ErrAccountNotActive, reads: 1},
		"no membership": {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: func(string, string, string) (*TenantMembership, error) {
			return nil, nil
		}}, want: ErrAccountNotActive, reads: 1},
		"read fails": {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: func(string, string, string) (*TenantMembership, error) {
			return nil, readErr
		}}, want: errManagedStandingUnread, reads: 1},
		"no reader":        {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, want: errManagedStandingUnread},
		"invited":          {user: User{Status: StatusInvited, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{}, want: ErrAccountNotActive},
		"never set up":     {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant}, reader: &managedMembershipsMock{}, want: ErrAccountNotActive},
		"pending deletion": {user: User{Status: StatusPendingDeletion, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{}, want: ErrAccountNotActive},
		"suspended tenant": {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenants: tenantIn(TenantStatusSuspended), want: ErrAccountNotActive, reads: 1},
		"latent tenant":    {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenants: tenantIn(TenantStatusLatent), reads: 1},
		"tenant read fails": {user: User{Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: setUp}, reader: &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenants: &managedTenantsMock{status: func(string, string) (string, error) {
			return "", readErr
		}}, want: errManagedStandingUnread, reads: 1},
	} {
		t.Run(name, func(t *testing.T) {
			svc := newTestAuthService(t, newFakeRepo())
			if tc.reader != nil {
				tenants := tc.tenants
				if tenants == nil {
					tenants = tenantIn(TenantStatusClaimed)
				}
				svc.WithManagedMemberships(tc.reader, tenants)
			}
			err := svc.refuseManagedAccount(managedScope(admitted()), &tc.user)
			if tc.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.want)
			}
			if tc.reader != nil {
				require.Equal(t, tc.reads, tc.reader.reads)
			}
		})
	}
}

// managedSignedIn is an AuthService with a set-up managed account of
// mTestTenant that has signed in, and the reader its sessions are judged by.
func managedSignedIn(t *testing.T) (*AuthService, *managedMembershipsMock, *LoginResult) {
	t.Helper()
	repo := newFakeRepo()
	reader := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	svc := newTestAuthService(t, repo).WithManagedMemberships(reader, tenantIn(TenantStatusClaimed))
	hash, err := passwords.Hash(signupPassword)
	require.NoError(t, err)
	now := time.Now()
	id, err := repo.CreateUser(context.Background(), &User{
		Email: maAddress, Name: "Ann Lee", Status: StatusActive, EmailVerified: true, PasswordHash: hash,
		ManagedByTenantID: mTestTenant, SetUpAtMs: now.UnixMilli(), SetupEpoch: 1, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	res, err := svc.PasswordLogin(managedScope(admitted()), maAddress, signupPassword, "203.0.113.9", "ua")
	require.NoError(t, err)
	require.Equal(t, id, res.User.ID)
	require.NotEmpty(t, res.RefreshToken)
	return svc, reader, res
}

func TestPasswordLogin_ManagedAccountNeedsAnActiveMembership(t *testing.T) {
	svc, reader, _ := managedSignedIn(t)
	reader.get = membershipIn(MembershipStatusSuspended)
	_, err := svc.PasswordLogin(managedScope(admitted()), maAddress, signupPassword, "203.0.113.9", "ua")
	require.ErrorIs(t, err, ErrAccountNotActive)
}

func TestRefreshToken_ManagedAccountOutOfStandingSpendsTheToken(t *testing.T) {
	svc, reader, res := managedSignedIn(t)
	reader.get = membershipIn(MembershipStatusSuspended)
	_, _, _, err := svc.RefreshToken(managedScope(admitted()), res.RefreshToken, "", "203.0.113.9", "ua")
	require.ErrorIs(t, err, ErrAccountNotActive)
	reader.get = membershipIn(MembershipStatusActive)
	_, _, _, err = svc.RefreshToken(managedScope(admitted()), res.RefreshToken, "", "203.0.113.9", "ua")
	require.ErrorIs(t, err, ErrUnauthenticated, "the refused token was spent")
}

func TestRefreshToken_ManagedStandingUnreadKeepsTheToken(t *testing.T) {
	svc, reader, res := managedSignedIn(t)
	reader.get = func(string, string, string) (*TenantMembership, error) { return nil, errors.New("db down") }
	_, _, _, err := svc.RefreshToken(managedScope(admitted()), res.RefreshToken, "", "203.0.113.9", "ua")
	require.ErrorIs(t, err, ErrAccountNotActive)
	reader.get = membershipIn(MembershipStatusActive)
	_, access, refreshed, err := svc.RefreshToken(managedScope(admitted()), res.RefreshToken, "", "203.0.113.9", "ua")
	require.NoError(t, err, "a failed read leaves the token for a retry")
	require.NotEmpty(t, access)
	require.NotEmpty(t, refreshed)
}

// A refresh judges a managed account's standing once, before it consumes
// the token: the token issue that follows does not read it again, so a read
// failing then cannot spend the token.
func TestRefreshToken_ManagedStandingIsReadOnce(t *testing.T) {
	svc, reader, res := managedSignedIn(t)
	before := reader.reads
	reads := 0
	reader.get = func(projectID, tenantID, userID string) (*TenantMembership, error) {
		reads++
		if reads > 1 {
			return nil, errors.New("db down")
		}
		return &TenantMembership{ProjectID: projectID, TenantID: tenantID, UserID: userID, Status: MembershipStatusActive}, nil
	}
	_, access, refreshed, err := svc.RefreshToken(managedScope(admitted()), res.RefreshToken, "", "203.0.113.9", "ua")
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refreshed)
	require.Equal(t, 1, reads, "one read per refresh")
	require.Equal(t, before+1, reader.reads)
}

// Every rule an agent's owner is held to runs through agentOwnerStanding: an
// agent of a managed owner who is suspended in the tenant, or whose tenant
// is suspended, is refused its next session, and gets one again once the
// owner is restored.
func TestAgentSession_ManagedOwnerNeedsStandingInTheTenant(t *testing.T) {
	f := newAgentFixture(t)
	reader := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	tenants := tenantIn(TenantStatusClaimed)
	f.svc.WithManagedMemberships(reader, tenants)
	f.repo.mu.Lock()
	f.owner.ManagedByTenantID, f.owner.SetUpAtMs = mTestTenant, 1
	f.repo.mu.Unlock()
	agent := seedAgent(f.repo, f.owner.ID)
	_, refresh := issueAgentTokens(t, f, agent)

	reader.get = membershipIn(MembershipStatusSuspended)
	_, _, _, err := f.svc.RefreshToken(context.Background(), refresh, "", "", "")
	require.ErrorIs(t, err, ErrAccountNotActive)
	_, _, err = f.svc.issueTokensWithSessionStart(context.Background(), agent, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.ErrorIs(t, err, ErrAccountNotActive, "the token chokepoint refuses too")

	reader.get = membershipIn(MembershipStatusActive)
	_, refresh = issueAgentTokens(t, f, agent)
	_, _, _, err = f.svc.RefreshToken(context.Background(), refresh, "", "", "")
	require.NoError(t, err, "restored, the owner's agent gets sessions again")

	f.svc.WithManagedMemberships(reader, tenantIn(TenantStatusSuspended))
	_, _, _, err = f.svc.RefreshToken(context.Background(), refresh, "", "", "")
	require.Error(t, err, "a suspended tenant's managed owner stands behind no agent")
}

func TestAgentOwnerStanding_IsTheOneRule(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo()).WithManagedMemberships(&managedMembershipsMock{get: membershipIn(MembershipStatusSuspended)}, tenantIn(TenantStatusClaimed))
	ctx := managedScope(admitted())
	require.NoError(t, svc.agentOwnerStanding(ctx, &User{ID: "p", Kind: UserKindPerson, Status: StatusActive}))
	require.ErrorIs(t, svc.agentOwnerStanding(ctx, &User{ID: "a", Kind: UserKindAgent, Status: StatusActive}), errAgentOwnerNotActive)
	require.ErrorIs(t, svc.agentOwnerStanding(ctx, &User{ID: "m", Kind: UserKindPerson, Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: 1}), ErrAccountNotActive)

	oauth := &AgentOAuthService{auth: svc}
	require.ErrorIs(t, oauth.ownerStanding(ctx, &User{ID: "a", Kind: UserKindAgent, Status: StatusActive}), ErrPermissionDenied)
	unread := newTestAuthService(t, newFakeRepo())
	err := (&AgentOAuthService{auth: unread}).ownerStanding(ctx, &User{ID: "m", Kind: UserKindPerson, Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: 1})
	require.ErrorIs(t, err, errManagedStandingUnread)
	require.False(t, isAgentOAuthAdmissionRefusal(err), "an unread standing does not end a grant")
	require.True(t, isAgentOAuthAdmissionRefusal(ErrAccountNotActive))
}
