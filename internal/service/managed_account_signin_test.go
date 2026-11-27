package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

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

// A tenant's account owns no agent: an agent a managed account somehow
// owns gets no session, even while the owner is in good standing.
func TestAgentSession_ManagedOwnerStandsBehindNoAgent(t *testing.T) {
	f := newAgentFixture(t)
	reader := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	f.svc.WithManagedMemberships(reader, tenantIn(TenantStatusClaimed))
	agent := seedAgent(f.repo, f.owner.ID)
	_, refresh := issueAgentTokens(t, f, agent)
	f.repo.mu.Lock()
	f.owner.ManagedByTenantID, f.owner.SetUpAtMs = mTestTenant, 1
	f.repo.mu.Unlock()

	_, _, _, err := f.svc.RefreshToken(context.Background(), refresh, "", "", "")
	require.ErrorIs(t, err, ErrAccountNotActive)
	_, _, err = f.svc.issueTokensWithSessionStart(context.Background(), agent, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.ErrorIs(t, err, errAgentOwnerNotActive, "the token chokepoint refuses too")
}

func TestIsEligibleAgentOwner_IsTheOneRule(t *testing.T) {
	require.True(t, isEligibleAgentOwner(&User{ID: "p", Kind: UserKindPerson, Status: StatusActive}))
	require.False(t, isEligibleAgentOwner(&User{ID: "a", Kind: UserKindAgent, Status: StatusActive}))
	require.False(t, isEligibleAgentOwner(&User{ID: "m", Kind: UserKindPerson, Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: 1}),
		"an account a tenant manages owns no agent")
	require.False(t, isEligibleAgentOwner(nil))
	require.True(t, isAgentOAuthAdmissionRefusal(ErrPermissionDenied))
}

// A teammate's tokens stand on its grantor's standing: a managed project
// admin who granted the hire gets none for the teammate while suspended in
// the tenant, a failed read stays retryable, and a restored grantor gets
// them again. A managed lead owns no teammate, so its key gets none at all.
func TestTeammateOwnerStandsBehind_ManagedGrantorNeedsStanding(t *testing.T) {
	repo := newFakeRepo()
	lead := seedPerson(repo, "lead@example.com")
	grantor := seedPerson(repo, "admin@acme.example.com")
	repo.mu.Lock()
	grantor.Role, grantor.ManagedByTenantID, grantor.SetUpAtMs = RoleAdmin, mTestTenant, 1
	repo.mu.Unlock()
	teammate := seedAgent(repo, lead.ID)
	reader := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	keys := (&TeammateKeyService{base: repo, logger: zap.NewNop()}).WithManagedStanding(reader, tenantIn(TenantStatusClaimed))
	key := &TeammateKey{OwnerUserID: grantor.ID, TeammateID: teammate.ID}
	ctx := context.Background()

	require.NoError(t, keys.ownerStandsBehind(ctx, mTestProject, key))
	reader.get = membershipIn(MembershipStatusSuspended)
	require.ErrorIs(t, keys.ownerStandsBehind(ctx, mTestProject, key), ErrUnauthenticated)
	reader.get = func(string, string, string) (*TenantMembership, error) { return nil, errors.New("db down") }
	require.ErrorIs(t, keys.ownerStandsBehind(ctx, mTestProject, key), errManagedStandingUnread, "a failed read is not a refusal for good")
	reader.get = membershipIn(MembershipStatusActive)
	require.NoError(t, keys.ownerStandsBehind(ctx, mTestProject, key))

	unwired := &TeammateKeyService{base: repo, logger: zap.NewNop()}
	require.ErrorIs(t, unwired.ownerStandsBehind(ctx, mTestProject, key), errManagedStandingUnread, "unwired, a managed grantor fails closed")
	require.Equal(t, ErrUnauthenticated, standingRefusal(ErrAccountNotActive))
	require.NoError(t, standingRefusal(nil))

	repo.mu.Lock()
	lead.ManagedByTenantID, lead.SetUpAtMs = mTestTenant, 1
	repo.mu.Unlock()
	leadsKey := &TeammateKey{OwnerUserID: lead.ID, TeammateID: teammate.ID}
	require.ErrorIs(t, keys.ownerStandsBehind(ctx, mTestProject, leadsKey), ErrUnauthenticated, "a managed lead's teammate gets no token")
}
