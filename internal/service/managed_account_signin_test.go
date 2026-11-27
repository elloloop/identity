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

func TestRefuseManagedAccount(t *testing.T) {
	readErr := errors.New("db down")
	setUp := time.Now().UnixMilli()
	for name, tc := range map[string]struct {
		user   User
		reader *managedMembershipsMock
		want   error
		reads  int
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
	} {
		t.Run(name, func(t *testing.T) {
			svc := newTestAuthService(t, newFakeRepo())
			if tc.reader != nil {
				svc.WithManagedMemberships(tc.reader)
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
	svc := newTestAuthService(t, repo).WithManagedMemberships(reader)
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
