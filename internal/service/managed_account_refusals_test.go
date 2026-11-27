package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// seedManaged seeds an account mTestTenant manages at email, active and set
// up unless status says otherwise.
func seedManaged(repo *fakeRepo, email, status string) *User {
	u := seedUser(repo, email, "hash", status)
	repo.mu.Lock()
	u.Kind = UserKindPerson
	u.ManagedByTenantID = mTestTenant
	u.SetUpAtMs = 1
	u.SetupEpoch = 1
	u.EmailVerified = true
	repo.mu.Unlock()
	return u
}

func TestOAuthLogin_RefusesAManagedAccountByEmail(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)

	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{Code: fakeOAuthCode("ann@acme.example.com", "Ann", "", "google"), Provider: "google", RedirectURI: "https://app/cb"})
	require.ErrorIs(t, err, ErrManagedAccount)
	links, err := repo.ListOAuthIdentitiesForUser(ctx, managed.ID)
	require.NoError(t, err)
	require.Empty(t, links, "no provider is linked to a managed account")
}

func TestOAuthLogin_RefusesAManagedAccountByItsLink(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: managed.ID, Provider: "google", ProviderUserID: "sub-ann@acme.example.com", EmailAtLinkTime: "ann@acme.example.com", CreatedAt: 1,
	}))
	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{Code: fakeOAuthCode("ann@acme.example.com", "Ann", "", "google"), Provider: "google", RedirectURI: "https://app/cb"})
	require.ErrorIs(t, err, ErrManagedAccount)
}

func TestOAuthLogin_PersonalAccountsAreUnchanged(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seed := seedUser(repo, "bob@example.com", "", StatusActive)
	res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: fakeOAuthCode("bob@example.com", "Bob", "", "google"), Provider: "google", RedirectURI: "https://app/cb"})
	require.NoError(t, err)
	require.Equal(t, seed.ID, res.User.ID)
}

func TestTenantOwnsProvider_NoTenantOwnsOneYet(t *testing.T) {
	for _, p := range []string{"google", "microsoft", "github", "apple", "oidc"} {
		require.False(t, tenantOwnsProvider(mTestTenant, p), p)
	}
	require.NoError(t, refuseManagedProvider(context.Background(), newTestAuthService(t, newFakeRepo()).logger, mTestProject, &User{ID: "p"}, "google"))
}

func TestPasswordless_InvitedManagedAccountGetsNothing(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	invited := seedManaged(repo, "ann@acme.example.com", StatusInvited)
	repo.mu.Lock()
	invited.SetUpAtMs = 0
	invited.EmailVerified = false
	repo.mu.Unlock()
	ctx := context.Background()

	require.True(t, svc.managedAccountWaiting(ctx, "ann@acme.example.com"))
	require.False(t, svc.managedAccountWaiting(ctx, "nobody@example.com"))
	_, err := svc.completePasswordlessLogin(ctx, canonicalize("ann@acme.example.com"), "email_code", "", "")
	require.ErrorIs(t, err, ErrManagedAccount)
	got, err := repo.GetUser(ctx, invited.ID)
	require.NoError(t, err)
	require.False(t, got.EmailVerified, "a refused code proves nothing on the account")

	repo.mu.Lock()
	invited.Status, invited.SetUpAtMs = StatusActive, 1
	repo.mu.Unlock()
	require.False(t, svc.managedAccountWaiting(ctx, "ann@acme.example.com"), "a set-up managed account gets codes")

	repo.findUserByEmailErr = errors.New("db down")
	require.False(t, svc.managedAccountWaiting(ctx, "ann@acme.example.com"), "a failed lookup sends as before")
}

func TestMerge_RefusesAManagedAccountOnEitherSide(t *testing.T) {
	repo := newFakeRepo()
	ctx := context.Background()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	personal := seedUser(repo, "bob@example.com", "hash", StatusActive)
	require.ErrorIs(t, checkSurvivor(ctx, repo, managed), ErrManagedAccount)
	require.ErrorIs(t, checkMergeable(ctx, repo, managed, personal), ErrManagedAccount)
	require.ErrorIs(t, checkMergeable(ctx, repo, personal, managed), ErrManagedAccount)
	require.False(t, managedAccountsMayMerge(personal, managed))
	require.True(t, managedAccountsMayMerge(personal, &User{}))
}

func TestCreateAgent_RefusesAManagedOwner(t *testing.T) {
	f := newAgentFixture(t)
	managed := seedManaged(f.repo, "ann@acme.example.com", StatusActive)
	_, err := f.svc.CreateAgent(context.Background(), managed.ID, "Helper", "", "", "", "", "managed-key")
	require.ErrorIs(t, err, ErrManagedAccount)
	_, err = f.svc.CreateAgent(context.Background(), f.admin.ID, "Helper", "", managed.ID, "", "", "admin-key")
	require.ErrorIs(t, err, ErrManagedAccount, "an admin cannot give a managed account an agent either")
}

func TestRequestEmailChange_RefusesAManagedAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	err := svc.RequestEmailChange(context.Background(), managed.ID, SessionSignIn{}, "ann@example.net", "whatever")
	require.ErrorIs(t, err, ErrManagedAccount)
}

func TestDeleteMyAccount_RefusesAManagedAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestProfileServiceForDeletion(repo, newRecordingAuditWriter())
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	_, err := svc.DeleteMyAccount(context.Background(), managed.ID, SessionSignIn{}, "")
	require.ErrorIs(t, err, ErrManagedAccount)
	got, err := repo.GetUser(context.Background(), managed.ID)
	require.NoError(t, err)
	require.Equal(t, StatusActive, got.Status)
}

func TestMaybeAutoFormTenant_SkipsAManagedAccount(t *testing.T) {
	repo := newFakeRepo()
	af := &fakeAutoFormer{}
	svc := newTestAuthService(t, repo).WithTenantAutoFormer(af)
	svc.maybeAutoFormTenant(withProject(mTestProject), &User{ID: "u", Email: "ann@acme.example.com", ManagedByTenantID: mTestTenant})
	require.Zero(t, len(af.calls))
	svc.maybeAutoFormTenant(withProject(mTestProject), &User{ID: "p", Email: "bob@acme.example.com"})
	require.Equal(t, 1, len(af.calls), "a personal account still forms its domain's tenant")
}

// managedMemberFixture is a membership fixture with the caller, mInviteeID,
// an account mTestTenant manages.
func managedMemberFixture(t *testing.T) *membershipFixture {
	t.Helper()
	f := newMembershipFixture()
	f.users.set(mTestProject, &User{ID: mInviteeID, Email: maAddress, EmailVerified: true, Status: StatusActive, Kind: UserKindPerson, ManagedByTenantID: mTestTenant})
	return f
}

func TestMembership_RefusesAManagedAccountsSelfServicePaths(t *testing.T) {
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: mTestProject, Access: ProjectAccessConfig{Mode: AccessModeOpen}, Tenants: ProjectTenantsConfig{SelfService: true}})

	f := managedMemberFixture(t)
	_, err := f.svc.CreateTenant(ctx, mInviteeID, "Side project", "", "")
	require.ErrorIs(t, err, ErrManagedAccount)

	f = managedMemberFixture(t)
	f.svc.WithDomains(newFakeDomainStore())
	_, err = f.svc.JoinTenantByDomain(ctx, mInviteeID, "other-tenant", "", "")
	require.ErrorIs(t, err, ErrManagedAccount)

	f = managedMemberFixture(t)
	f.seedAdmin(mTestProject, "other-tenant", mAdminID)
	raw := "ordinary-token"
	f.invitations.byID[f.invitations.key(mTestProject, "inv-other")] = &TenantInvitation{
		ID: "inv-other", ProjectID: mTestProject, TenantID: "other-tenant", TokenHash: sha256Hex(raw),
		Email: maAddress, Role: RoleMember, Status: InvitationStatusPending, InvitedBy: mAdminID,
	}
	_, err = f.svc.AcceptTenantInvitation(ctx, mInviteeID, raw)
	require.ErrorIs(t, err, ErrManagedAccount)
	require.Equal(t, InvitationStatusPending, f.invitations.byID[f.invitations.key(mTestProject, "inv-other")].Status)

	f = managedMemberFixture(t)
	f.seedMember(mTestProject, mTestTenant, mInviteeID, RoleAdmin)
	f.seedAdmin(mTestProject, mTestTenant, "owner-2")
	f.seedMember(mTestProject, mTestTenant, mAdminID, RoleAdmin)
	err = f.svc.RemoveTenantMember(ctx, mInviteeID, SessionSignIn{}, mTestTenant, mInviteeID, "", "")
	require.ErrorIs(t, err, ErrManagedAccount, "a managed admin cannot leave")
	err = f.svc.RemoveTenantMember(ctx, mAdminID, SessionSignIn{}, mTestTenant, mAdminID, "", "")
	require.NoError(t, err, "a personal admin still may")

	storeErr := errors.New("db down")
	f = managedMemberFixture(t)
	f.seedMember(mTestProject, mTestTenant, mInviteeID, RoleAdmin)
	f.users.getErr = storeErr
	err = f.svc.RemoveTenantMember(ctx, mInviteeID, SessionSignIn{}, mTestTenant, mInviteeID, "", "")
	require.ErrorIs(t, err, storeErr)
}

// managedAdminDB is a graph store with an admin and an account mTestTenant
// manages, target-1.
func managedAdminDB() *fakeDB {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", maAddress, "Ann", "member", "active")
	db.nodes["target-1"].Payload[ufManagedByTenantID] = mTestTenant
	return db
}

func TestAdminService_RefusesManagedAccounts(t *testing.T) {
	ctx := context.Background()
	for name, call := range map[string]func(*AdminService) error{
		"deactivate": func(s *AdminService) error { return s.DeactivateUser(ctx, "admin-1", "target-1", "") },
		"reactivate": func(s *AdminService) error { return s.ReactivateUser(ctx, "admin-1", SessionSignIn{}, "target-1") },
		"reset password": func(s *AdminService) error {
			_, err := s.ResetUserPassword(ctx, "admin-1", SessionSignIn{}, "target-1", true)
			return err
		},
		"update": func(s *AdminService) error {
			_, err := s.UpdateUser(ctx, "admin-1", SessionSignIn{}, "target-1", "New", "", "")
			return err
		},
		"delete": func(s *AdminService) error { return s.DeleteUser(ctx, "admin-1", "target-1") },
	} {
		t.Run(name, func(t *testing.T) {
			repo := newFakeRepo()
			repo.users["target-1"] = &User{ID: "target-1", Email: maAddress, Status: StatusActive, ManagedByTenantID: mTestTenant}
			db := managedAdminDB()
			require.ErrorIs(t, call(newTestAdminServiceWithRepo(db, repo)), ErrManagedAccount)
			require.Equal(t, "active", db.nodes["target-1"].Payload[ufStatus])
			require.NotNil(t, repo.users["target-1"], "the account is kept")
		})
	}
}

func TestPurge_EndsAManagedAccountsSetUpLinksFirst(t *testing.T) {
	ctx := context.Background()
	managed := &User{ID: "target-1", Email: maAddress, Status: StatusActive, ManagedByTenantID: mTestTenant}

	repo := newFakeRepo()
	repo.users["target-1"] = managed
	var ended string
	svc := newTestAdminServiceWithRepo(newFakeDB(), repo).WithManagedSetups(&managedSetupsMock{links: func(_, userID string) error {
		ended = userID
		return nil
	}})
	require.NoError(t, svc.PurgeAccount(ctx, "actor", managed))
	require.Equal(t, "target-1", ended)
	require.Nil(t, repo.users["target-1"])

	repo = newFakeRepo()
	repo.users["target-1"] = managed
	storeErr := errors.New("db down")
	svc = newTestAdminServiceWithRepo(newFakeDB(), repo).WithManagedSetups(&managedSetupsMock{links: func(string, string) error { return storeErr }})
	require.ErrorIs(t, svc.PurgeAccount(ctx, "actor", managed), storeErr)
	require.NotNil(t, repo.users["target-1"], "nothing is purged when the links could not be ended")

	svc = newTestAdminServiceWithRepo(newFakeDB(), repo)
	require.ErrorIs(t, svc.PurgeAccount(ctx, "actor", managed), ErrUnavailable)
	require.NotNil(t, repo.users["target-1"])
}

// The repair rewrites and merges no account a tenant manages: the tenant
// gave it its address, and a merge would move it out of the tenant's hands.
func TestRepairStoredEmails_SkipsManagedAccounts(t *testing.T) {
	svc, repo, _ := repairFixture(t)
	lone := seedVerified(repo, "Ann.Lee@Acme.Example.com", "")
	lone.ManagedByTenantID = mTestTenant
	pairManaged := seedVerified(repo, "first.last@gmail.com", "")
	pairManaged.ManagedByTenantID = mTestTenant
	seedVerified(repo, "firstlast@gmail.com", "")

	for _, item := range runRepair(t, svc, true).Items {
		require.Equal(t, EmailRepairSkip, item.Action, item.UserID)
		require.Equal(t, repairReasonTenantManaged, item.Reason)
	}
	require.Equal(t, "Ann.Lee@Acme.Example.com", storedUser(t, repo, lone.ID).Email)
	require.Equal(t, "first.last@gmail.com", storedUser(t, repo, pairManaged.ID).Email)
}

func TestLinkIdentity_RefusesAManagedAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	_, err := svc.LinkIdentity(ctx, managed.ID, SessionSignIn{AuthTimeSec: svc.nowMs() / 1000, AMR: []string{AMRCredentialEnrollment}},
		fakeOAuthCode("ann@acme.example.com", "Ann", "", "google"), "google", "https://app/cb", "", "", "")
	require.ErrorIs(t, err, ErrManagedAccount)
	links, err := repo.ListOAuthIdentitiesForUser(ctx, managed.ID)
	require.NoError(t, err)
	require.Empty(t, links)
}
