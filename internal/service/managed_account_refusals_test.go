package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
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

	before, err := repo.GetUser(ctx, managed.ID)
	require.NoError(t, err)
	_, err = svc.OAuthLogin(ctx, OAuthLoginParams{Code: fakeOAuthCode("ann@acme.example.com", "Someone Else", "https://example.com/a.png", "google"), Provider: "google", RedirectURI: "https://app/cb"})
	require.ErrorIs(t, err, ErrManagedAccount)
	after, err := repo.GetUser(ctx, managed.ID)
	require.NoError(t, err)
	require.Equal(t, before.Name, after.Name, "the provider's profile is not applied")
	require.Equal(t, before.EmailVerified, after.EmailVerified)
	links, err := repo.ListOAuthIdentitiesForUser(ctx, managed.ID)
	require.NoError(t, err)
	require.Empty(t, links, "no provider is linked to a managed account")
}

// A provider that did not prove the account's own address is refused as it
// would be for any account, so it learns nothing about whether a tenant
// manages the address.
func TestOAuthLogin_UnprovenAddressLearnsNothingAboutManagement(t *testing.T) {
	ctx := context.Background()
	answer := func(managed bool) error {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		if managed {
			seedManaged(repo, "ann@acme.example.com", StatusActive)
		} else {
			seedUser(repo, "ann@acme.example.com", "hash", StatusActive)
		}
		_, err := svc.OAuthLogin(ctx, OAuthLoginParams{Code: fakeOAuthCode("ann+x@acme.example.com", "Ann", "", "google"), Provider: "google", RedirectURI: "https://app/cb"})
		return err
	}
	managedErr, personalErr := answer(true), answer(false)
	require.ErrorIs(t, managedErr, ErrUnauthenticated)
	require.NotErrorIs(t, managedErr, ErrManagedAccount, "no managed-address oracle")
	require.Equal(t, personalErr.Error(), managedErr.Error(), "the same answer either way")
}

func TestOAuthLogin_RefusesAManagedAccountByItsLink(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: managed.ID, Provider: "google", ProviderUserID: "sub-ann@acme.example.com", EmailAtLinkTime: "ann@acme.example.com", CreatedAt: 1,
	}))
	before, err := repo.GetUser(ctx, managed.ID)
	require.NoError(t, err)
	_, err = svc.OAuthLogin(ctx, OAuthLoginParams{Code: fakeOAuthCode("ann@acme.example.com", "Someone Else", "https://example.com/a.png", "google"), Provider: "google", RedirectURI: "https://app/cb"})
	require.ErrorIs(t, err, ErrManagedAccount)
	after, err := repo.GetUser(ctx, managed.ID)
	require.NoError(t, err)
	require.Equal(t, before.Name, after.Name, "the provider's profile is not applied")
	require.Equal(t, before.AvatarURL, after.AvatarURL)
	require.Equal(t, before.UpdatedAt, after.UpdatedAt, "nothing is written to the account")
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
	ctx := context.Background()
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	managed := &User{ID: "m", ManagedByTenantID: mTestTenant}
	personal := &User{ID: "p"}
	require.ErrorIs(t, refuseManagedMerge(ctx, logger, mTestProject, managed, personal), ErrManagedAccount)
	require.ErrorIs(t, refuseManagedMerge(ctx, logger, mTestProject, personal, managed), ErrManagedAccount)
	require.NoError(t, refuseManagedMerge(ctx, logger, mTestProject, personal, &User{ID: "q"}))
	entries := logs.FilterMessage("managed_account_refused").All()
	require.Len(t, entries, 2)
	require.Equal(t, "merge", entries[0].ContextMap()["surface"])

	db := newFakeDB()
	db.addUser("admin-1", "admin@example.com", "Admin", "admin", "active")
	repo := newFakeRepo()
	repo.users["m"] = &User{ID: "m", Email: maAddress, Status: StatusActive, ManagedByTenantID: mTestTenant}
	repo.users["p"] = &User{ID: "p", Email: "bob@example.com", Status: StatusActive}
	admin := newTestAdminServiceWithRepo(db, repo)
	_, err := admin.MergeUsers(ctx, "admin-1", SessionSignIn{}, "p", "m", false)
	require.ErrorIs(t, err, ErrManagedAccount, "an admin merging a managed account away")
	_, err = admin.MergeUsers(ctx, "admin-1", SessionSignIn{}, "m", "p", false)
	require.ErrorIs(t, err, ErrManagedAccount, "an admin merging into a managed account")
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
	sessions := newFakeRepo()
	f.svc.WithAccounts(sessions)
	err = f.svc.RemoveTenantMember(ctx, mInviteeID, liveSession(t, sessions, mInviteeID), mTestTenant, mInviteeID, "", "")
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
	db.addUser("admin-1", "admin@example.com", "Admin", "admin", "active")
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
	svc := newTestAuthService(t, repo).WithManagedMemberships(&managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenantIn(TenantStatusClaimed))
	ctx := context.Background()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	signIn := liveSession(t, repo, managed.ID)
	signIn.AMR = []string{AMRCredentialEnrollment}
	_, err := svc.LinkIdentity(ctx, managed.ID, signIn,
		fakeOAuthCode("ann@acme.example.com", "Ann", "", "google"), "google", "https://app/cb", "", "", "")
	require.ErrorIs(t, err, ErrManagedAccount)
	links, err := repo.ListOAuthIdentitiesForUser(ctx, managed.ID)
	require.NoError(t, err)
	require.Empty(t, links)
}

// A managed account out of standing in its tenant comes to own no agent by
// any path: an offer to it, its acceptance of an offer, or an admin's
// reassignment of an orphan to it.
func TestAgentTransfer_ToAManagedAccountOutOfStandingIsRefused(t *testing.T) {
	ctx := context.Background()
	suspended := &managedMembershipsMock{get: membershipIn(MembershipStatusSuspended)}

	f := newAgentFixture(t)
	f.svc.WithManagedMemberships(suspended, tenantIn(TenantStatusClaimed))
	managed := seedManaged(f.repo, "ann@acme.example.com", StatusActive)
	agent := seedAgent(f.repo, f.owner.ID)
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, SessionSignIn{}, agent.ID, managed.ID, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument, "an offer to a managed account out of standing")
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	require.Empty(t, stored.PendingOwnerUserID)

	f.repo.mu.Lock()
	f.repo.users[agent.ID].PendingOwnerUserID = managed.ID
	f.repo.mu.Unlock()
	_, err = f.svc.AcceptAgentTransfer(ctx, managed.ID, agent.ID, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument, "a managed account out of standing accepting an offer")
	stored, _ = f.repo.GetUser(ctx, agent.ID)
	require.Equal(t, f.owner.ID, stored.OwnerUserID)

	g := newAgentFixture(t)
	g.svc.WithManagedMemberships(suspended, tenantIn(TenantStatusClaimed))
	managed = seedManaged(g.repo, "ann@acme.example.com", StatusActive)
	orphan := seedAgent(g.repo, g.owner.ID)
	require.NoError(t, g.repo.DeleteUser(ctx, g.owner.ID))
	_, err = g.svc.TransferAgent(ctx, g.admin.ID, SessionSignIn{}, orphan.ID, managed.ID, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument, "an orphan reassigned to a managed account out of standing")
	stored, _ = g.repo.GetUser(ctx, orphan.ID)
	require.Equal(t, g.owner.ID, stored.OwnerUserID)
}

// When a managed owner's standing cannot be read, creating an agent for it,
// offering it one and accepting one return that refusal as it is,
// retryable, rather than as an owner not eligible, and change nothing.
func TestAgentOwnership_StandingUnreadPassesThrough(t *testing.T) {
	ctx := context.Background()
	f := newAgentFixture(t)
	f.svc.WithManagedMemberships(&managedMembershipsMock{get: func(string, string, string) (*TenantMembership, error) {
		return nil, errors.New("db down")
	}}, tenantIn(TenantStatusClaimed))
	managed := seedManaged(f.repo, "ann@acme.example.com", StatusActive)
	agent := seedAgent(f.repo, f.owner.ID)

	_, err := f.svc.CreateAgent(ctx, f.admin.ID, SessionSignIn{}, "Helper", "", managed.ID, "", "", "unread-key")
	require.ErrorIs(t, err, ErrUnavailable, "creating an agent for it")
	_, err = f.svc.TransferAgent(ctx, f.owner.ID, SessionSignIn{}, agent.ID, managed.ID, "", "")
	require.ErrorIs(t, err, ErrUnavailable, "offering it an agent")
	f.repo.mu.Lock()
	f.repo.users[agent.ID].PendingOwnerUserID = managed.ID
	f.repo.mu.Unlock()
	_, err = f.svc.AcceptAgentTransfer(ctx, managed.ID, agent.ID, "", "")
	require.ErrorIs(t, err, ErrUnavailable, "accepting an offer")
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	require.Equal(t, f.owner.ID, stored.OwnerUserID)

	assert.Equal(t, 1, f.writer.countByEventTypeAndDetail(string(audit.EventAgentCreated), "step", "owner_standing_unread"), "the creation's refusal is audited")
	assert.Equal(t, 2, f.writer.countByEventTypeAndDetail(string(audit.EventAgentTransferred), "step", "owner_standing_unread"), "the offer's and the acceptance's")
	assert.Zero(t, f.writer.countByEventTypeAndDetail(string(audit.EventAgentCreated), "step", "owner_not_eligible"))
	assert.Zero(t, f.writer.countByEventTypeAndDetail(string(audit.EventAgentTransferred), "step", "owner_not_eligible"))
}

// An account waiting for its set-up is sent no password reset, and a reset
// token issued for it sets nothing.
func TestPasswordReset_InvitedManagedAccountGetsNone(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithManagedMemberships(&managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenantIn(TenantStatusClaimed))
	mailer := &recordingMailer{}
	svc.mailer = mailer
	invited := seedManaged(repo, "ann@acme.example.com", StatusInvited)
	ctx := context.Background()

	svc.sendPasswordResetNow(ctx, "ann@acme.example.com", emailLink{})
	require.Zero(t, mailer.count(), "no reset mail to a waiting managed account")

	require.NoError(t, repo.CreatePasswordResetToken(ctx, &PasswordResetToken{
		TokenHash: sha256Hex("reset-token"), UserID: invited.ID, Email: invited.Email, ExpiresAt: svc.nowMs() + 60_000, CreatedAt: svc.nowMs(),
	}))
	before, err := repo.GetUser(ctx, invited.ID)
	require.NoError(t, err)
	err = svc.ConfirmPasswordReset(ctx, "reset-token", signupPassword)
	require.ErrorIs(t, err, ErrManagedAccount)
	after, err := repo.GetUser(ctx, invited.ID)
	require.NoError(t, err)
	require.Equal(t, before.PasswordHash, after.PasswordHash, "the token sets no password")

	repo.mu.Lock()
	invited.Status = StatusActive
	repo.mu.Unlock()
	svc.sendPasswordResetNow(ctx, "ann@acme.example.com", emailLink{})
	require.Equal(t, 1, mailer.count(), "a set-up managed account still gets a reset")
}

// The merge refuses a managed account on the other side before it touches
// that account's failed-sign-in count.
func TestMergeAccounts_RefusesAManagedOtherBeforeTouchingIt(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AccountMergeEnabled = true
	hash, err := passwords.Hash(signupPassword)
	require.NoError(t, err)
	survivor := seedUser(repo, "bob@example.com", hash, StatusActive)
	other := seedManaged(repo, "ann@acme.example.com", StatusActive)
	repo.mu.Lock()
	survivor.EmailVerified = true
	other.PasswordHash = hash
	other.FailedLoginCount = 2
	repo.mu.Unlock()

	_, err = svc.MergeAccounts(context.Background(), survivor.ID, SessionSignIn{AuthTimeSec: svc.nowMs() / 1000, AMR: []string{AMRCredentialEnrollment}},
		"ann@acme.example.com", signupPassword, "", "", false)
	require.ErrorIs(t, err, ErrManagedAccount)
	got, err := repo.GetUser(context.Background(), other.ID)
	require.NoError(t, err)
	require.Equal(t, 2, got.FailedLoginCount, "the other account's failed-sign-in count is untouched")
}

// A managed account adds no recovery email: asking and verifying are both
// refused with POLICY, and nothing is sent or stored.
func TestRecoveryEmail_ManagedAccountAddsNone(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: mTestProject, Access: ProjectAccessConfig{Mode: AccessModeOpen}, RecoveryEmails: ProjectRecoveryEmailsConfig{Enabled: true}})
	signIn := SessionSignIn{AuthTimeSec: svc.nowMs() / 1000}

	err := svc.RequestRecoveryEmail(ctx, managed.ID, signIn, "ann@example.net")
	require.ErrorIs(t, err, ErrManagedAccountsNotAdmitted)
	_, err = svc.VerifyRecoveryEmail(ctx, managed.ID, signIn, "ann@example.net", "123456")
	require.ErrorIs(t, err, ErrManagedAccountsNotAdmitted)
	held, err := repo.ListRecoveryEmails(ctx, managed.ID)
	require.NoError(t, err)
	require.Empty(t, held)
}
