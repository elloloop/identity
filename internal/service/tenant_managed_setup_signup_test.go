package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
)

const managedSetupToken = "managed-set-up-token"

// managedSetupFixture is an AuthService whose server enables managed
// accounts, with an invited managed account and its pending set-up link.
type managedSetupFixture struct {
	svc         *AuthService
	repo        *fakeRepo
	invitations *fakeInvitationStore
	tenants     *fakeTenantStore
	store       *managedSetupsMock
	audit       *recordingAuditWriter
	publisher   *capturePublisher
	account     *User
}

func newManagedSetupFixture(t *testing.T) *managedSetupFixture {
	t.Helper()
	repo := newFakeRepo()
	w := newRecordingAuditWriter()
	invitations := newFakeInvitationStore()
	tenants := newFakeTenantStore()
	tenants.ensure(mTestProject, mTestTenant)
	store := &managedSetupsMock{}
	pub := &capturePublisher{}
	svc := newTestAuthServiceWithAudit(t, repo, w).
		WithOpenInvitations(invitations).
		WithMailDelivery(true).
		WithManagedAccounts(store, tenants).
		WithEventPublisher(pub)
	svc.cfg.ManagedAccountsEnabled = true
	id, err := repo.CreateUser(context.Background(), &User{
		Email: maAddress, Name: "Ann Lee", Status: StatusInvited, ManagedByTenantID: mTestTenant, SetupEpoch: 1,
	})
	require.NoError(t, err)
	account, err := repo.GetUser(context.Background(), id)
	require.NoError(t, err)
	invitations.byID[invitations.key(mTestProject, "inv-ann")] = &TenantInvitation{
		ID: "inv-ann", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(managedSetupToken),
		Email: maAddress, Role: RoleMember, Status: InvitationStatusPending, UserID: id, DeliveryEmail: maDelivery,
		SetupEpoch: 1, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
	}
	return &managedSetupFixture{svc: svc, repo: repo, invitations: invitations, tenants: tenants, store: store, audit: w, publisher: pub, account: account}
}

func (f *managedSetupFixture) link() *TenantInvitation {
	return f.invitations.byID[f.invitations.key(mTestProject, "inv-ann")]
}

// completes programs the store to set the account up with its membership in
// membershipStatus.
func (f *managedSetupFixture) completes(membershipStatus string, firstSetUp bool) *ManagedSetupCompletion {
	var got ManagedSetupCompletion
	f.store.complete = func(c ManagedSetupCompletion) (*ManagedSetupCompleted, error) {
		got = c
		u := *f.account
		u.Status, u.EmailVerified, u.PasswordHash, u.SetUpAtMs = StatusActive, true, c.PasswordHash, c.NowMs
		return &ManagedSetupCompleted{
			User:       &u,
			Membership: &TenantMembership{ProjectID: mTestProject, TenantID: mTestTenant, UserID: u.ID, Role: RoleMember, Status: membershipStatus},
			Invitation: &TenantInvitation{ID: c.InvitationID, Status: InvitationStatusAccepted},
			FirstSetUp: firstSetUp,
		}, nil
	}
	return &got
}

func (f *managedSetupFixture) setUp(ctx context.Context, password string) (*LoginResult, error) {
	return f.svc.SignUpWithTenantInvitation(ctx, managedSetupToken, "", password, "203.0.113.9", "setup-test")
}

func TestSignUpWithTenantInvitation_ManagedSetupSignsIn(t *testing.T) {
	f := newManagedSetupFixture(t)
	got := f.completes(MembershipStatusActive, true)
	f.svc.cfg.PasswordSignupEnabled = false

	res, err := f.setUp(managedScope(admitted()), signupPassword)
	require.NoError(t, err, "a set-up needs neither password sign-up nor a name")
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
	require.Equal(t, "Ann Lee", res.User.Name, "the name is the tenant's")
	require.Empty(t, res.User.PasswordHash)
	require.Equal(t, "inv-ann", got.InvitationID)
	require.Equal(t, mTestProject, got.ProjectID)
	require.NotEmpty(t, got.PasswordHash)
	require.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventManagedAccountSetUp), f.account.ID, f.account.ID))
	require.Equal(t, 1, f.audit.countByEventTypeAndDetail(string(audit.EventLoginSuccess), "method", "managed_account_setup"))
	evs := f.publisher.all()
	require.Len(t, evs, 1)
	require.Equal(t, events.EventUserCreated, evs[0].Type)
}

func TestSignUpWithTenantInvitation_ManagedSetupAfterAResetAnnouncesNothing(t *testing.T) {
	f := newManagedSetupFixture(t)
	f.completes(MembershipStatusActive, false)
	_, err := f.setUp(managedScope(admitted()), signupPassword)
	require.NoError(t, err)
	require.Empty(t, f.publisher.all())
}

func TestSignUpWithTenantInvitation_ManagedSetupKeepsASuspensionAndSignsNothingIn(t *testing.T) {
	f := newManagedSetupFixture(t)
	f.completes(MembershipStatusSuspended, true)
	res, err := f.setUp(managedScope(admitted()), signupPassword)
	require.ErrorIs(t, err, ErrMemberSuspended)
	require.Nil(t, res)
	require.Zero(t, f.audit.countByEventType(string(audit.EventLoginSuccess)))
	require.Equal(t, 1, f.audit.countByEventType(string(audit.EventManagedAccountSetUp)))
}

func TestSignUpWithTenantInvitation_ManagedSetupRefusals(t *testing.T) {
	storeErr := errors.New("db down")
	for name, tc := range map[string]struct {
		access   ProjectAccessConfig
		password string
		mutate   func(*managedSetupFixture)
		want     error
	}{
		"no password":          {access: admitted(), want: ErrInvalidArgument},
		"token outside email":  {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.link().TokenOnlyInEmail = false }, want: ErrInvitationSignupUnavailable},
		"mail not delivered":   {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.svc.mailDelivers = false }, want: ErrInvitationSignupUnavailable},
		"expired":              {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.link().ExpiresAtMs = 1 }, want: ErrInvitationExpired},
		"revoked":              {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.link().Status = InvitationStatusRevoked }, want: ErrInvitationRevoked},
		"project not opted in": {access: ProjectAccessConfig{}, password: signupPassword, want: ErrManagedAccountsNotAdmitted},
		"self-service tenant": {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) {
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, CreatedBy: "someone"})
		}, want: ErrManagedAccountsNotAdmitted},
		"replaced link":   {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.link().SetupEpoch = 0 }, want: ErrManagedSetupStale},
		"account gone":    {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.link().UserID = "nobody" }, want: ErrManagedSetupStale},
		"account lookup":  {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.repo.getUserErr = storeErr }, want: storeErr},
		"denied domain":   {access: ProjectAccessConfig{AdmitManagedAccounts: true, BlockedDomains: []string{maDomain}}, password: signupPassword, want: ErrManagedAccountsNotAdmitted},
		"weak password":   {access: admitted(), password: "short", want: ErrWeakPassword},
		"link lookup":     {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.invitations.getErr = storeErr }, want: storeErr},
		"store stale":     {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.store.complete = completeFails(ErrManagedSetupStale) }, want: ErrManagedSetupStale},
		"store error":     {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.store.complete = completeFails(storeErr) }, want: storeErr},
		"server flag off": {access: admitted(), password: signupPassword, mutate: func(f *managedSetupFixture) { f.svc.cfg.ManagedAccountsEnabled = false }, want: ErrInvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedSetupFixture(t)
			f.completes(MembershipStatusActive, true)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			res, err := f.setUp(managedScope(tc.access), tc.password)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, res)
			require.Empty(t, f.publisher.all())
		})
	}
}

func completeFails(err error) func(ManagedSetupCompletion) (*ManagedSetupCompleted, error) {
	return func(ManagedSetupCompletion) (*ManagedSetupCompleted, error) { return nil, err }
}

func TestSignUpWithTenantInvitation_OrdinaryTokenFallsThroughWithTheFlagOn(t *testing.T) {
	f := newManagedSetupFixture(t)
	_, err := f.svc.SignUpWithTenantInvitation(managedScope(admitted()), "no-such-token", "Ann", signupPassword, "", "")
	require.ErrorIs(t, err, ErrInvitationSignupUnavailable, "an unknown token is answered as before: this project has not opted in")
	f.svc.cfg.PasswordSignupEnabled = false
	_, err = f.svc.SignUpWithTenantInvitation(managedScope(admitted()), "no-such-token", "Ann", signupPassword, "", "")
	require.ErrorIs(t, err, ErrSignupDisabled)
	_, err = f.svc.SignUpWithTenantInvitation(context.Background(), managedSetupToken, "", signupPassword, "", "")
	require.Error(t, err, "a request with no project sets nothing up")
	require.Empty(t, f.publisher.all())
}

func TestManagedSetupRefusalReason(t *testing.T) {
	for err, want := range map[error]string{
		ErrManagedSetupStale:       "stale",
		ErrManagedDomainUnverified: "domain_unverified",
		ErrInvitationUsed:          "invitation_closed",
		ErrInvitationExpired:       "invitation_closed",
		ErrNotFound:                "invitation_closed",
		errors.New("boom"):         "store_error",
	} {
		require.Equal(t, want, managedSetupRefusalReason(err))
	}
}

func TestManagedAccountsAdmitted(t *testing.T) {
	require.False(t, managedAccountsAdmitted(nil, admitted(), &Tenant{}))
	on := testConfig()
	on.ManagedAccountsEnabled = true
	require.False(t, managedAccountsAdmitted(on, admitted(), nil))
	require.True(t, managedAccountsAdmitted(on, admitted(), &Tenant{}))
	require.False(t, managedAccountsAdmitted(on, admitted(), &Tenant{CreatedBy: "u"}))
	require.True(t, managedAccountsAdmitted(on, ProjectAccessConfig{AdmitManagedAccounts: true, AdmitManagedAccountsSelfService: true}, &Tenant{CreatedBy: "u"}))
}
