package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

// managedSetupsMock is a ManagedSetupStore whose every method is the
// function the test programs; an unprogrammed method fails the call.
type managedSetupsMock struct {
	create   func(ManagedSetup) (*ManagedSetupIssued, error)
	complete func(ManagedSetupCompletion) (*ManagedSetupCompleted, error)
	revoke   func(projectID, tenantID, invitationID, by string) (*ManagedSetupRevoked, error)
	holders  func(projectID, tenantID string, addresses []string) (map[string]string, error)
	among    func(projectID, tenantID string, userIDs []string) (map[string]bool, error)
	links    func(projectID, userID string) error
}

var errNotProgrammed = errors.New("managedSetupsMock: method not programmed")

func (m *managedSetupsMock) CreateManagedSetup(_ context.Context, s ManagedSetup) (*ManagedSetupIssued, error) {
	if m.create == nil {
		return nil, errNotProgrammed
	}
	return m.create(s)
}

func (m *managedSetupsMock) CompleteManagedSetup(_ context.Context, c ManagedSetupCompletion) (*ManagedSetupCompleted, error) {
	if m.complete == nil {
		return nil, errNotProgrammed
	}
	return m.complete(c)
}

func (m *managedSetupsMock) RevokeManagedSetup(_ context.Context, projectID, tenantID, invitationID, by string) (*ManagedSetupRevoked, error) {
	if m.revoke == nil {
		return nil, errNotProgrammed
	}
	return m.revoke(projectID, tenantID, invitationID, by)
}

func (m *managedSetupsMock) ManagedAddressHolders(_ context.Context, projectID, tenantID string, addresses []string) (map[string]string, error) {
	if m.holders == nil {
		return nil, errNotProgrammed
	}
	return m.holders(projectID, tenantID, addresses)
}

func (m *managedSetupsMock) ManagedAccountsAmong(_ context.Context, projectID, tenantID string, userIDs []string) (map[string]bool, error) {
	if m.among == nil {
		return nil, errNotProgrammed
	}
	return m.among(projectID, tenantID, userIDs)
}

func (m *managedSetupsMock) RevokeSetupLinksOf(_ context.Context, projectID, userID string) error {
	if m.links == nil {
		return errNotProgrammed
	}
	return m.links(projectID, userID)
}

var _ ManagedSetupStore = (*managedSetupsMock)(nil)

const (
	maDomain   = "acme.example.com"
	maAddress  = "ann@" + maDomain
	maDelivery = "ann@example.net"
	maUserID   = "user-ann"
)

// managedScope is a request for mTestProject under access, an open project.
func managedScope(access ProjectAccessConfig) context.Context {
	if access.Mode == "" {
		access.Mode = AccessModeOpen
	}
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: mTestProject, Access: access})
}

func admitted() ProjectAccessConfig { return ProjectAccessConfig{AdmitManagedAccounts: true} }

// managedMembershipFixture is a membership fixture whose server enables
// managed accounts, with an owner of mTestTenant, writing set-up links
// through store and auditing to writer.
func managedMembershipFixture(store *managedSetupsMock) (*membershipFixture, *recordingAuditWriter) {
	f := newMembershipFixtureWith(true, &config.Config{ManagedAccountsEnabled: true})
	w := newRecordingAuditWriter()
	f.svc.WithManagedSetups(store).WithAudit(audit.NewLogger(w, "test-tenant", nil))
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	return f, w
}

func annRequest() ManagedAccountRequest {
	return ManagedAccountRequest{
		TenantID: mTestTenant, Username: "Ann", Domain: maDomain, DisplayName: "Ann Lee",
		DeliveryEmail: maDelivery, Role: RoleMember,
	}
}

func issuedFor(s ManagedSetup, created bool, previous string) *ManagedSetupIssued {
	return &ManagedSetupIssued{
		User: &User{ID: maUserID, Email: s.Address, Name: s.DisplayName},
		Invitation: &TenantInvitation{
			ID: "inv-ann", ProjectID: s.ProjectID, TenantID: s.TenantID, Email: s.Address, Role: s.Role,
			UserID: maUserID, DeliveryEmail: s.DeliveryEmail, Status: InvitationStatusPending, TokenOnlyInEmail: true,
		},
		Created: created, PreviousDeliveryEmail: previous,
	}
}

func TestCreateManagedSetupInvitation_CreatesMailsAndAudits(t *testing.T) {
	var got ManagedSetup
	f, w := managedMembershipFixture(&managedSetupsMock{create: func(s ManagedSetup) (*ManagedSetupIssued, error) {
		got = s
		return issuedFor(s, true, ""), nil
	}})

	out, err := f.svc.CreateManagedSetupInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, annRequest(), "203.0.113.1", "ua")
	require.NoError(t, err)
	require.Equal(t, EmailSent, out.EmailStatus)
	require.Empty(t, out.RawToken, "the token goes only into the email")
	require.Equal(t, maAddress, got.Address, "the username is lowered")
	require.Equal(t, maDomain, got.Domain)
	require.Equal(t, "Ann Lee", got.DisplayName)
	require.Equal(t, maDelivery, got.DeliveryEmail)
	require.Equal(t, mAdminID, got.InvitedBy)
	require.NotEmpty(t, got.TokenHash)
	require.Positive(t, got.Limits.MaxPerTenant)
	require.Equal(t, maDelivery, f.mailer.last().To)
	require.Contains(t, f.mailer.last().Text, maAddress)
	require.Equal(t, 1, w.countByEventTypeActorTarget(string(audit.EventManagedAccountCreated), mAdminID, maUserID))
}

func TestCreateManagedSetupInvitation_ResendAuditsADeliveryChange(t *testing.T) {
	for name, tc := range map[string]struct {
		previous string
		changed  bool
	}{
		"same address":    {maDelivery, false},
		"another address": {"old@example.net", true},
		"none pending":    {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			f, w := managedMembershipFixture(&managedSetupsMock{create: func(s ManagedSetup) (*ManagedSetupIssued, error) {
				return issuedFor(s, false, tc.previous), nil
			}})
			f.mailer.sendErr = errors.New("smtp down")
			out, err := f.svc.CreateManagedSetupInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, annRequest(), "", "")
			require.NoError(t, err)
			require.Equal(t, EmailSendFailed, out.EmailStatus, "a failed send does not fail the resend")
			details := w.detailsOf(string(audit.EventManagedAccountSetupResent))
			require.Len(t, details, 1)
			require.Equal(t, tc.changed, details[0]["delivery_changed"])
			require.Zero(t, w.countByEventType(string(audit.EventManagedAccountCreated)))
		})
	}
}

func TestCreateManagedSetupInvitation_Refusals(t *testing.T) {
	storeErr := errors.New("db down")
	for name, tc := range map[string]struct {
		cfg    *config.Config
		access ProjectAccessConfig
		mutate func(*membershipFixture, *ManagedAccountRequest)
		store  func(ManagedSetup) (*ManagedSetupIssued, error)
		noMail bool
		want   error
	}{
		"server flag off":      {cfg: &config.Config{}, access: admitted(), want: ErrManagedAccountsNotAdmitted},
		"project not opted in": {access: ProjectAccessConfig{}, want: ErrManagedAccountsNotAdmitted},
		"self-service tenant": {access: admitted(), mutate: func(f *membershipFixture, _ *ManagedAccountRequest) {
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, CreatedBy: mAdminID})
		}, want: ErrManagedAccountsNotAdmitted},
		"denied domain": {access: ProjectAccessConfig{AdmitManagedAccounts: true, BlockedDomains: []string{maDomain}}, want: ErrManagedAccountsNotAdmitted},
		"admin asks for an owner": {access: admitted(), mutate: func(f *membershipFixture, r *ManagedAccountRequest) {
			f.seedMember(mTestProject, mTestTenant, mAdminID, RoleAdmin)
			r.Role = RoleOwner
		}, want: ErrPermissionDenied},
		"mailer does not deliver": {access: admitted(), noMail: true, want: ErrEmailDeliveryDisabled},
		"missing tenant":          {access: admitted(), mutate: func(_ *membershipFixture, r *ManagedAccountRequest) { r.TenantID = " " }, want: ErrInvalidArgument},
		"bad role":                {access: admitted(), mutate: func(_ *membershipFixture, r *ManagedAccountRequest) { r.Role = "boss" }, want: ErrInvalidArgument},
		"bad delivery":            {access: admitted(), mutate: func(_ *membershipFixture, r *ManagedAccountRequest) { r.DeliveryEmail = "nope" }, want: ErrInvalidArgument},
		"bad name":                {access: admitted(), mutate: func(_ *membershipFixture, r *ManagedAccountRequest) { r.DisplayName = "a\u202eb" }, want: ErrInvalidArgument},
		"bad domain":              {access: admitted(), mutate: func(_ *membershipFixture, r *ManagedAccountRequest) { r.Domain = "nodot" }, want: ErrInvalidArgument},
		"not an admin": {access: admitted(), mutate: func(f *membershipFixture, _ *ManagedAccountRequest) {
			f.seedMember(mTestProject, mTestTenant, mAdminID, RoleMember)
		}, want: ErrPermissionDenied},
		"store refusal": {access: admitted(), store: func(ManagedSetup) (*ManagedSetupIssued, error) { return nil, ErrManagedAddressUnavailable }, want: ErrManagedAddressUnavailable},
		"store error":   {access: admitted(), store: func(ManagedSetup) (*ManagedSetupIssued, error) { return nil, storeErr }, want: storeErr},
	} {
		t.Run(name, func(t *testing.T) {
			store := &managedSetupsMock{create: tc.store}
			f, _ := managedMembershipFixture(store)
			if tc.cfg != nil {
				f.svc.cfg = tc.cfg
			}
			f.svc.mailerDelivers = !tc.noMail
			req := annRequest()
			if tc.mutate != nil {
				tc.mutate(f, &req)
			}
			_, err := f.svc.CreateManagedSetupInvitation(managedScope(tc.access), mAdminID, SessionSignIn{}, req, "", "")
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, f.mailer.count())
		})
	}
}

func TestCreateManagedSetupInvitation_NeedsTheStoreACallerAndAProject(t *testing.T) {
	f := newMembershipFixtureWith(true, &config.Config{ManagedAccountsEnabled: true})
	_, err := f.svc.CreateManagedSetupInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, annRequest(), "", "")
	require.ErrorIs(t, err, ErrUnimplemented)
	_, err = f.svc.CreateManagedSetupInvitation(managedScope(admitted()), "", SessionSignIn{}, annRequest(), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.CreateManagedSetupInvitation(context.Background(), mAdminID, SessionSignIn{}, annRequest(), "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestManagedCreateRefusalReason(t *testing.T) {
	for err, want := range map[error]string{
		ErrManagedByThisTenant:       "managed_by_this_tenant",
		ErrManagedAddressUnavailable: "address_unavailable",
		ErrManagedDomainUnverified:   "domain_unverified",
		ErrPermissionDenied:          "not_permitted",
		ErrInvitationResendTooSoon:   "limited",
		errors.New("boom"):           "store_error",
	} {
		require.Equal(t, want, managedCreateRefusalReason(err))
	}
}

func TestCreateTenantInvitation_RefusesTheTenantsManagedAddress(t *testing.T) {
	holdersErr := errors.New("db down")
	for name, tc := range map[string]struct {
		holders func(string, string, []string) (map[string]string, error)
		want    error
	}{
		"managed by this tenant": {func(_, _ string, a []string) (map[string]string, error) {
			return map[string]string{a[0]: ManagedAddressManagedByThis}, nil
		}, ErrManagedByThisTenant},
		"lookup fails": {func(string, string, []string) (map[string]string, error) { return nil, holdersErr }, holdersErr},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := managedMembershipFixture(&managedSetupsMock{holders: tc.holders})
			_, err := f.svc.CreateTenantInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant, maAddress, RoleMember)
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, f.mailer.count())
		})
	}
	f, _ := managedMembershipFixture(&managedSetupsMock{holders: func(_, _ string, a []string) (map[string]string, error) {
		return map[string]string{a[0]: ManagedAddressHeldOutsideTheTenant}, nil
	}})
	_, err := f.svc.CreateTenantInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant, maAddress, RoleMember)
	require.NoError(t, err, "an address held outside the tenant is invited as any other")
}

// Revoking a set-up link deletes its never-set-up account, audited, and
// announces nothing: the account was never announced as created.
func TestRevokeTenantInvitation_ManagedSetupDeletesWithoutAnnouncing(t *testing.T) {
	deleted := &User{ID: maUserID, Email: maAddress}
	var by string
	f, w := managedMembershipFixture(&managedSetupsMock{revoke: func(_, _, id, caller string) (*ManagedSetupRevoked, error) {
		by = caller
		return &ManagedSetupRevoked{Invitation: &TenantInvitation{ID: id, TenantID: mTestTenant, Status: InvitationStatusRevoked}, Changed: true, DeletedUser: deleted}, nil
	}})

	inv, err := f.svc.RevokeTenantInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant, "inv-ann", "", "")
	require.NoError(t, err)
	require.Equal(t, InvitationStatusRevoked, inv.Status)
	require.Equal(t, mAdminID, by, "the store judges the caller under its locks")
	require.Equal(t, 1, w.countByEventTypeActorTarget(string(audit.EventManagedAccountDeleted), mAdminID, maUserID))
	require.Equal(t, 1, w.countByEventType(string(audit.EventTenantInvitationRevoked)))
}

func TestRevokeTenantInvitation_ManagedPaths(t *testing.T) {
	storeErr := errors.New("db down")
	f, _ := managedMembershipFixture(&managedSetupsMock{revoke: func(string, string, string, string) (*ManagedSetupRevoked, error) {
		return nil, storeErr
	}})
	_, err := f.svc.RevokeTenantInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant, "inv-ann", "", "")
	require.ErrorIs(t, err, storeErr)

	f, _ = managedMembershipFixture(&managedSetupsMock{revoke: func(string, string, string, string) (*ManagedSetupRevoked, error) {
		return nil, ErrNotFound
	}})
	f.invitations.byID[f.invitations.key(mTestProject, "inv-1")] = &TenantInvitation{ID: "inv-1", ProjectID: mTestProject, TenantID: mTestTenant, Status: InvitationStatusPending}
	inv, err := f.svc.RevokeTenantInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant, "inv-1", "", "")
	require.NoError(t, err, "an ordinary invitation is revoked as before")
	require.Equal(t, InvitationStatusRevoked, inv.Status)

	reached := false
	f, _ = managedMembershipFixture(&managedSetupsMock{revoke: func(_, _, id, _ string) (*ManagedSetupRevoked, error) {
		reached = true
		return &ManagedSetupRevoked{Invitation: &TenantInvitation{ID: id, TenantID: mTestTenant, Status: InvitationStatusRevoked}, Changed: true}, nil
	}})
	f.svc.cfg.ManagedAccountsEnabled = false
	_, err = f.svc.RevokeTenantInvitation(managedScope(ProjectAccessConfig{}), mAdminID, SessionSignIn{}, mTestTenant, "inv-ann", "", "")
	require.NoError(t, err)
	require.True(t, reached, "a set-up link is revoked through the managed store whatever the switches say")
}

func TestListTenantMembers_MarksAccountKinds(t *testing.T) {
	f, _ := managedMembershipFixture(&managedSetupsMock{among: func(_, _ string, ids []string) (map[string]bool, error) {
		require.ElementsMatch(t, []string{mAdminID, maUserID}, ids)
		return map[string]bool{maUserID: true}, nil
	}})
	f.seedMember(mTestProject, mTestTenant, maUserID, RoleMember)
	members, err := f.svc.ListTenantMembers(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant)
	require.NoError(t, err)
	kinds := map[string]string{}
	for _, m := range members {
		kinds[m.UserID] = m.AccountKind
	}
	require.Equal(t, map[string]string{mAdminID: AccountKindPersonal, maUserID: AccountKindManaged}, kinds)

	storeErr := errors.New("db down")
	f, _ = managedMembershipFixture(&managedSetupsMock{among: func(string, string, []string) (map[string]bool, error) { return nil, storeErr }})
	_, err = f.svc.ListTenantMembers(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant)
	require.ErrorIs(t, err, storeErr)

	plain := newMembershipFixture()
	plain.seedAdmin(mTestProject, mTestTenant, mAdminID)
	members, err = plain.svc.ListTenantMembers(managedScope(admitted()), mAdminID, SessionSignIn{}, mTestTenant)
	require.NoError(t, err)
	require.Equal(t, AccountKindPersonal, members[0].AccountKind, "without the managed store every account is personal")
}

func TestAcceptTenantInvitation_ManagedSetupLink(t *testing.T) {
	f, _ := managedMembershipFixture(&managedSetupsMock{})
	raw := "set-up-token"
	f.invitations.byID[f.invitations.key(mTestProject, "inv-ann")] = &TenantInvitation{
		ID: "inv-ann", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
		Email: maAddress, Status: InvitationStatusAccepted, UserID: maUserID, DeliveryEmail: maDelivery, SetupEpoch: 1,
	}
	_, err := f.svc.AcceptTenantInvitation(managedScope(admitted()), maUserID, raw)
	require.ErrorIs(t, err, ErrNotFound, "an account with no membership left gets none back")

	f.seedMember(mTestProject, mTestTenant, maUserID, RoleMember)
	m, err := f.svc.AcceptTenantInvitation(managedScope(admitted()), maUserID, raw)
	require.NoError(t, err)
	require.Equal(t, maUserID, m.UserID)

	_, err = f.svc.AcceptTenantInvitation(managedScope(admitted()), mAdminID, raw)
	require.ErrorIs(t, err, ErrPermissionDenied)

	storeErr := errors.New("db down")
	f.memberships.getErr = storeErr
	_, err = f.svc.AcceptTenantInvitation(managedScope(admitted()), maUserID, raw)
	require.ErrorIs(t, err, storeErr)
}

func TestGetTenantInvitation_ManagedSetupLink(t *testing.T) {
	f, _ := managedMembershipFixture(&managedSetupsMock{})
	raw := "set-up-token"
	put := func(status string, epoch int64) {
		f.invitations.byID[f.invitations.key(mTestProject, "inv-ann")] = &TenantInvitation{
			ID: "inv-ann", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
			Email: maAddress, Status: status, UserID: maUserID, DeliveryEmail: maDelivery, SetupEpoch: epoch,
			ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
		}
	}
	f.users.set(mTestProject, &User{ID: maUserID, Email: maAddress, Name: "Ann Lee", Status: StatusInvited, ManagedByTenantID: mTestTenant, SetupEpoch: 2})

	put(InvitationStatusPending, 2)
	view, err := f.svc.GetTenantInvitation(managedScope(admitted()), raw)
	require.NoError(t, err)
	require.True(t, view.IsManagedSetup)
	require.Equal(t, maAddress, view.Email, "the address the link was delivered to is never answered")
	require.Equal(t, maAddress, view.AccountAddress)
	require.Equal(t, "Ann Lee", view.DisplayName)
	require.False(t, view.AccountExists)

	put(InvitationStatusPending, 1)
	view, err = f.svc.GetTenantInvitation(managedScope(admitted()), raw)
	require.NoError(t, err)
	require.True(t, view.IsManagedSetup)
	require.Empty(t, view.AccountAddress+view.DisplayName, "a replaced link describes no account")

	put(InvitationStatusPending, 2)
	f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, CreatedBy: mAdminID})
	view, err = f.svc.GetTenantInvitation(managedScope(admitted()), raw)
	require.NoError(t, err)
	require.Equal(t, maAddress, view.AccountAddress)
	require.Empty(t, view.DisplayName, "a self-service tenant's names are withheld")

	storeErr := errors.New("db down")
	f.tenants.getErr = storeErr
	_, err = f.svc.GetTenantInvitation(managedScope(admitted()), raw)
	require.ErrorIs(t, err, storeErr)
	f.tenants.getErr = nil

	f.users.getErr = storeErr
	_, err = f.svc.GetTenantInvitation(managedScope(admitted()), raw)
	require.ErrorIs(t, err, storeErr)
}

// The delivery address is held to the per-recipient cap across the project.
func TestCreateManagedSetupInvitation_CapsTheDeliveryAddress(t *testing.T) {
	var got ManagedSetup
	f, _ := managedMembershipFixture(&managedSetupsMock{create: func(s ManagedSetup) (*ManagedSetupIssued, error) {
		got = s
		return issuedFor(s, true, ""), nil
	}})
	_, err := f.svc.CreateManagedSetupInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, annRequest(), "", "")
	require.NoError(t, err)
	require.Equal(t, f.svc.config().TenantInvitationRecipientLimit(), got.MaxPerDeliveryEmail)
	require.Positive(t, got.MaxPerDeliveryEmail)
	require.Positive(t, got.Limits.ResendCooldownStartMs, "the cooldown the store applies to the delivery address too")
}

// A refusal is logged with its reason only: never the address, the username
// or the error text that may carry them.
func TestCreateManagedSetupInvitation_RefusalLogCarriesNoAddress(t *testing.T) {
	f, _ := managedMembershipFixture(&managedSetupsMock{})
	core, logs := observer.New(zap.InfoLevel)
	f.svc.logger = zap.New(core)
	req := annRequest()
	req.Username = "secret..name"
	_, err := f.svc.CreateManagedSetupInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, req, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	entries := logs.FilterMessage("managed_account_create_refused").All()
	require.Len(t, entries, 1)
	require.Equal(t, "invalid_argument", entries[0].ContextMap()["reason"])
	for k, v := range entries[0].ContextMap() {
		require.NotContains(t, fmt.Sprint(v), "secret", k)
		require.NotContains(t, fmt.Sprint(v), maDelivery, k)
	}
}

// A self-service tenant's set-up email greets by the address's local part,
// never by the name its admin typed, and names no tenant.
func TestCreateManagedSetupInvitation_SelfServiceGreetingIsTheLocalPart(t *testing.T) {
	f, _ := managedMembershipFixture(&managedSetupsMock{create: func(s ManagedSetup) (*ManagedSetupIssued, error) {
		return issuedFor(s, true, ""), nil
	}})
	access := ProjectAccessConfig{AdmitManagedAccounts: true, AdmitManagedAccountsSelfService: true}
	f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, CreatedBy: mAdminID, Name: "Typed Name Inc"})
	req := annRequest()
	req.DisplayName = "Admin Typed"
	_, err := f.svc.CreateManagedSetupInvitation(managedScope(access), mAdminID, SessionSignIn{}, req, "", "")
	require.NoError(t, err)
	text := f.mailer.last().Text
	require.Contains(t, text, "Hi ann,")
	require.NotContains(t, text, "Admin Typed")
	require.NotContains(t, text, "Typed Name Inc")

	g, _ := managedMembershipFixture(&managedSetupsMock{create: func(s ManagedSetup) (*ManagedSetupIssued, error) {
		return issuedFor(s, true, ""), nil
	}})
	g.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, Name: "Acme"})
	_, err = g.svc.CreateManagedSetupInvitation(managedScope(admitted()), mAdminID, SessionSignIn{}, annRequest(), "", "")
	require.NoError(t, err)
	require.Contains(t, g.mailer.last().Text, "Hi Ann Lee,", "an operator's tenant greets by the name it gave")
	require.Contains(t, g.mailer.last().Text, "Acme")
}

// countingTenants counts the tenant reads a request makes.
type countingTenants struct {
	*fakeTenantStore
	reads int
}

func (c *countingTenants) GetTenant(ctx context.Context, projectID, tenantID string) (*Tenant, error) {
	c.reads++
	return c.fakeTenantStore.GetTenant(ctx, projectID, tenantID)
}

func TestGetTenantInvitation_ManagedSetupReadsTheTenantOnce(t *testing.T) {
	f, _ := managedMembershipFixture(&managedSetupsMock{})
	counted := &countingTenants{fakeTenantStore: f.tenants}
	f.svc.tenants = counted
	raw := "set-up-token"
	f.invitations.byID[f.invitations.key(mTestProject, "inv-ann")] = &TenantInvitation{
		ID: "inv-ann", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
		Email: maAddress, Status: InvitationStatusPending, UserID: maUserID, DeliveryEmail: maDelivery, SetupEpoch: 1,
		ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
	}
	f.users.set(mTestProject, &User{ID: maUserID, Email: maAddress, Name: "Ann Lee", Status: StatusInvited, ManagedByTenantID: mTestTenant, SetupEpoch: 1})
	view, err := f.svc.GetTenantInvitation(managedScope(admitted()), raw)
	require.NoError(t, err)
	require.Equal(t, "Ann Lee", view.DisplayName)
	require.Equal(t, 1, counted.reads)
}

// Another account never accepts a set-up link as an ordinary invitation,
// pending or accepted: it is refused and gains no membership.
func TestAcceptTenantInvitation_ManagedSetupLinkRefusesAnotherAccount(t *testing.T) {
	for _, status := range []string{InvitationStatusPending, InvitationStatusAccepted} {
		f, _ := managedMembershipFixture(&managedSetupsMock{})
		raw := "set-up-token-" + status
		f.invitations.byID[f.invitations.key(mTestProject, "inv-ann")] = &TenantInvitation{
			ID: "inv-ann", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
			Email: maAddress, Status: status, UserID: maUserID, DeliveryEmail: maDelivery, SetupEpoch: 1,
			ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
		}
		const other = "user-someone-else"
		f.users.put(mTestProject, other, maAddress)
		_, err := f.svc.AcceptTenantInvitation(managedScope(admitted()), other, raw)
		require.ErrorIs(t, err, ErrPermissionDenied, status)
		m, err := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, other)
		require.NoError(t, err, status)
		require.Nil(t, m, "%s: the caller gains no membership", status)
		require.Equal(t, status, f.invitations.byID[f.invitations.key(mTestProject, "inv-ann")].Status, "%s: the link is unchanged", status)
	}
}
