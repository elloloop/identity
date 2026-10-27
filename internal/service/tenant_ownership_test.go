package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

const ownTenant = "t-own"

// ineligibleOwners puts into users, in project, one account of each kind
// that may not own a tenant, and returns their ids.
func ineligibleOwners(users *fakeUserDirectory, project string) []string {
	users.set(project, &User{ID: "anon", IsAnonymous: true, Status: StatusActive, EmailVerified: true})
	users.set(project, &User{ID: "agent", Kind: UserKindAgent, OwnerUserID: "someone", Status: StatusActive, EmailVerified: true})
	users.set(project, &User{ID: "merged", Email: "m@example.test", MergedIntoUserID: "someone", Status: StatusActive, EmailVerified: true})
	users.set(project, &User{ID: "inactive", Email: "i@example.test", Status: StatusDeactivated, EmailVerified: true})
	users.set(project, &User{ID: "unverified", Email: "u@example.test", Status: StatusActive})
	return []string{"anon", "agent", "merged", "inactive", "unverified"}
}

// ── TransferTenantOwnership ───────────────────────────────────────────────

// newOwnershipFixture is a self-service fixture holding a claimed tenant
// that ssOwnerID owns, which they created, and that ssOtherID belongs to
// through their email's domain, which the tenant verified.
func newOwnershipFixture() *selfServiceFixture {
	f := newSelfServiceFixture(&config.Config{})
	f.tenants.ensure(ssProject, ownTenant)
	f.members.verifyDomain(ssProject, ownTenant, "example.test")
	f.seed(ssOwnerID, MembershipSourceCreated, RoleOwner, MembershipStatusActive)
	f.seed(ssOtherID, MembershipSourceDomain, RoleMember, MembershipStatusActive)
	return f
}

func (f *selfServiceFixture) seed(userID, source, role, status string) {
	_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: userID,
		Source: source, Role: role, Status: status,
	})
}

func (f *selfServiceFixture) role(t *testing.T, userID string) string {
	t.Helper()
	m, err := f.members.GetMembership(context.Background(), ssProject, ownTenant, userID)
	require.NoError(t, err)
	require.NotNil(t, m, userID)
	return m.Role
}

func TestTransferTenantOwnership_HandsTheTenantOnAndAudits(t *testing.T) {
	f := newOwnershipFixture()

	out, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, " "+ownTenant+" ", " "+ssOtherID+" ", "203.0.113.7", "test-agent")
	require.NoError(t, err)

	assert.Equal(t, ssOtherID, out.Owner.UserID)
	assert.Equal(t, RoleOwner, out.Owner.Role)
	assert.Equal(t, MembershipSourceAdded, out.Owner.Source, "an owner no longer depends on the email's domain")
	assert.Equal(t, ssOwnerID, out.PreviousOwner.UserID)
	assert.Equal(t, RoleAdmin, out.PreviousOwner.Role, "the previous owner stays on as an admin")
	assert.Equal(t, MembershipSourceCreated, out.PreviousOwner.Source)
	assert.Equal(t, RoleOwner, f.role(t, ssOtherID))
	assert.Equal(t, RoleAdmin, f.role(t, ssOwnerID))

	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventTenantOwnershipTransferred), ssOwnerID, ssOtherID))
	assert.Equal(t, 1, f.audit.countByEventTypeAndDetail(string(audit.EventTenantOwnershipTransferred), "tenant_id", ownTenant))
	assert.Equal(t, 1, f.audit.countByEventTypeAndDetail(string(audit.EventTenantOwnershipTransferred), "project_id", ssProject))

	// The previous owner is an admin now, so they cannot hand it on again.
	_, err = f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantOwnershipTransferred)))
}

// Naming a co-owner leaves them the owner and the caller an admin: an owner
// steps down without removing themselves.
func TestTransferTenantOwnership_ToACoOwner(t *testing.T) {
	f := newOwnershipFixture()
	f.seed(ssOtherID, MembershipSourceInvited, RoleOwner, MembershipStatusActive)

	out, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	assert.Equal(t, RoleOwner, out.Owner.Role)
	assert.Equal(t, MembershipSourceInvited, out.Owner.Source, "a source other than the domain's is kept")
	assert.Equal(t, RoleAdmin, f.role(t, ssOwnerID))
}

func TestTransferTenantOwnership_OnlyAnActiveOwnerOfAGovernableTenant(t *testing.T) {
	for name, setup := range map[string]func(f *selfServiceFixture){
		"admin": func(f *selfServiceFixture) {
			f.seed(ssOwnerID, MembershipSourceAdded, RoleAdmin, MembershipStatusActive)
		},
		"member": func(f *selfServiceFixture) {
			f.seed(ssOwnerID, MembershipSourceAdded, RoleMember, MembershipStatusActive)
		},
		"inactive owner": func(f *selfServiceFixture) {
			f.seed(ssOwnerID, MembershipSourceAdded, RoleOwner, MembershipStatusInactive)
		},
		"not a member": func(f *selfServiceFixture) {
			delete(f.members.byKey, f.members.key(ssProject, ownTenant, ssOwnerID))
		},
		"suspended":      func(f *selfServiceFixture) { f.tenants.byID[ssProject+"/"+ownTenant].Status = TenantStatusSuspended },
		"unknown tenant": func(f *selfServiceFixture) { delete(f.tenants.byID, ssProject+"/"+ownTenant) },
	} {
		f := newOwnershipFixture()
		setup(f)
		_, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
		require.ErrorIs(t, err, ErrPermissionDenied, name)
		assert.Equal(t, RoleMember, f.role(t, ssOtherID), name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipTransferred)), name)
	}
}

func TestTransferTenantOwnership_RefusesBadRequests(t *testing.T) {
	f := newOwnershipFixture()
	ctx := withTenantsProject(false)

	_, err := f.svc.TransferTenantOwnership(ctx, "", ownTenant, ssOtherID, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.TransferTenantOwnership(context.Background(), ssOwnerID, ownTenant, ssOtherID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project in scope")

	for name, args := range map[string][2]string{
		"blank tenant": {" ", ssOtherID},
		"blank user":   {ownTenant, " "},
		"the caller":   {ownTenant, ssOwnerID},
	} {
		_, err := f.svc.TransferTenantOwnership(ctx, ssOwnerID, args[0], args[1], "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, name)
	}

	// The new owner must be an active member of the tenant.
	_, err = f.svc.TransferTenantOwnership(ctx, ssOwnerID, ownTenant, "user-stranger", "", "")
	require.ErrorIs(t, err, ErrNotFound)
	f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusPending)
	_, err = f.svc.TransferTenantOwnership(ctx, ssOwnerID, ownTenant, ssOtherID, "", "")
	require.ErrorIs(t, err, ErrNotFound, "a pending membership is not an active one")

	assert.Equal(t, RoleOwner, f.role(t, ssOwnerID))
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipTransferred)))
}

// A member through their email's domain is one only while the tenant
// verifies that domain, so ownership cannot pass to someone the domain no
// longer makes a member.
func TestTransferTenantOwnership_DomainMemberMustStillBelong(t *testing.T) {
	for name, leave := range map[string]func(f *selfServiceFixture){
		"domain no longer verified": func(f *selfServiceFixture) {
			delete(f.members.verified[ssProject+"/"+ownTenant], "example.test")
		},
		"email on another domain": func(f *selfServiceFixture) {
			f.users.byID[ssProject+"/"+ssOtherID].Email = "other@elsewhere.test"
		},
	} {
		f := newOwnershipFixture()
		leave(f)
		_, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
		require.ErrorIs(t, err, ErrNotFound, name)
		assert.Equal(t, RoleMember, f.role(t, ssOtherID), name)
		assert.Equal(t, RoleOwner, f.role(t, ssOwnerID), name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipTransferred)), name)
	}

	// An invited member's membership does not depend on the domain.
	f := newOwnershipFixture()
	f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusActive)
	delete(f.members.verified[ssProject+"/"+ownTenant], "example.test")
	_, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
}

// An owner sends the tenant's invitations and must be able to sign in, so the
// ownership goes only to an account that could have created the tenant.
func TestTransferTenantOwnership_RefusesAccountsThatCannotOwn(t *testing.T) {
	f := newOwnershipFixture()
	ids := append(ineligibleOwners(f.users, ssProject), "user-without-account")
	for _, id := range ids {
		f.seed(id, MembershipSourceAdded, RoleMember, MembershipStatusActive)
		_, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, id, "", "")
		require.ErrorIs(t, err, ErrIneligibleTenantOwner, id)
		assert.Equal(t, RoleMember, f.role(t, id), id)
	}
	assert.Equal(t, RoleOwner, f.role(t, ssOwnerID))
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipTransferred)))
}

func TestTransferTenantOwnership_StoreErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, fail := range map[string]func(f *selfServiceFixture){
		"membership read": func(f *selfServiceFixture) { f.members.getErr = boom },
		"user read":       func(f *selfServiceFixture) { f.users.getErr = boom },
		"transfer":        func(f *selfServiceFixture) { f.members.transferErr = boom },
	} {
		f := newOwnershipFixture()
		fail(f)
		_, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
		require.ErrorIs(t, err, boom, name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipTransferred)), name)
	}
}

func TestTransferTenantOwnership_WithoutAuditStillTransfers(t *testing.T) {
	f := newOwnershipFixture()
	f.svc.WithAudit(nil)

	_, err := f.svc.TransferTenantOwnership(withTenantsProject(false), ssOwnerID, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	assert.Equal(t, RoleOwner, f.role(t, ssOtherID))
}

// ── AdminRecoverTenantOwnership ───────────────────────────────────────────

// newRecoveryFixture is an operator fixture holding claimed tenant t-1 of
// proj, whose only owner, "gone", was deactivated, and whose member "heir"
// can own it.
func newRecoveryFixture() *adminFixture {
	f := newAdminFixture(testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: TenantStatusClaimed})
	f.users.set("proj", &User{ID: "gone", Email: "g@example.test", Status: StatusDeactivated, EmailVerified: true})
	f.users.set("proj", &User{ID: "heir", Email: "h@example.test", Status: StatusActive, EmailVerified: true})
	f.seedMembership("gone", MembershipSourceCreated, RoleOwner, MembershipStatusActive)
	f.seedMembership("heir", MembershipSourceDomain, RoleMember, MembershipStatusActive)
	return f
}

func (f *adminFixture) seedMembership(userID, source, role, status string) {
	_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: "proj", TenantID: "t-1", UserID: userID, Source: source, Role: role, Status: status,
	})
}

func (f *adminFixture) recover(userID, reason string) (*TenantMembership, error) {
	return f.svc.AdminRecoverTenantOwnership(context.Background(), testAdminSecret, "proj", "t-1", userID, reason, testOperatorIP, testOperatorUA)
}

func TestAdminRecoverTenantOwnership_Gated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	disabled := newAdminFixture("")
	_, err := disabled.svc.AdminRecoverTenantOwnership(ctx, "anything", "proj", "t-1", "heir", "why", "", "")
	require.ErrorIs(t, err, ErrUnimplemented)

	f := newRecoveryFixture()
	for _, presented := range []string{"", "wrong", testAdminSecret + "x"} {
		_, err := f.svc.AdminRecoverTenantOwnership(ctx, presented, "proj", "t-1", "heir", "why", "", "")
		require.ErrorIs(t, err, ErrPermissionDenied, presented)
	}

	m, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
	assert.Equal(t, RoleMember, m.Role)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)))
}

func TestAdminRecoverTenantOwnership_AppointsAndAudits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecoveryFixture()

	got, err := f.svc.AdminRecoverTenantOwnership(ctx, testAdminSecret, " proj ", " t-1 ", " heir ", "  owner left the company\n", testOperatorIP, testOperatorUA)
	require.NoError(t, err)
	assert.Equal(t, "heir", got.UserID)
	assert.Equal(t, RoleOwner, got.Role)
	assert.Equal(t, MembershipStatusActive, got.Status)
	assert.Equal(t, MembershipSourceAdded, got.Source, "the ownership no longer depends on the email's domain")
	stored, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
	assert.Equal(t, RoleOwner, stored.Role)

	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventTenantOwnershipRecovered), "", "heir"))
	details := f.audit.detailsOf(string(audit.EventTenantOwnershipRecovered))
	require.Len(t, details, 1)
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": "t-1", "reason": "owner left the company"}, details[0])
	assert.Equal(t, [][2]string{{testOperatorIP, testOperatorUA}}, f.audit.clientsOf(string(audit.EventTenantOwnershipRecovered)))

	// Asking again finds heir the owner: the same answer, recorded once.
	again, err := f.recover("heir", "retry")
	require.NoError(t, err)
	assert.Equal(t, got, again)
	assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)))

	// heir can sign in, so nobody else may be appointed now.
	f.users.set("proj", &User{ID: "late", Email: "l@example.test", Status: StatusActive, EmailVerified: true})
	_, err = f.recover("late", "why")
	require.ErrorIs(t, err, ErrTenantStillGoverned)
}

// Each way an owner or admin stops being one who can sign in leaves the
// tenant recoverable, and an account outside the tenant may be appointed.
func TestAdminRecoverTenantOwnership_WhenNobodyCanGovern(t *testing.T) {
	t.Parallel()
	for name, gone := range map[string]func(f *adminFixture){
		"owner deleted": func(f *adminFixture) {
			// Deleting an account deletes its memberships with it.
			delete(f.members.byKey, f.members.key("proj", "t-1", "gone"))
			delete(f.users.byID, "proj/gone")
		},
		"account missing":       func(f *adminFixture) { delete(f.users.byID, "proj/gone") },
		"owner merged away":     func(f *adminFixture) { f.users.byID["proj/gone"].MergedIntoUserID = "someone" },
		"owner never signed up": func(f *adminFixture) { f.users.byID["proj/gone"].Status = StatusInvited },
		"membership inactive": func(f *adminFixture) {
			f.seedMembership("gone", MembershipSourceCreated, RoleOwner, MembershipStatusInactive)
		},
		"tenant suspended": func(f *adminFixture) {
			f.tenants.byID["proj/t-1"].Status = TenantStatusSuspended
		},
		"admin deactivated": func(f *adminFixture) {
			f.users.set("proj", &User{ID: "old-admin", Email: "a@example.test", Status: StatusDeactivated, EmailVerified: true})
			f.seedMembership("old-admin", MembershipSourceInvited, RoleAdmin, MembershipStatusActive)
		},
		"admin membership inactive": func(f *adminFixture) {
			f.users.set("proj", &User{ID: "old-admin", Email: "a@example.test", Status: StatusActive, EmailVerified: true})
			f.seedMembership("old-admin", MembershipSourceInvited, RoleAdmin, MembershipStatusInactive)
		},
		"admin an agent": func(f *adminFixture) {
			f.users.set("proj", &User{ID: "bot", Kind: UserKindAgent, OwnerUserID: "gone", Status: StatusActive})
			f.seedMembership("bot", MembershipSourceAdded, RoleAdmin, MembershipStatusActive)
		},
	} {
		f := newRecoveryFixture()
		gone(f)
		f.users.set("proj", &User{ID: "outsider", Email: "o@example.test", Status: StatusActive, EmailVerified: true})

		got, err := f.recover("outsider", "why")
		require.NoError(t, err, name)
		assert.Equal(t, RoleOwner, got.Role, name)
		assert.Equal(t, MembershipSourceAdded, got.Source, name)
		assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)), name)
	}
}

// While an owner or an admin can still sign in, they govern the tenant: an
// owner transfers it, an admin invites a new owner. An account pending
// deletion can sign in, which cancels the deletion, so it counts; so does
// an owner whose email is unverified.
func TestAdminRecoverTenantOwnership_RefusesWhileGoverned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, govern := range map[string]struct {
		role string
		user User
	}{
		"active owner":           {role: RoleOwner, user: User{Status: StatusActive, EmailVerified: true}},
		"unverified owner":       {role: RoleOwner, user: User{Status: StatusActive}},
		"owner pending deletion": {role: RoleOwner, user: User{Status: StatusPendingDeletion, EmailVerified: true}},
		"active admin":           {role: RoleAdmin, user: User{Status: StatusActive, EmailVerified: true}},
		"admin pending deletion": {role: RoleAdmin, user: User{Status: StatusPendingDeletion}},
	} {
		f := newRecoveryFixture()
		here := govern.user
		here.ID, here.Email = "here", "here@example.test"
		f.users.set("proj", &here)
		f.seedMembership("here", MembershipSourceInvited, govern.role, MembershipStatusActive)

		_, err := f.recover("heir", "why")
		require.ErrorIs(t, err, ErrTenantStillGoverned, name)
		m, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
		assert.Equal(t, RoleMember, m.Role, name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)), name)
	}
}

// Naming an owner who can sign in returns their membership unchanged, even
// one recovery would not appoint now (here, an unverified email), so an
// operator's retry gets the answer the first call gave; nothing is recorded.
func TestAdminRecoverTenantOwnership_NamingAnOwnerChangesNothing(t *testing.T) {
	t.Parallel()
	f := newRecoveryFixture()
	f.users.set("proj", &User{ID: "here", Email: "here@example.test", Status: StatusPendingDeletion})
	f.seedMembership("here", MembershipSourceInvited, RoleOwner, MembershipStatusActive)

	got, err := f.recover("here", "why")
	require.NoError(t, err)
	assert.Equal(t, RoleOwner, got.Role)
	assert.Equal(t, MembershipSourceInvited, got.Source)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)))

	// An admin named is not an owner: the tenant is governed, so refused.
	f.users.set("proj", &User{ID: "admin", Email: "a@example.test", Status: StatusActive, EmailVerified: true})
	f.seedMembership("admin", MembershipSourceInvited, RoleAdmin, MembershipStatusActive)
	_, err = f.recover("admin", "why")
	require.ErrorIs(t, err, ErrTenantStillGoverned)
}

// The appointee's membership, whatever its state, becomes an active owner
// one, and keeps a source other than the domain's.
func TestAdminRecoverTenantOwnership_RaisesTheAppointeesMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, seed := range map[string]struct{ source, role, status string }{
		"inactive member":   {MembershipSourceInvited, RoleMember, MembershipStatusInactive},
		"inactive owner":    {MembershipSourceCreated, RoleOwner, MembershipStatusInactive},
		"pending member":    {MembershipSourceInvited, RoleMember, MembershipStatusPending},
		"active member":     {MembershipSourceInvited, RoleMember, MembershipStatusActive},
		"deactivated admin": {MembershipSourceAdded, RoleAdmin, MembershipStatusInactive},
	} {
		f := newRecoveryFixture()
		f.seedMembership("heir", seed.source, seed.role, seed.status)

		got, err := f.recover("heir", "why")
		require.NoError(t, err, name)
		assert.Equal(t, RoleOwner, got.Role, name)
		assert.Equal(t, MembershipStatusActive, got.Status, name)
		assert.Equal(t, seed.source, got.Source, name)
		stored, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
		assert.Equal(t, got, stored, name)
		assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)), name)
	}
}

// Two recoveries naming the same account can both pass the check; the one
// whose grant changes nothing records nothing, so the trail holds one entry
// per appointment.
func TestAdminRecoverTenantOwnership_RecordsOnlyAChange(t *testing.T) {
	t.Parallel()
	f := newRecoveryFixture()
	racing := &grantBetweenStore{fakeMembershipStore: f.members, grant: &TenantMembership{
		ProjectID: "proj", TenantID: "t-1", UserID: "heir", Source: MembershipSourceAdded, Role: RoleOwner,
	}}
	f.svc = NewControlPlaneAdminService(testAdminSecret, false, testAdminSecretsKey(), f.projects, f.tenants, racing, f.users, f.policies, f.admins, f.dns,
		audit.NewLogger(f.audit, "test-project", zap.NewNop()), zap.NewNop())

	got, err := f.recover("heir", "why")
	require.NoError(t, err)
	assert.Equal(t, RoleOwner, got.Role)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)))
}

// grantBetweenStore grants its membership right after the first tenant
// listing, standing in for a recovery that commits while another is between
// its check and its grant.
type grantBetweenStore struct {
	*fakeMembershipStore
	grant *TenantMembership
}

func (s *grantBetweenStore) ListMembershipsForTenant(ctx context.Context, projectID, tenantID string) ([]*TenantMembership, error) {
	out, err := s.fakeMembershipStore.ListMembershipsForTenant(ctx, projectID, tenantID)
	if s.grant != nil {
		grant := s.grant
		s.grant = nil
		if _, _, err := s.GrantMembership(ctx, grant); err != nil {
			return nil, err
		}
	}
	return out, err
}

func TestAdminRecoverTenantOwnership_RefusesBadArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecoveryFixture()
	f.tenants.put(&Tenant{ID: "t-latent", ProjectID: "proj", Status: TenantStatusLatent})
	call := func(projectID, tenantID, userID, reason string) error {
		_, err := f.svc.AdminRecoverTenantOwnership(ctx, testAdminSecret, projectID, tenantID, userID, reason, "", "")
		return err
	}

	for name, err := range map[string]error{
		"blank project":  call(" ", "t-1", "heir", "why"),
		"blank tenant":   call("proj", " ", "heir", "why"),
		"blank user":     call("proj", "t-1", " ", "why"),
		"blank reason":   call("proj", "t-1", "heir", " "),
		"long reason":    call("proj", "t-1", "heir", strings.Repeat("a", operatorReasonMaxRunes+1)),
		"control reason": call("proj", "t-1", "heir", "why\x00"),
	} {
		require.ErrorIs(t, err, ErrInvalidArgument, name)
	}
	require.ErrorIs(t, call("proj", "t-missing", "heir", "why"), ErrNotFound)
	require.ErrorIs(t, call("proj-2", "t-1", "heir", "why"), ErrNotFound, "another project's tenant")
	require.ErrorIs(t, call("proj", "t-latent", "heir", "why"), ErrTenantStatusConflict)
	require.ErrorIs(t, call("proj", "t-1", "user-missing", "why"), ErrNotFound)
	f.users.set("proj-2", &User{ID: "elsewhere", Email: "e@example.test", Status: StatusActive, EmailVerified: true})
	require.ErrorIs(t, call("proj", "t-1", "elsewhere", "why"), ErrNotFound, "an account of another project")
	for _, id := range ineligibleOwners(f.users, "proj") {
		require.ErrorIs(t, call("proj", "t-1", id, "why"), ErrIneligibleTenantOwner, id)
	}
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)))
}

func TestAdminRecoverTenantOwnership_StoreErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	for name, fail := range map[string]func(f *adminFixture){
		"tenant read":     func(f *adminFixture) { f.tenants.getErr = boom },
		"user read":       func(f *adminFixture) { f.users.getErr = boom },
		"membership list": func(f *adminFixture) { f.members.listErr = boom },
		"grant":           func(f *adminFixture) { f.members.upsertErr = boom },
	} {
		f := newRecoveryFixture()
		fail(f)
		_, err := f.recover("heir", "why")
		require.ErrorIs(t, err, boom, name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)), name)
	}
}

// An owner's account the directory cannot read stops the recovery: whether
// they can sign in is unknown.
func TestAdminRecoverTenantOwnership_OwnerLookupError(t *testing.T) {
	t.Parallel()
	f := newRecoveryFixture()
	boom := errors.New("boom")
	f.svc = NewControlPlaneAdminService(testAdminSecret, false, testAdminSecretsKey(), f.projects, f.tenants, f.members, failingUserDirectory{fakeUserDirectory: f.users, userID: "gone", err: boom}, f.policies, f.admins, f.dns, nil, zap.NewNop())

	_, err := f.recover("heir", "why")
	require.ErrorIs(t, err, boom)
}

// failingUserDirectory is a user directory that fails the lookup of one user.
type failingUserDirectory struct {
	*fakeUserDirectory
	userID string
	err    error
}

func (d failingUserDirectory) GetUserInProject(ctx context.Context, projectID, userID string) (*User, error) {
	if userID == d.userID {
		return nil, d.err
	}
	return d.fakeUserDirectory.GetUserInProject(ctx, projectID, userID)
}
