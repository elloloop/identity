package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/audit"
)

// ── SetTenantMemberRole ──────────────────────────────────────────────────

const roleChangedEvent = string(audit.EventTenantMemberRoleChanged)

// roleFixture is an ownership fixture, ssOwnerID owning ownTenant and
// ssOtherID a member through their email's verified domain, whose log lines
// are recorded.
type roleFixture struct {
	*selfServiceFixture
	logs *observer.ObservedLogs
}

func newRoleFixture() *roleFixture {
	f := newOwnershipFixture()
	logger, logs := observedLogger()
	f.svc.logger = logger
	return &roleFixture{selfServiceFixture: f, logs: logs}
}

// person gives userID an active, verified account and an invited membership
// of ownTenant with role and status.
func (f *roleFixture) person(userID, role, status string) {
	f.users.set(ssProject, &User{ID: userID, Email: userID + "@example.test", Status: StatusActive, EmailVerified: true})
	f.seed(userID, MembershipSourceInvited, role, status)
}

func (f *roleFixture) setRole(callerID, targetID, role string) (*TenantMembership, error) {
	return f.svc.SetTenantMemberRole(withTenantsProject(false), callerID, SessionSignIn{}, ownTenant, targetID, role, "", "")
}

func (f *roleFixture) membership(t *testing.T, userID string) *TenantMembership {
	t.Helper()
	m, err := f.members.GetMembership(context.Background(), ssProject, ownTenant, userID)
	require.NoError(t, err)
	require.NotNil(t, m, userID)
	return m
}

// requireRefused asserts the one refusal line the calls since the last
// check logged names caller, target and reason, and clears the log.
func (f *roleFixture) requireRefused(t *testing.T, callerID, targetID, reason string) {
	t.Helper()
	requireOneLogLine(t, f.logs, "tenant_member_role_change_refused", map[string]any{
		"project_id": ssProject, "tenant_id": ownTenant, "user_id": targetID, "caller_id": callerID, "reason": reason,
	})
	requireNoLine(t, f.logs, "tenant_member_role_changed", "tenant_member_role_unchanged")
	f.logs.TakeAll()
}

// An owner promotes a member to admin and the new admin governs at once; the
// owner then makes them a member again and they no longer do. Each change is
// audited with the role it replaced and logged with both roles, and no line
// carries an address.
func TestSetTenantMemberRole_PromotesAndDemotesAndAudits(t *testing.T) {
	f := newRoleFixture()
	ctx := withTenantsProject(false)

	_, err := f.svc.ListTenantMembers(ctx, ssOtherID, SessionSignIn{}, ownTenant)
	require.ErrorIs(t, err, ErrPermissionDenied, "a member does not govern")

	got, err := f.svc.SetTenantMemberRole(ctx, ssOwnerID, SessionSignIn{}, " "+ownTenant+" ", " "+ssOtherID+" ", " Admin ", "203.0.113.7", "test-agent")
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, got.Role)
	assert.Equal(t, MembershipStatusActive, got.Status)
	assert.Equal(t, MembershipSourceAdded, got.Source, "an admin no longer depends on the email's domain")
	assert.Equal(t, got, f.membership(t, ssOtherID))
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(roleChangedEvent, ssOwnerID, ssOtherID))
	assert.Equal(t, []map[string]any{{
		"project_id": ssProject, "tenant_id": ownTenant,
		"role": RoleAdmin, "previous_role": RoleMember, "source": MembershipSourceAdded, "status": MembershipStatusActive,
	}}, f.audit.detailsOf(roleChangedEvent))
	assert.Equal(t, [][2]string{{"203.0.113.7", "test-agent"}}, f.audit.clientsOf(roleChangedEvent))
	requireOneLogLine(t, f.logs, "tenant_member_role_changed", map[string]any{
		"project_id": ssProject, "tenant_id": ownTenant, "user_id": ssOtherID, "caller_id": ssOwnerID,
		"from_role": RoleMember, "to_role": RoleAdmin, "status": MembershipStatusActive,
	})

	members, err := f.svc.ListTenantMembers(ctx, ssOtherID, SessionSignIn{}, ownTenant)
	require.NoError(t, err, "the promoted admin governs at once")
	assert.Len(t, members, 2)
	mine, err := f.svc.ListMyTenants(ctx, ssOtherID, SessionSignIn{})
	require.NoError(t, err)
	require.Len(t, mine, 1)
	assert.Equal(t, RoleAdmin, mine[0].Role)

	got, err = f.setRole(ssOwnerID, ssOtherID, RoleMember)
	require.NoError(t, err)
	assert.Equal(t, RoleMember, got.Role)
	assert.Equal(t, MembershipSourceAdded, got.Source, "a demotion keeps the source")
	assert.Equal(t, 2, f.audit.countByEventTypeActorTarget(roleChangedEvent, ssOwnerID, ssOtherID))
	assert.Equal(t, RoleAdmin, f.audit.detailsOf(roleChangedEvent)[1]["previous_role"])
	assert.Equal(t, 2, f.logs.FilterMessage("tenant_member_role_changed").Len())
	_, err = f.svc.ListTenantMembers(ctx, ssOtherID, SessionSignIn{}, ownTenant)
	require.ErrorIs(t, err, ErrPermissionDenied, "the demoted member no longer governs")
	requireNothingPersonal(t, f.logs, "owner@example.test", "other@example.test")
}

// An admin sets roles as an owner does, their own included, so an admin can
// step down while someone else governs.
func TestSetTenantMemberRole_AnAdminMaySetRolesAndStepDown(t *testing.T) {
	f := newRoleFixture()
	f.person("user-admin", RoleAdmin, MembershipStatusActive)

	got, err := f.setRole("user-admin", ssOtherID, RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, got.Role)
	got, err = f.setRole("user-admin", "user-admin", RoleMember)
	require.NoError(t, err)
	assert.Equal(t, RoleMember, got.Role)
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(roleChangedEvent, "user-admin", "user-admin"))
}

// Setting the role a member holds returns the membership as it is, records
// nothing, and logs it unchanged; so does naming an admin who cannot be made
// one now, since nothing is made.
func TestSetTenantMemberRole_SettingTheRoleHeldChangesNothing(t *testing.T) {
	f := newRoleFixture()
	before := f.membership(t, ssOtherID)

	got, err := f.setRole(ssOwnerID, ssOtherID, RoleMember)
	require.NoError(t, err)
	assert.Equal(t, before, got)
	requireOneLogLine(t, f.logs, "tenant_member_role_unchanged", map[string]any{
		"project_id": ssProject, "tenant_id": ownTenant, "user_id": ssOtherID, "caller_id": ssOwnerID,
		"to_role": RoleMember, "status": MembershipStatusActive,
	})

	f.users.set(ssProject, &User{ID: "bot", Kind: UserKindAgent, OwnerUserID: ssOwnerID, Status: StatusActive})
	f.seed("bot", MembershipSourceAdded, RoleAdmin, MembershipStatusActive)
	got, err = f.setRole(ssOwnerID, "bot", RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, got.Role)
	assert.Zero(t, f.audit.countByEventType(roleChangedEvent))
	requireNoLine(t, f.logs, "tenant_member_role_changed", "tenant_member_role_change_refused")
}

// Only an active owner or admin of a tenant that may be governed sets a role;
// anyone else is refused and the member keeps theirs.
func TestSetTenantMemberRole_OnlyAnActiveOwnerOrAdminOfAGovernableTenant(t *testing.T) {
	for name, setup := range map[string]func(f *roleFixture) string{
		"plain member": func(f *roleFixture) string {
			f.person("user-member", RoleMember, MembershipStatusActive)
			return "user-member"
		},
		"non-member": func(*roleFixture) string { return "user-stranger" },
		"suspended admin": func(f *roleFixture) string {
			f.person("user-admin", RoleAdmin, MembershipStatusSuspended)
			return "user-admin"
		},
		"inactive owner": func(f *roleFixture) string {
			f.person("user-co-owner", RoleOwner, MembershipStatusInactive)
			return "user-co-owner"
		},
		"owner of a suspended tenant": func(f *roleFixture) string {
			f.tenants.byID[ssProject+"/"+ownTenant].Status = TenantStatusSuspended
			return ssOwnerID
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture()
			caller := setup(f)

			_, err := f.setRole(caller, ssOtherID, RoleAdmin)
			require.ErrorIs(t, err, ErrPermissionDenied)
			assert.Equal(t, RoleMember, f.membership(t, ssOtherID).Role)
			assert.Zero(t, f.audit.countByEventType(roleChangedEvent))
			f.requireRefused(t, caller, ssOtherID, "not_permitted")
		})
	}
}

// The caller's authority is checked again where the change is written, so
// an admin suspended or made a member while the call is in flight changes
// nothing.
func TestSetTenantMemberRole_TheCallerMustStillGovernWhereItWrites(t *testing.T) {
	for name, lose := range map[string]func(m *TenantMembership){
		"suspended":        func(m *TenantMembership) { m.Status = MembershipStatusSuspended },
		"made member":      func(m *TenantMembership) { m.Role = RoleMember },
		"membership ended": func(m *TenantMembership) { m.Status = MembershipStatusInactive },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture()
			f.person("user-admin", RoleAdmin, MembershipStatusActive)
			f.members.onSetRole = func() { lose(f.members.byKey[f.members.key(ssProject, ownTenant, "user-admin")]) }

			_, err := f.setRole("user-admin", ssOtherID, RoleAdmin)
			require.ErrorIs(t, err, ErrPermissionDenied)
			assert.Equal(t, RoleMember, f.membership(t, ssOtherID).Role)
			assert.Zero(t, f.audit.countByEventType(roleChangedEvent))
			f.requireRefused(t, "user-admin", ssOtherID, "not_permitted")
		})
	}
}

// An owner's role changes only by a transfer, whoever asks, the owner
// included; "owner" itself is not a role this call sets.
func TestSetTenantMemberRole_RefusesAnOwnersRole(t *testing.T) {
	f := newRoleFixture()
	f.person("user-co-owner", RoleOwner, MembershipStatusActive)
	f.person("user-admin", RoleAdmin, MembershipStatusActive)

	for _, tc := range []struct{ caller, target, role string }{
		{ssOwnerID, "user-co-owner", RoleAdmin},
		{ssOwnerID, ssOwnerID, RoleMember},
		{"user-admin", ssOwnerID, RoleAdmin},
	} {
		_, err := f.setRole(tc.caller, tc.target, tc.role)
		require.ErrorIs(t, err, ErrMemberIsOwner, "%+v", tc)
		assert.Equal(t, RoleOwner, f.membership(t, tc.target).Role, "%+v", tc)
		f.requireRefused(t, tc.caller, tc.target, "member_is_owner")
	}

	_, err := f.setRole(ssOwnerID, ssOtherID, RoleOwner)
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "TransferTenantOwnership")
	f.requireRefused(t, ssOwnerID, ssOtherID, "invalid_argument")
	assert.Equal(t, RoleMember, f.membership(t, ssOtherID).Role)
	assert.Zero(t, f.audit.countByEventType(roleChangedEvent))
}

// A tenant keeps an active owner or admin: the last admin of a tenant with no
// active owner cannot step down, while one of two admins, or an admin beside
// an owner, can.
func TestSetTenantMemberRole_KeepsAnActiveOwnerOrAdmin(t *testing.T) {
	f := newRoleFixture()
	f.seed(ssOwnerID, MembershipSourceCreated, RoleOwner, MembershipStatusSuspended)
	f.person("user-admin", RoleAdmin, MembershipStatusActive)

	_, err := f.setRole("user-admin", "user-admin", RoleMember)
	require.ErrorIs(t, err, ErrLastTenantGovernor, "a suspended owner does not govern")
	assert.Equal(t, RoleAdmin, f.membership(t, "user-admin").Role)
	f.requireRefused(t, "user-admin", "user-admin", "last_governor")

	f.person("user-admin-2", RoleAdmin, MembershipStatusActive)
	_, err = f.setRole("user-admin", "user-admin", RoleMember)
	require.NoError(t, err, "another admin governs")
	_, err = f.setRole("user-admin-2", "user-admin-2", RoleMember)
	require.ErrorIs(t, err, ErrLastTenantGovernor, "now the last one")
	f.logs.TakeAll()

	f.seed(ssOwnerID, MembershipSourceCreated, RoleOwner, MembershipStatusActive)
	_, err = f.setRole("user-admin-2", "user-admin-2", RoleMember)
	require.NoError(t, err, "an active owner governs")
	assert.Equal(t, 2, f.audit.countByEventType(roleChangedEvent))
}

// An admin sends the tenant's invitations, so only an account that may own a
// tenant is made one; any other is refused with why, and stays a member. An
// admin who could not be made one now may still be made a member.
func TestSetTenantMemberRole_PromotesOnlyAnAccountThatMayBeAnAdmin(t *testing.T) {
	f := newRoleFixture()
	for _, id := range ineligibleOwners(f.users, ssProject) {
		f.seed(id, MembershipSourceAdded, RoleMember, MembershipStatusActive)
		_, err := f.setRole(ssOwnerID, id, RoleAdmin)
		require.ErrorIs(t, err, ErrIneligibleTenantAdmin, id)
		assert.Equal(t, RoleMember, f.membership(t, id).Role, id)
		f.requireRefused(t, ssOwnerID, id, "ineligible_admin")
	}
	_, err := f.setRole(ssOwnerID, "agent", RoleAdmin)
	assert.ErrorContains(t, err, "not an active person's")
	_, err = f.setRole(ssOwnerID, "unverified", RoleAdmin)
	assert.ErrorContains(t, err, "email is unverified")
	assert.Zero(t, f.audit.countByEventType(roleChangedEvent))

	f.seed("agent", MembershipSourceAdded, RoleAdmin, MembershipStatusActive)
	got, err := f.setRole(ssOwnerID, "agent", RoleMember)
	require.NoError(t, err)
	assert.Equal(t, RoleMember, got.Role)
}

// A suspended member keeps the suspension with the new role, and comes back
// with it when restored.
func TestSetTenantMemberRole_ASuspendedMemberStaysSuspended(t *testing.T) {
	f := newRoleFixture()
	ctx := withTenantsProject(false)
	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)

	got, err := f.setRole(ssOwnerID, ssOtherID, RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, got.Role)
	assert.Equal(t, MembershipStatusSuspended, got.Status)
	assert.Equal(t, MembershipStatusSuspended, f.audit.detailsOf(roleChangedEvent)[0]["status"])
	_, err = f.svc.ListTenantMembers(ctx, ssOtherID, SessionSignIn{}, ownTenant)
	require.ErrorIs(t, err, ErrPermissionDenied, "a suspended admin does not govern")

	restored, err := f.svc.RestoreTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, restored.Role)
	assert.Equal(t, MembershipStatusActive, restored.Status)
}

// A user_id that is not an active or suspended member is NotFound, as is a
// member only through their email's domain once the tenant no longer
// verifies it; an invited member does not depend on the domain.
func TestSetTenantMemberRole_NotAMemberIsNotFound(t *testing.T) {
	for name, leave := range map[string]func(f *roleFixture){
		"no membership": func(f *roleFixture) { delete(f.members.byKey, f.members.key(ssProject, ownTenant, ssOtherID)) },
		"no account":    func(f *roleFixture) { delete(f.users.byID, ssProject+"/"+ssOtherID) },
		"inactive":      func(f *roleFixture) { f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusInactive) },
		"pending":       func(f *roleFixture) { f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusPending) },
		"domain no longer verified": func(f *roleFixture) {
			delete(f.members.verified[ssProject+"/"+ownTenant], "example.test")
		},
		"email on another domain": func(f *roleFixture) {
			f.users.byID[ssProject+"/"+ssOtherID].Email = "other@elsewhere.test"
		},
		"email unverified": func(f *roleFixture) { f.users.byID[ssProject+"/"+ssOtherID].EmailVerified = false },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture()
			leave(f)
			for _, role := range []string{RoleAdmin, RoleMember} {
				_, err := f.setRole(ssOwnerID, ssOtherID, role)
				require.ErrorIs(t, err, ErrNotFound, role)
				f.requireRefused(t, ssOwnerID, ssOtherID, "not_found")
			}
			assert.Zero(t, f.audit.countByEventType(roleChangedEvent))
		})
	}

	f := newRoleFixture()
	f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusActive)
	delete(f.members.verified[ssProject+"/"+ownTenant], "example.test")
	got, err := f.setRole(ssOwnerID, ssOtherID, RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, MembershipSourceInvited, got.Source, "a source other than the domain's is kept")
}

func TestSetTenantMemberRole_RefusesBadRequests(t *testing.T) {
	f := newRoleFixture()
	ctx := withTenantsProject(false)

	_, err := f.svc.SetTenantMemberRole(context.Background(), ssOwnerID, SessionSignIn{}, ownTenant, ssOtherID, RoleAdmin, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project in scope")
	_, err = f.svc.SetTenantMemberRole(ctx, "", SessionSignIn{}, ownTenant, ssOtherID, RoleAdmin, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	f.logs.TakeAll()

	for name, args := range map[string][3]string{
		"blank tenant": {" ", ssOtherID, RoleAdmin},
		"blank user":   {ownTenant, " ", RoleAdmin},
		"blank role":   {ownTenant, ssOtherID, " "},
		"owner":        {ownTenant, ssOtherID, RoleOwner},
		"unknown role": {ownTenant, ssOtherID, "superuser"},
	} {
		_, err := f.svc.SetTenantMemberRole(ctx, ssOwnerID, SessionSignIn{}, args[0], args[1], args[2], "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, name)
		line := decisionLine(t, f.logs, "tenant_member_role_change_refused")
		assert.Equal(t, "invalid_argument", line["reason"], name)
		assert.NotContains(t, line, "to_role", "%s: a role refused is not logged", name)
		f.logs.TakeAll()
	}
	assert.Equal(t, RoleMember, f.membership(t, ssOtherID).Role)
	assert.Zero(t, f.audit.countByEventType(roleChangedEvent))
}

func TestSetTenantMemberRole_StoreErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, fail := range map[string]func(f *roleFixture){
		"membership read": func(f *roleFixture) { f.members.getErr = boom },
		"user read":       func(f *roleFixture) { f.users.getErr = boom },
		"role write":      func(f *roleFixture) { f.members.setRoleErr = boom },
	} {
		f := newRoleFixture()
		fail(f)
		_, err := f.setRole(ssOwnerID, ssOtherID, RoleAdmin)
		require.ErrorIs(t, err, boom, name)
		assert.Zero(t, f.audit.countByEventType(roleChangedEvent), name)
		assert.Equal(t, "store_error", decisionLine(t, f.logs, "tenant_member_role_change_refused")["reason"], name)
	}
}

func TestSetTenantMemberRole_WithoutAnAuditTrailStillChanges(t *testing.T) {
	f := newRoleFixture()
	f.svc.WithAudit(nil)

	_, err := f.setRole(ssOwnerID, ssOtherID, RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, f.membership(t, ssOtherID).Role)
}
