package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/audit"
)

// ── SuspendTenantMember / RestoreTenantMember ────────────────────────────

// suspensionFixture is a join fixture in which joinerID has joined
// ownTenant through their email's domain, which the tenant verified.
func suspensionFixture(t *testing.T) *joinFixture {
	t.Helper()
	f := newJoinFixture()
	_, err := f.svc.JoinTenantByDomain(withTenantsProject(false), joinerID, ownTenant, "", "")
	require.NoError(t, err)
	return f
}

func (f *joinFixture) membership(t *testing.T, userID string) *TenantMembership {
	t.Helper()
	m, err := f.members.GetMembership(context.Background(), ssProject, ownTenant, userID)
	require.NoError(t, err)
	require.NotNil(t, m, userID)
	return m
}

// A suspension keeps the membership, its role and source, and takes the
// tenant away from the member until a restore gives it back; each change is
// recorded once, with who made it and the membership it left.
func TestSuspendTenantMember_SuspendsAndRestoresAndAudits(t *testing.T) {
	f := suspensionFixture(t)
	ctx := withTenantsProject(false)
	suspended, restored := string(audit.EventTenantMemberSuspended), string(audit.EventTenantMemberRestored)

	got, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, " "+ownTenant+" ", " "+joinerID+" ", "203.0.113.7", "test-agent")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusSuspended, got.Status)
	assert.Equal(t, RoleMember, got.Role)
	assert.Equal(t, MembershipSourceDomain, got.Source)
	assert.Equal(t, got, f.membership(t, joinerID))
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(suspended, ssOwnerID, joinerID))
	assert.Equal(t, []map[string]any{{
		"project_id": ssProject, "tenant_id": ownTenant,
		"role": RoleMember, "source": MembershipSourceDomain, "status": MembershipStatusSuspended,
	}}, f.audit.detailsOf(suspended))
	assert.Equal(t, [][2]string{{"203.0.113.7", "test-agent"}}, f.audit.clientsOf(suspended))

	mine, err := f.svc.ListMyTenants(ctx, joinerID)
	require.NoError(t, err)
	assert.Empty(t, mine, "a suspended member's tenant is not theirs to choose")
	members, err := f.svc.ListTenantMembers(ctx, ssOwnerID, ownTenant)
	require.NoError(t, err)
	assert.Len(t, members, 2, "the member list still shows them")

	// Suspending them again changes and records nothing.
	again, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)
	assert.Equal(t, got, again)
	assert.Equal(t, 1, f.audit.countByEventType(suspended))

	back, err := f.svc.RestoreTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "198.51.100.2", "other-agent")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, back.Status)
	assert.Equal(t, RoleMember, back.Role)
	assert.Equal(t, MembershipSourceDomain, back.Source)
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(restored, ssOwnerID, joinerID))
	assert.Equal(t, []map[string]any{{
		"project_id": ssProject, "tenant_id": ownTenant,
		"role": RoleMember, "source": MembershipSourceDomain, "status": MembershipStatusActive,
	}}, f.audit.detailsOf(restored))
	mine, err = f.svc.ListMyTenants(ctx, joinerID)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	assert.Equal(t, ownTenant, mine[0].TenantID)

	// Restoring an active member changes and records nothing.
	again, err = f.svc.RestoreTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)
	assert.Equal(t, back, again)
	assert.Equal(t, 1, f.audit.countByEventType(restored))
}

// Without an audit trail both changes still happen.
func TestSuspendTenantMember_WithoutAnAuditTrail(t *testing.T) {
	f := suspensionFixture(t)
	f.svc.WithAudit(nil)
	ctx := withTenantsProject(false)

	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusSuspended, f.membership(t, joinerID).Status)
	_, err = f.svc.RestoreTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, f.membership(t, joinerID).Status)
}

// A suspended member cannot let themselves back in: their domain does not
// offer the tenant, joining by it is refused with the reason, and a
// suspended admin cannot administer.
func TestSuspendTenantMember_KeepsTheMemberOut(t *testing.T) {
	f := suspensionFixture(t)
	ctx := withTenantsProject(false)
	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)

	assert.Empty(t, f.joinable(t, joinerID))
	_, err = f.svc.JoinTenantByDomain(ctx, joinerID, ownTenant, "", "")
	require.ErrorIs(t, err, ErrMemberSuspended)
	assert.Equal(t, MembershipStatusSuspended, f.membership(t, joinerID).Status)
	assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantJoinedByDomain)), "only the first join is recorded")

	// An admin suspended can neither list, remove nor suspend anyone.
	f.seed(ssOtherID, MembershipSourceInvited, RoleAdmin, MembershipStatusActive)
	_, err = f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	_, err = f.svc.ListTenantMembers(ctx, ssOtherID, ownTenant)
	require.ErrorIs(t, err, ErrPermissionDenied)
	_, err = f.svc.RestoreTenantMember(ctx, ssOtherID, ownTenant, ssOtherID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "nobody restores themselves")
	require.ErrorIs(t, f.svc.RemoveTenantMember(ctx, ssOtherID, ownTenant, joinerID, "", ""), ErrPermissionDenied)
}

// An invitation the suspended member accepts leaves the suspension, and the
// invitation, as they were.
func TestSuspendTenantMember_AnInvitationDoesNotLiftIt(t *testing.T) {
	f := newMembershipFixtureNoMail()
	rawToken := f.seedInvite(t)
	f.users.put(mTestProject, mInviteeID, mInvitee)
	f.seedMember(mTestProject, mTestTenant, mInviteeID, RoleMember)
	ctx := withProject(mTestProject)
	_, err := f.svc.SuspendTenantMember(ctx, mAdminID, mTestTenant, mInviteeID, "", "")
	require.NoError(t, err)

	_, err = f.svc.AcceptTenantInvitation(ctx, mInviteeID, rawToken)
	require.ErrorIs(t, err, ErrMemberSuspended)
	m, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, mInviteeID)
	assert.Equal(t, MembershipStatusSuspended, m.Status)
	assert.Equal(t, RoleMember, m.Role, "the invitation's admin role is not granted")
	invs, _ := f.invitations.ListInvitationsForTenant(context.Background(), mTestProject, mTestTenant)
	require.Len(t, invs, 1)
	assert.Equal(t, InvitationStatusPending, invs[0].Status)

	// Once restored, the invitation is accepted as any other.
	_, err = f.svc.RestoreTenantMember(ctx, mAdminID, mTestTenant, mInviteeID, "", "")
	require.NoError(t, err)
	m, err = f.svc.AcceptTenantInvitation(ctx, mInviteeID, rawToken)
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, m.Role)
	assert.Equal(t, MembershipStatusActive, m.Status)
}

// A tenant keeps an active owner: its last one cannot be suspended, by an
// admin or anyone, while one of two can, by an admin too.
func TestSuspendTenantMember_KeepsAnOwner(t *testing.T) {
	f := suspensionFixture(t)
	ctx := withTenantsProject(false)
	f.seed(ssOtherID, MembershipSourceInvited, RoleAdmin, MembershipStatusActive)

	_, err := f.svc.SuspendTenantMember(ctx, ssOtherID, ownTenant, ssOwnerID, "", "")
	require.ErrorIs(t, err, ErrLastOwner)
	assert.Equal(t, MembershipStatusActive, f.membership(t, ssOwnerID).Status)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantMemberSuspended)))

	f.seed(joinerID, MembershipSourceInvited, RoleOwner, MembershipStatusActive)
	got, err := f.svc.SuspendTenantMember(ctx, ssOtherID, ownTenant, ssOwnerID, "", "")
	require.NoError(t, err)
	assert.Equal(t, RoleOwner, got.Role)
	assert.Equal(t, MembershipStatusSuspended, got.Status)
	_, err = f.svc.SuspendTenantMember(ctx, ssOtherID, ownTenant, joinerID, "", "")
	require.ErrorIs(t, err, ErrLastOwner, "the other owner is now the last active one")
}

// A domain member whose email left the tenant's verified domains while
// suspended comes back ended, as the change of email would have left them.
func TestRestoreTenantMember_ADomainMemberOffTheDomainEnds(t *testing.T) {
	f := suspensionFixture(t)
	ctx := withTenantsProject(false)
	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)
	f.users.set(ssProject, &User{ID: joinerID, Email: "joiner@elsewhere.test", Status: StatusActive, EmailVerified: true})

	got, err := f.svc.RestoreTenantMember(ctx, ssOwnerID, ownTenant, joinerID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusInactive, got.Status)
	assert.Equal(t, MembershipStatusInactive, f.membership(t, joinerID).Status)
	assert.Equal(t, MembershipStatusInactive, f.audit.detailsOf(string(audit.EventTenantMemberRestored))[0]["status"])

	// A membership from any other source comes back active wherever the
	// email is.
	f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusActive)
	_, err = f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	f.users.set(ssProject, &User{ID: ssOtherID, Email: "other@elsewhere.test", Status: StatusActive, EmailVerified: true})
	got, err = f.svc.RestoreTenantMember(ctx, ssOwnerID, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, got.Status)
}

func TestSuspendAndRestoreTenantMember_Refusals(t *testing.T) {
	type call func(f *joinFixture, ctx context.Context, caller, tenant, target string) error
	suspend := func(f *joinFixture, ctx context.Context, caller, tenant, target string) error {
		_, err := f.svc.SuspendTenantMember(ctx, caller, tenant, target, "", "")
		return err
	}
	restore := func(f *joinFixture, ctx context.Context, caller, tenant, target string) error {
		_, err := f.svc.RestoreTenantMember(ctx, caller, tenant, target, "", "")
		return err
	}
	for name, do := range map[string]call{"suspend": suspend, "restore": restore} {
		t.Run(name, func(t *testing.T) {
			f := suspensionFixture(t)
			f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusActive)
			ctx := withTenantsProject(false)

			require.ErrorIs(t, do(f, context.Background(), ssOwnerID, ownTenant, joinerID), ErrPermissionDenied, "no project")
			require.ErrorIs(t, do(f, ctx, "", ownTenant, joinerID), ErrUnauthenticated)
			require.ErrorIs(t, do(f, ctx, ssOwnerID, " ", joinerID), ErrInvalidArgument)
			require.ErrorIs(t, do(f, ctx, ssOwnerID, ownTenant, " "), ErrInvalidArgument)
			require.ErrorIs(t, do(f, ctx, ssOtherID, ownTenant, joinerID), ErrPermissionDenied, "a member is not an admin")
			require.ErrorIs(t, do(f, ctx, "stranger", ownTenant, joinerID), ErrPermissionDenied)
			require.ErrorIs(t, do(f, ctx, ssOwnerID, ownTenant, "stranger"), ErrNotFound)
			f.seed("ended", MembershipSourceInvited, RoleMember, MembershipStatusInactive)
			require.ErrorIs(t, do(f, ctx, ssOwnerID, ownTenant, "ended"), ErrNotFound, "an ended membership is not a member's")

			f.tenant().Status = TenantStatusSuspended
			require.ErrorIs(t, do(f, ctx, ssOwnerID, ownTenant, joinerID), ErrPermissionDenied, "a suspended tenant")
			assert.Equal(t, MembershipStatusActive, f.membership(t, joinerID).Status)
			assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantMemberSuspended)))
			assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantMemberRestored)))
		})
	}

	// An admin may not suspend themselves; anyone else naming themselves is
	// refused as a non-admin first.
	f := suspensionFixture(t)
	f.seed(ssOtherID, MembershipSourceInvited, RoleMember, MembershipStatusActive)
	ctx := withTenantsProject(false)
	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, ownTenant, " "+ssOwnerID, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument, "nobody suspends themselves")
	_, err = f.svc.SuspendTenantMember(ctx, ssOtherID, ownTenant, ssOtherID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "a member is not an admin, of themselves either")
	assert.Equal(t, MembershipStatusActive, f.membership(t, ssOwnerID).Status)
}

// ── who else lifts a suspension ─────────────────────────────────────────

// An operator's appointment lifts a suspension: the appointee becomes an
// active owner, and the appointment is recorded.
func TestAdminRecoverTenantOwnership_LiftsASuspension(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, seed := range map[string]struct{ source, role string }{
		"suspended member":        {MembershipSourceInvited, RoleMember},
		"suspended domain member": {MembershipSourceDomain, RoleMember},
		"suspended owner":         {MembershipSourceCreated, RoleOwner},
	} {
		f := newRecoveryFixture()
		f.seedMembership("heir", seed.source, seed.role, MembershipStatusSuspended)

		got, err := f.recover("heir", "why")
		require.NoError(t, err, name)
		assert.Equal(t, RoleOwner, got.Role, name)
		assert.Equal(t, MembershipStatusActive, got.Status, name)
		stored, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
		assert.Equal(t, got, stored, name)
		assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantOwnershipRecovered)), name)
	}
}

// An operator's grant of administration lifts a suspension too.
func TestAdminAddTenantAdmin_LiftsASuspension(t *testing.T) {
	t.Parallel()
	f := newRecoveryFixture()
	f.seedMembership("heir", MembershipSourceInvited, RoleMember, MembershipStatusSuspended)

	got, err := f.svc.AdminAddTenantAdmin(context.Background(), testAdminSecret, "proj", "t-1", "heir", RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, got.Status)
	stored, _ := f.members.GetMembership(context.Background(), "proj", "t-1", "heir")
	assert.Equal(t, MembershipStatusActive, stored.Status)
	assert.Equal(t, RoleAdmin, stored.Role)
}

// A caller suspended while their domain's check is in flight gains no
// ownership; the domain they proved is verified all the same.
func TestVerifyDomain_ASuspensionDuringTheCheckStands(t *testing.T) {
	f := newDomainFixture()
	id := f.publishedClaim(t, TenantStatusClaimed)
	f.resolver.onLookup = func() {
		m := f.members.byKey[f.members.key(testProject, testTenant, testCaller)]
		m.Role, m.Status = RoleAdmin, MembershipStatusSuspended
	}

	got, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.NoError(t, err)
	assert.Equal(t, DomainStatusVerified, got.Status)
	m, _ := f.members.GetMembership(context.Background(), testProject, testTenant, testCaller)
	assert.Equal(t, MembershipStatusSuspended, m.Status)
	assert.Equal(t, RoleAdmin, m.Role)
}
