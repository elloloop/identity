package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/audit"
)

// ── RevokeTenantInvitation ───────────────────────────────────────────────

const revokedEvent = string(audit.EventTenantInvitationRevoked)

// revokeFixture is a no-mail membership fixture whose audit trail and logs
// are recorded, with mAdminID an owner of mTestTenant and mInvitee invited to
// it.
type revokeFixture struct {
	*membershipFixture
	audit *recordingAuditWriter
	logs  *observer.ObservedLogs
	inv   *TenantInvitation
	token string
}

func newRevokeFixture(t *testing.T) *revokeFixture {
	t.Helper()
	f := newMembershipFixtureNoMail()
	w := newRecordingAuditWriter()
	core, logs := observer.New(zapcore.InfoLevel)
	f.svc.WithAudit(audit.NewLogger(w, "test-tenant", nil))
	f.svc.logger = zap.New(core)
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	out, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleAdmin)
	require.NoError(t, err)
	f.users.put(mTestProject, mInviteeID, mInvitee)
	return &revokeFixture{membershipFixture: f, audit: w, logs: logs, inv: out.Invitation, token: out.RawToken}
}

// requireRevokeRefused asserts the one refusal line the last revoke logged
// names reason.
func (f *revokeFixture) requireRevokeRefused(t *testing.T, caller, tenantID, invitationID, reason string) {
	t.Helper()
	requireOneLogLine(t, f.logs, "tenant_invitation_revoke_refused", map[string]any{
		"project_id": mTestProject, "tenant_id": tenantID, "invitation_id": invitationID, "user_id": caller, "reason": reason,
	})
	f.logs.TakeAll()
}

func (f *revokeFixture) stored(t *testing.T, projectID, invitationID string) *TenantInvitation {
	t.Helper()
	inv, ok := f.invitations.byID[f.invitations.key(projectID, invitationID)]
	require.True(t, ok, invitationID)
	return inv
}

// An owner revokes a pending invitation: it is revoked, its token no longer
// redeems, and the revocation is recorded once with who made it.
func TestRevokeTenantInvitation_OwnerRevokesAndTheTokenStopsRedeeming(t *testing.T) {
	f := newRevokeFixture(t)
	ctx := withProject(mTestProject)

	got, err := f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, " "+mTestTenant+" ", " "+f.inv.ID+" ", "203.0.113.7", "test-agent")
	require.NoError(t, err)
	assert.Equal(t, f.inv.ID, got.ID)
	assert.Equal(t, InvitationStatusRevoked, got.Status)
	assert.Equal(t, InvitationStatusRevoked, f.stored(t, mTestProject, f.inv.ID).Status)
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(revokedEvent, mAdminID, f.inv.ID))
	assert.Equal(t, []map[string]any{{
		"project_id": mTestProject, "tenant_id": mTestTenant, "role": RoleAdmin, "invited_by": mAdminID,
	}}, f.audit.detailsOf(revokedEvent))
	assert.Equal(t, [][2]string{{"203.0.113.7", "test-agent"}}, f.audit.clientsOf(revokedEvent))
	requireOneLogLine(t, f.logs, "tenant_invitation_revoked", map[string]any{
		"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": f.inv.ID, "user_id": mAdminID,
	})

	_, err = f.svc.AcceptTenantInvitation(ctx, mInviteeID, f.token)
	require.ErrorIs(t, err, ErrPermissionDenied)
	m, err := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, mInviteeID)
	require.NoError(t, err)
	assert.Nil(t, m, "a revoked invitation makes nobody a member")
}

func TestRevokeTenantInvitation_AnAdminMayRevoke(t *testing.T) {
	f := newRevokeFixture(t)
	f.seedMember(mTestProject, mTestTenant, "user-co-admin", RoleAdmin)

	got, err := f.svc.RevokeTenantInvitation(withProject(mTestProject), "user-co-admin", SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, InvitationStatusRevoked, got.Status)
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(revokedEvent, "user-co-admin", f.inv.ID))
}

// Revoking a revoked invitation returns it unchanged and records nothing, so
// a retry is safe.
func TestRevokeTenantInvitation_RevokingTwiceChangesNothing(t *testing.T) {
	f := newRevokeFixture(t)
	ctx := withProject(mTestProject)

	first, err := f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.NoError(t, err)
	again, err := f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, first, again)
	assert.Equal(t, 1, f.audit.countByEventType(revokedEvent))
	assert.Equal(t, 1, f.logs.FilterMessage("tenant_invitation_revoked").Len())
	requireOneLogLine(t, f.logs, "tenant_invitation_revoke_unchanged", map[string]any{
		"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": f.inv.ID, "user_id": mAdminID,
		"status": InvitationStatusRevoked,
	})
}

// Only an active owner or admin of a tenant that may be governed revokes its
// invitations; anyone else is refused before the invitation is read, and the
// invitation stays open.
func TestRevokeTenantInvitation_RefusesWhoCannotGovernTheTenant(t *testing.T) {
	for name, setup := range map[string]func(f *revokeFixture) string{
		"plain member": func(f *revokeFixture) string {
			f.seedMember(mTestProject, mTestTenant, "user-member", RoleMember)
			return "user-member"
		},
		"non-member": func(*revokeFixture) string { return "user-stranger" },
		"suspended admin": func(f *revokeFixture) string {
			f.seedMember(mTestProject, mTestTenant, "user-suspended", RoleAdmin)
			_, _, err := f.memberships.SuspendMembership(context.Background(), mTestProject, mTestTenant, "user-suspended")
			require.NoError(t, err)
			return "user-suspended"
		},
		"owner of a suspended tenant": func(f *revokeFixture) string {
			f.tenants.byID[mTestProject+"/"+mTestTenant].Status = TenantStatusSuspended
			return mAdminID
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRevokeFixture(t)
			caller := setup(f)

			_, err := f.svc.RevokeTenantInvitation(withProject(mTestProject), caller, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
			require.ErrorIs(t, err, ErrPermissionDenied)
			assert.Equal(t, InvitationStatusPending, f.stored(t, mTestProject, f.inv.ID).Status)
			assert.Zero(t, f.audit.countByEventType(revokedEvent))
			f.requireRevokeRefused(t, caller, mTestTenant, f.inv.ID, "not_permitted")
		})
	}
}

// An id that is not one of the named tenant's invitations is NotFound,
// whether another tenant holds it or nobody does, and the other tenant's
// invitation is left as it is. An admin of one tenant naming another is
// refused as any non-admin is.
func TestRevokeTenantInvitation_AnotherTenantsOrUnknownInvitationIsNotFound(t *testing.T) {
	f := newRevokeFixture(t)
	ctx := withProject(mTestProject)
	const otherTenant, otherAdmin = "tenant-2", "user-admin-2"
	f.seedAdmin(mTestProject, otherTenant, otherAdmin)
	other, err := f.svc.CreateTenantInvitation(ctx, otherAdmin, SessionSignIn{}, otherTenant, "someone@acme.com", RoleMember)
	require.NoError(t, err)

	_, err = f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, other.Invitation.ID, "", "")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, InvitationStatusPending, f.stored(t, mTestProject, other.Invitation.ID).Status)
	f.requireRevokeRefused(t, mAdminID, mTestTenant, other.Invitation.ID, "not_found")

	_, err = f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, "inv-unknown", "", "")
	require.ErrorIs(t, err, ErrNotFound)
	f.requireRevokeRefused(t, mAdminID, mTestTenant, "inv-unknown", "not_found")

	_, err = f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, otherTenant, other.Invitation.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	assert.Equal(t, InvitationStatusPending, f.stored(t, mTestProject, other.Invitation.ID).Status)
	f.requireRevokeRefused(t, mAdminID, otherTenant, other.Invitation.ID, "not_permitted")

	_, err = f.svc.RevokeTenantInvitation(withProject("proj-other"), mAdminID, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "the caller governs the tenant in its own project only")
	assert.Zero(t, f.audit.countByEventType(revokedEvent))
}

// An accepted invitation is refused: revoking it would not end the
// membership it made, which RemoveTenantMember does.
func TestRevokeTenantInvitation_AcceptedInvitationIsRefused(t *testing.T) {
	f := newRevokeFixture(t)
	ctx := withProject(mTestProject)
	_, err := f.svc.AcceptTenantInvitation(ctx, mInviteeID, f.token)
	require.NoError(t, err)

	_, err = f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.ErrorIs(t, err, ErrInvitationUsed)
	assert.Equal(t, InvitationStatusAccepted, f.stored(t, mTestProject, f.inv.ID).Status)
	f.requireRevokeRefused(t, mAdminID, mTestTenant, f.inv.ID, "accepted")
	m, err := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, mInviteeID)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, MembershipStatusActive, m.Status)
	assert.Zero(t, f.audit.countByEventType(revokedEvent))
}

// An invitation already marked expired is returned as it is: its token
// redeems nothing either way.
func TestRevokeTenantInvitation_ExpiredInvitationIsUnchanged(t *testing.T) {
	f := newRevokeFixture(t)
	ctx := withProject(mTestProject)
	f.svc.nowFunc = func() time.Time { return time.Now().Add(defaultInvitationTTL + time.Hour) }
	_, err := f.svc.AcceptTenantInvitation(ctx, mInviteeID, f.token)
	require.ErrorIs(t, err, ErrPermissionDenied)

	got, err := f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, InvitationStatusExpired, got.Status)
	assert.Zero(t, f.audit.countByEventType(revokedEvent))
	requireOneLogLine(t, f.logs, "tenant_invitation_revoke_unchanged", map[string]any{"status": InvitationStatusExpired})
}

func TestRevokeTenantInvitation_RejectsMissingProjectCallerAndIDs(t *testing.T) {
	f := newRevokeFixture(t)
	ctx := withProject(mTestProject)

	_, err := f.svc.RevokeTenantInvitation(context.Background(), mAdminID, SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project")
	requireOneLogLine(t, f.logs, "tenant_invitation_revoke_refused", map[string]any{"project_id": "", "reason": "no_project"})
	f.logs.TakeAll()
	_, err = f.svc.RevokeTenantInvitation(ctx, "", SessionSignIn{}, mTestTenant, f.inv.ID, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated, "no caller")
	f.requireRevokeRefused(t, "", mTestTenant, f.inv.ID, "unauthenticated")
	_, err = f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, " ", f.inv.ID, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument, "no tenant_id")
	f.requireRevokeRefused(t, mAdminID, "", f.inv.ID, "invalid_argument")
	_, err = f.svc.RevokeTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, " ", "", "")
	require.ErrorIs(t, err, ErrInvalidArgument, "no invitation_id")
	f.requireRevokeRefused(t, mAdminID, mTestTenant, "", "invalid_argument")
	assert.Equal(t, InvitationStatusPending, f.stored(t, mTestProject, f.inv.ID).Status)
}
