//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// TestRedesign_Membership_SuspendAndRestore drives a member's suspension over
// the Connect client against a real Postgres: an owner suspends an admin who
// joined by invitation. The admin keeps the membership, its role and its
// source, but may no longer select the tenant at a refresh or act as its
// admin, and their refresh token still rotates without the tenant. The owner
// restores them, and the next refresh selects the tenant again. Both changes
// are audited.
func TestRedesign_Membership_SuspendAndRestore(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()

	owner := signupVerifiedUser(t, h, fmt.Sprintf("suspend-owner-%d@example-corp.com", stamp))
	created, err := owner.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "The Team"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()

	memberAddr := fmt.Sprintf("suspend-member-%d@example-corp.com", stamp)
	member := signupVerifiedUser(t, h, memberAddr)
	if _, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: memberAddr, Role: service.RoleAdmin,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	if _, err := member.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: extractMailedToken(t, h, memberAddr),
	})); err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: memberAddr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	selected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: login.Msg.GetRefreshToken(), TenantId: tenantID,
	}))
	if err != nil {
		t.Fatalf("RefreshToken selecting the tenant before the suspension: %v", err)
	}

	_, err = owner.client.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: tenantID, UserId: owner.userID,
	}))
	requireConnectCode(t, "suspending yourself", err, connect.CodeInvalidArgument)

	suspended, err := owner.client.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: tenantID, UserId: member.userID,
	}))
	if err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	if m := suspended.Msg.GetMembership(); m.GetStatus() != service.MembershipStatusSuspended ||
		m.GetRole() != service.RoleAdmin || m.GetSource() != service.MembershipSourceInvited || m.GetUserId() != member.userID {
		t.Fatalf("suspended membership = %+v, want the admin's invited membership, suspended", m)
	}
	listed, err := owner.client.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: tenantID}))
	if err != nil {
		t.Fatalf("ListTenantMembers: %v", err)
	}
	statuses := map[string]string{}
	for _, m := range listed.Msg.GetMembers() {
		statuses[m.GetUserId()] = m.GetStatus()
	}
	if statuses[member.userID] != service.MembershipStatusSuspended {
		t.Fatalf("ListTenantMembers statuses = %+v, want the member listed as suspended", statuses)
	}

	rotated := requireNotInTenant(t, h, "suspended", login.Msg.GetAccessToken(), selected.Msg.GetRefreshToken(), tenantID)
	_, err = member.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: fmt.Sprintf("colleague-%d@example-corp.com", stamp), Role: service.RoleMember,
	}))
	requireConnectCode(t, "a suspended admin inviting", err, connect.CodePermissionDenied)
	_, err = member.client.RestoreTenantMember(ctx, connect.NewRequest(&identitypb.RestoreTenantMemberRequest{
		TenantId: tenantID, UserId: member.userID,
	}))
	requireConnectCode(t, "a suspended admin restoring themselves", err, connect.CodePermissionDenied)

	restored, err := owner.client.RestoreTenantMember(ctx, connect.NewRequest(&identitypb.RestoreTenantMemberRequest{
		TenantId: tenantID, UserId: member.userID,
	}))
	if err != nil {
		t.Fatalf("RestoreTenantMember: %v", err)
	}
	if m := restored.Msg.GetMembership(); m.GetStatus() != service.MembershipStatusActive || m.GetRole() != service.RoleAdmin {
		t.Fatalf("restored membership = %+v, want the admin's membership, active", m)
	}
	reselected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: rotated, TenantId: tenantID,
	}))
	if err != nil {
		t.Fatalf("RefreshToken selecting the tenant after the restore: %v", err)
	}
	if got := decodeTokenTenantClaim(t, reselected.Msg.GetAccessToken()); got != tenantID {
		t.Fatalf("restored token's tenant claim = %q, want %q", got, tenantID)
	}

	for _, eventType := range []audit.EventType{audit.EventTenantMemberSuspended, audit.EventTenantMemberRestored} {
		event := waitForAuditEvent(t, h, member.userID, string(eventType))
		if event.ActorUserID != owner.userID || event.TargetUserID != member.userID || !event.Success {
			t.Fatalf("%s event = %+v, want a success by the owner on the member", eventType, event)
		}
		if event.Details["tenant_id"] != tenantID || event.Details["project_id"] != h.ProjectID || event.Details["role"] != service.RoleAdmin {
			t.Fatalf("%s details = %+v, want the admin's membership of %s in %s", eventType, event.Details, tenantID, h.ProjectID)
		}
	}
}
