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

// TestRedesign_Membership_SetMemberRole drives a role change over the
// Connect client against a real Postgres: an owner makes a member an admin,
// who can then list the members and invite at once, with the access token
// they already hold; the admin steps down and can do neither. The token
// carries no tenant role, ListMyTenants shows the role as it stands, an
// owner's role is refused, and the promotion is audited with the role it
// replaced.
func TestRedesign_Membership_SetMemberRole(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()

	owner := signupVerifiedUser(t, h, fmt.Sprintf("role-owner-%d@example-corp.com", stamp))
	created, err := owner.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "The Team"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()

	memberAddr := fmt.Sprintf("role-member-%d@example-corp.com", stamp)
	member := signupVerifiedUser(t, h, memberAddr)
	if _, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: memberAddr, Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	if _, err := member.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: extractMailedToken(t, h, memberAddr),
	})); err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	setRole := func(caller membershipUser, userID, role string) (*identitypb.TenantMembership, error) {
		t.Helper()
		resp, err := caller.client.SetTenantMemberRole(ctx, connect.NewRequest(&identitypb.SetTenantMemberRoleRequest{
			TenantId: tenantID, UserId: userID, Role: role,
		}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetMembership(), nil
	}
	listMembers := func() error {
		_, err := member.client.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: tenantID}))
		return err
	}
	invite := func() error {
		_, err := member.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
			TenantId: tenantID, Email: fmt.Sprintf("role-colleague-%d@example-corp.com", time.Now().UnixNano()), Role: service.RoleMember,
		}))
		return err
	}
	myRole := func() string {
		t.Helper()
		mine, err := member.client.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
		if err != nil {
			t.Fatalf("ListMyTenants: %v", err)
		}
		for _, tenant := range mine.Msg.GetTenants() {
			if tenant.GetTenantId() == tenantID {
				return tenant.GetRole()
			}
		}
		t.Fatalf("ListMyTenants = %+v, want %s", mine.Msg.GetTenants(), tenantID)
		return ""
	}

	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: memberAddr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	roleClaim := decodeTokenClaims(t, login.Msg.GetAccessToken())["role"]

	requireConnectCode(t, "a member listing the members", listMembers(), connect.CodePermissionDenied)
	_, err = setRole(member, member.userID, service.RoleAdmin)
	requireConnectCode(t, "a member promoting themselves", err, connect.CodePermissionDenied)

	promoted, err := setRole(owner, member.userID, service.RoleAdmin)
	if err != nil {
		t.Fatalf("SetTenantMemberRole(admin): %v", err)
	}
	if promoted.GetRole() != service.RoleAdmin || promoted.GetStatus() != service.MembershipStatusActive ||
		promoted.GetSource() != service.MembershipSourceInvited || promoted.GetUserId() != member.userID {
		t.Fatalf("promoted membership = %+v, want the member's invited membership as an admin", promoted)
	}
	if err := listMembers(); err != nil {
		t.Fatalf("ListTenantMembers by the promoted admin: %v", err)
	}
	if err := invite(); err != nil {
		t.Fatalf("CreateTenantInvitation by the promoted admin: %v", err)
	}
	if got := myRole(); got != service.RoleAdmin {
		t.Fatalf("ListMyTenants role = %q, want admin", got)
	}
	event := waitForAuditEvent(t, h, member.userID, string(audit.EventTenantMemberRoleChanged))
	if event.ActorUserID != owner.userID || event.TargetUserID != member.userID || !event.Success {
		t.Fatalf("role change event = %+v, want a success by the owner on the member", event)
	}
	if event.Details["tenant_id"] != tenantID || event.Details["project_id"] != h.ProjectID ||
		event.Details["role"] != service.RoleAdmin || event.Details["previous_role"] != service.RoleMember {
		t.Fatalf("role change details = %+v, want member to admin in %s", event.Details, tenantID)
	}

	selected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: login.Msg.GetRefreshToken(), TenantId: tenantID,
	}))
	if err != nil {
		t.Fatalf("RefreshToken selecting the tenant: %v", err)
	}
	claims := decodeTokenClaims(t, selected.Msg.GetAccessToken())
	if claims["tenant"] != tenantID || claims["role"] != roleClaim {
		t.Fatalf("access token claims = %+v, want the tenant selected and the role claim unchanged from %v", claims, roleClaim)
	}

	_, err = setRole(owner, owner.userID, service.RoleAdmin)
	requireConnectCode(t, "an owner's role", err, connect.CodeFailedPrecondition)
	_, err = setRole(owner, member.userID, service.RoleOwner)
	requireConnectCode(t, "the owner role", err, connect.CodeInvalidArgument)

	steppedDown, err := setRole(member, member.userID, service.RoleMember)
	if err != nil {
		t.Fatalf("SetTenantMemberRole(member) by the admin themselves: %v", err)
	}
	if steppedDown.GetRole() != service.RoleMember {
		t.Fatalf("stepped-down membership = %+v, want member", steppedDown)
	}
	requireConnectCode(t, "a demoted admin listing the members", listMembers(), connect.CodePermissionDenied)
	requireConnectCode(t, "a demoted admin inviting", invite(), connect.CodePermissionDenied)
	if got := myRole(); got != service.RoleMember {
		t.Fatalf("ListMyTenants role = %q, want member", got)
	}
}
