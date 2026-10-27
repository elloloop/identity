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

// TestRedesign_TenantOwnership drives a tenant's ownership over the wire
// against a real Postgres: its owner hands it to a member, who becomes the
// owner while the previous owner stays on as an admin; only an owner may do
// so; and once no owner can sign in, an operator appoints one, which an
// operator cannot do while an owner still can. Each change is audited once.
func TestRedesign_TenantOwnership(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	unique := time.Now().UnixNano()

	founderAddr := fmt.Sprintf("own-founder-%d@example.com", unique)
	founder := signupVerifiedUser(t, h, founderAddr)
	created, err := founder.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Acme Ownership"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()

	heirAddr := fmt.Sprintf("own-heir-%d@example.com", unique)
	heir := signupVerifiedUser(t, h, heirAddr)
	if _, err := founder.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: heirAddr, Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	if _, err := heir.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: extractMailedToken(t, h, heirAddr),
	})); err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	stranger := signupVerifiedUser(t, h, fmt.Sprintf("own-stranger-%d@example.com", unique))

	transfer := func(caller membershipUser, userID string) (*connect.Response[identitypb.TransferTenantOwnershipResponse], error) {
		return caller.client.TransferTenantOwnership(ctx, connect.NewRequest(&identitypb.TransferTenantOwnershipRequest{
			TenantId: tenantID, UserId: userID,
		}))
	}
	_, err = transfer(heir, founder.userID)
	requireConnectCode(t, "a member transferring", err, connect.CodePermissionDenied)
	_, err = transfer(founder, stranger.userID)
	requireConnectCode(t, "transferring to a non-member", err, connect.CodeNotFound)

	moved, err := transfer(founder, heir.userID)
	if err != nil {
		t.Fatalf("TransferTenantOwnership: %v", err)
	}
	if o := moved.Msg.GetOwner(); o.GetUserId() != heir.userID || o.GetRole() != service.RoleOwner || o.GetSource() != service.MembershipSourceInvited {
		t.Fatalf("owner = %+v, want %s the invited owner", o, heir.userID)
	}
	if p := moved.Msg.GetPreviousOwner(); p.GetUserId() != founder.userID || p.GetRole() != service.RoleAdmin || p.GetSource() != service.MembershipSourceCreated {
		t.Fatalf("previous owner = %+v, want %s an admin", p, founder.userID)
	}
	if roles := tenantRoles(t, heir, tenantID); roles[heir.userID] != service.RoleOwner || roles[founder.userID] != service.RoleAdmin {
		t.Fatalf("members after the transfer = %v", roles)
	}
	_, err = transfer(founder, heir.userID)
	requireConnectCode(t, "the previous owner transferring again", err, connect.CodePermissionDenied)

	recoverOwner := func(secret, tenant, userID string) (*connect.Response[identitypb.AdminRecoverTenantOwnershipResponse], error) {
		return h.adminClient(secret).AdminRecoverTenantOwnership(ctx, connect.NewRequest(&identitypb.AdminRecoverTenantOwnershipRequest{
			ProjectId: h.ProjectID, TenantId: tenant, UserId: userID, Reason: "the owner left",
		}))
	}
	_, err = recoverOwner(harnessAdminSecret, tenantID, founder.userID)
	requireConnectCode(t, "recovering while the owner can sign in", err, connect.CodeFailedPrecondition)

	// The owner's account is deactivated: nobody can govern the tenant.
	if err := h.Stores.users.UpdateUser(ctx, heir.userID, map[string]any{"status": service.StatusDeactivated}); err != nil {
		t.Fatalf("deactivate the owner: %v", err)
	}
	_, err = recoverOwner("wrong-secret", tenantID, founder.userID)
	requireConnectCode(t, "recovering with a wrong secret", err, connect.CodePermissionDenied)
	_, err = recoverOwner(harnessAdminSecret, tenantID, "user-unknown")
	requireConnectCode(t, "recovering to an unknown account", err, connect.CodeNotFound)
	_, err = recoverOwner(harnessAdminSecret, tenantID, heir.userID)
	requireConnectCode(t, "recovering to a deactivated account", err, connect.CodeFailedPrecondition)
	latentID, err := h.Stores.tenants.CreateTenant(ctx, &service.Tenant{
		ProjectID: h.ProjectID, Name: "latent.example", PrimaryDomain: fmt.Sprintf("own-latent-%d.example", unique),
		Status: service.TenantStatusLatent,
	})
	if err != nil {
		t.Fatalf("CreateTenant latent: %v", err)
	}
	_, err = recoverOwner(harnessAdminSecret, latentID, founder.userID)
	requireConnectCode(t, "recovering a latent tenant", err, connect.CodeFailedPrecondition)

	recovered, err := recoverOwner(harnessAdminSecret, tenantID, founder.userID)
	if err != nil {
		t.Fatalf("AdminRecoverTenantOwnership: %v", err)
	}
	if m := recovered.Msg.GetMembership(); m.GetUserId() != founder.userID || m.GetRole() != service.RoleOwner || m.GetStatus() != service.MembershipStatusActive {
		t.Fatalf("recovered membership = %+v, want %s the active owner", m, founder.userID)
	}
	again, err := recoverOwner(harnessAdminSecret, tenantID, founder.userID)
	if err != nil {
		t.Fatalf("AdminRecoverTenantOwnership again: %v", err)
	}
	if again.Msg.GetMembership().GetId() != recovered.Msg.GetMembership().GetId() {
		t.Fatalf("a retried recovery returned %+v, want %+v", again.Msg.GetMembership(), recovered.Msg.GetMembership())
	}
	if roles := tenantRoles(t, founder, tenantID); roles[founder.userID] != service.RoleOwner {
		t.Fatalf("members after the recovery = %v", roles)
	}

	transferred := waitForTenantAuditEvents(t, h.ProjectID, tenantID, audit.EventTenantOwnershipTransferred)
	if len(transferred) != 1 || transferred[0]["project_id"] != h.ProjectID {
		t.Fatalf("%s events = %v, want one", audit.EventTenantOwnershipTransferred, transferred)
	}
	recoveries := waitForTenantAuditEvents(t, h.ProjectID, tenantID, audit.EventTenantOwnershipRecovered)
	if len(recoveries) != 1 || recoveries[0]["reason"] != "the owner left" {
		t.Fatalf("%s events = %v, want one with the reason", audit.EventTenantOwnershipRecovered, recoveries)
	}
}

// tenantRoles lists tenantID's members as caller, an admin of it, by user id.
func tenantRoles(t *testing.T, caller membershipUser, tenantID string) map[string]string {
	t.Helper()
	list, err := caller.client.ListTenantMembers(context.Background(), connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: tenantID}))
	if err != nil {
		t.Fatalf("ListTenantMembers: %v", err)
	}
	roles := map[string]string{}
	for _, m := range list.Msg.GetMembers() {
		roles[m.GetUserId()] = m.GetRole()
	}
	return roles
}
