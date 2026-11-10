//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// tenantOperatorClient returns a Connect client presenting a tenant_operator
// credential in X-Tenant-Operator-Key and nothing else.
func (h *RedesignHarness) tenantOperatorClient(rawKey string) identityconnectgen.IdentityServiceClient {
	return h.ClientWithHost("", map[string]string{middleware.TenantOperatorKeyHeader: rawKey})
}

// TestRedesign_TenantOperatorCredential drives a tenant_operator credential
// over the wire against a real Postgres. Minted with the admin secret, it
// reads, lists, suspends and restores its own project's tenants, reads their
// login policy, creates a tenant, makes an account of the project its owner
// and another its member, and restores a tenant it created that nobody
// governs, and its changes name it as their actor. It is refused another
// project, a tenant of another project, and every operator call outside the
// tenant operations, and a revocation holds from the next call. The refusals
// of the credential are recorded under its project with their reasons.
func TestRedesign_TenantOperatorCredential(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	addr := fmt.Sprintf("operator-owner-%d@example.com", unique)
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	verifyMailedEmail(t, h, h.Client, addr)
	created, err := h.AuthedClient(signup.Msg.GetAccessToken()).CreateTenant(ctx,
		connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Acme Operated"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()

	minted, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: h.ProjectID, Kind: service.CredentialKindTenantOperator,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential(tenant_operator): %v", err)
	}
	if !strings.HasPrefix(minted.Msg.GetPublicId(), "ok_") || !strings.HasPrefix(minted.Msg.GetRawKey(), minted.Msg.GetPublicId()+".") {
		t.Fatalf("minted public id %q, raw key not shaped <public id>.<secret>", minted.Msg.GetPublicId())
	}
	actor := "credential:" + minted.Msg.GetCredentialId()
	operator := h.tenantOperatorClient(minted.Msg.GetRawKey())

	got, err := operator.AdminGetTenant(ctx, connect.NewRequest(&identitypb.AdminGetTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID,
	}))
	if err != nil {
		t.Fatalf("AdminGetTenant with the credential: %v", err)
	}
	if got.Msg.GetTenant().GetStatus() != service.TenantStatusClaimed {
		t.Fatalf("AdminGetTenant = %+v, want claimed", got.Msg.GetTenant())
	}
	listed, err := operator.AdminListTenants(ctx, connect.NewRequest(&identitypb.AdminListTenantsRequest{
		ProjectId: h.ProjectID, Limit: 200,
	}))
	if err != nil {
		t.Fatalf("AdminListTenants with the credential: %v", err)
	}
	found := false
	for _, tn := range listed.Msg.GetTenants() {
		found = found || tn.GetId() == tenantID
	}
	if !found {
		t.Fatalf("AdminListTenants did not return %s", tenantID)
	}
	if _, err := operator.GetLoginPolicy(ctx, connect.NewRequest(&identitypb.GetLoginPolicyRequest{
		ProjectId: h.ProjectID, TenantId: tenantID,
	})); err != nil {
		t.Fatalf("GetLoginPolicy with the credential: %v", err)
	}
	suspended, err := operator.AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "support hold",
	}))
	if err != nil {
		t.Fatalf("AdminSuspendTenant with the credential: %v", err)
	}
	if suspended.Msg.GetTenant().GetStatus() != service.TenantStatusSuspended {
		t.Fatalf("AdminSuspendTenant = %+v, want suspended", suspended.Msg.GetTenant())
	}
	restored, err := operator.AdminRestoreTenant(ctx, connect.NewRequest(&identitypb.AdminRestoreTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "hold lifted",
	}))
	if err != nil {
		t.Fatalf("AdminRestoreTenant with the credential: %v", err)
	}
	if restored.Msg.GetTenant().GetStatus() != service.TenantStatusClaimed {
		t.Fatalf("AdminRestoreTenant = %+v, want claimed", restored.Msg.GetTenant())
	}
	for _, event := range []audit.EventType{audit.EventTenantSuspended, audit.EventTenantRestored} {
		if actors := waitForAuditActors(t, h.ProjectID, event, tenantID, 1); len(actors) != 1 || actors[0] != actor {
			t.Fatalf("%s actors = %v, want [%s]", event, actors, actor)
		}
	}

	createdResp, err := operator.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId: h.ProjectID, Name: "Acme Provisioned", PrimaryDomain: fmt.Sprintf("provisioned-%d.example", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateTenant with the credential: %v", err)
	}
	provisionedID := createdResp.Msg.GetTenantId()
	provisioned, err := h.Stores.tenants.GetTenant(ctx, h.ProjectID, provisionedID)
	if err != nil || provisioned == nil || provisioned.Status != service.TenantStatusClaimed {
		t.Fatalf("provisioned tenant = %+v (%v), want a claimed tenant of the project", provisioned, err)
	}
	ownerID := signup.Msg.GetUser().GetId()
	addedResp, err := operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: ownerID, Role: service.RoleOwner,
	}))
	if err != nil {
		t.Fatalf("AdminAddTenantAdmin with the credential: %v", err)
	}
	if m := addedResp.Msg.GetMembership(); m.GetUserId() != ownerID || m.GetRole() != service.RoleOwner {
		t.Fatalf("AdminAddTenantAdmin membership = %+v, want %s as owner", m, ownerID)
	}
	mem, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, provisionedID, ownerID)
	if err != nil || mem == nil || mem.Role != service.RoleOwner || mem.Status != service.MembershipStatusActive || mem.Source != service.MembershipSourceAdded {
		t.Fatalf("stored membership = %+v (%v), want an active added owner", mem, err)
	}
	for _, event := range []audit.EventType{audit.EventTenantCreated, audit.EventTenantAdminAdded} {
		if actors := waitForAuditActors(t, h.ProjectID, event, provisionedID, 1); len(actors) != 1 || actors[0] != actor {
			t.Fatalf("%s actors = %v, want [%s]", event, actors, actor)
		}
	}
	if targets := pollAuditColumn(t, 1, `
		SELECT target || ' ' || (details->>'role') FROM audit_events
		 WHERE project_id = $1 AND event_type = $2 AND details->>'tenant_id' = $3`,
		h.ProjectID, string(audit.EventTenantAdminAdded), provisionedID); len(targets) != 1 || targets[0] != ownerID+" owner" {
		t.Fatalf("tenant_admin_added target and role = %v, want [%s owner]", targets, ownerID)
	}

	// The credential appoints only a first governor: a retry of the grant
	// returns the membership and records nothing more, and it can neither
	// lower the owner it appointed nor touch a tenant someone governs.
	retried, err := operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: ownerID, Role: service.RoleOwner,
	}))
	if err != nil || retried.Msg.GetMembership().GetId() != addedResp.Msg.GetMembership().GetId() {
		t.Fatalf("retried AdminAddTenantAdmin = %+v (%v), want the same membership", retried, err)
	}
	_, err = operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: ownerID, Role: service.RoleAdmin,
	}))
	requireConnectCode(t, "AdminAddTenantAdmin lowering the owner it appointed", err, connect.CodeFailedPrecondition)
	_, err = operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, UserId: ownerID, Role: service.RoleAdmin,
	}))
	requireConnectCode(t, "AdminAddTenantAdmin on a tenant its owner governs", err, connect.CodeFailedPrecondition)
	if mem, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, tenantID, ownerID); err != nil || mem == nil || mem.Role != service.RoleOwner {
		t.Fatalf("the governed tenant's owner membership = %+v (%v), want it unchanged", mem, err)
	}
	if grants := pollAuditColumn(t, 1, `
		SELECT id FROM audit_events WHERE project_id = $1 AND event_type = $2`,
		h.ProjectID, string(audit.EventTenantAdminAdded)); len(grants) != 1 {
		t.Fatalf("tenant_admin_added records = %d, want only the first grant's", len(grants))
	}

	// The credential adds a person of the project as a member, once, and
	// never lowers the role of someone already in the tenant.
	memberAddr := fmt.Sprintf("operator-member-%d@example.com", unique)
	memberSignup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: memberAddr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(member): %v", err)
	}
	verifyMailedEmail(t, h, h.Client, memberAddr)
	memberID := memberSignup.Msg.GetUser().GetId()
	joined, err := operator.AdminAddTenantMember(ctx, connect.NewRequest(&identitypb.AdminAddTenantMemberRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: memberID,
	}))
	if err != nil {
		t.Fatalf("AdminAddTenantMember with the credential: %v", err)
	}
	if m := joined.Msg.GetMembership(); m.GetUserId() != memberID || m.GetRole() != service.RoleMember || m.GetStatus() != service.MembershipStatusActive {
		t.Fatalf("AdminAddTenantMember membership = %+v, want %s as an active member", m, memberID)
	}
	rejoined, err := operator.AdminAddTenantMember(ctx, connect.NewRequest(&identitypb.AdminAddTenantMemberRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: memberID,
	}))
	if err != nil || rejoined.Msg.GetMembership().GetId() != joined.Msg.GetMembership().GetId() {
		t.Fatalf("retried AdminAddTenantMember = %+v (%v), want the same membership", rejoined, err)
	}
	kept, err := operator.AdminAddTenantMember(ctx, connect.NewRequest(&identitypb.AdminAddTenantMemberRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: ownerID,
	}))
	if err != nil || kept.Msg.GetMembership().GetRole() != service.RoleOwner {
		t.Fatalf("AdminAddTenantMember of the owner = %+v (%v), want the owner's membership unchanged", kept, err)
	}
	if actors := waitForAuditActors(t, h.ProjectID, audit.EventTenantMemberAdded, provisionedID, 1); len(actors) != 1 || actors[0] != actor {
		t.Fatalf("tenant_member_added actors = %v, want [%s] for the one addition that wrote", actors, actor)
	}

	// A tenant the credential created can be restored by it though nobody
	// governs it; the admin secret's rule is unchanged.
	bare, err := operator.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId: h.ProjectID, Name: "Acme Unstaffed",
	}))
	if err != nil {
		t.Fatalf("AdminCreateTenant(bare) with the credential: %v", err)
	}
	bareID := bare.Msg.GetTenantId()
	if _, err := operator.AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: bareID, Reason: "paused",
	})); err != nil {
		t.Fatalf("AdminSuspendTenant(bare): %v", err)
	}
	_, err = admin.AdminRestoreTenant(ctx, connect.NewRequest(&identitypb.AdminRestoreTenantRequest{
		ProjectId: h.ProjectID, TenantId: bareID, Reason: "resumed",
	}))
	requireConnectCode(t, "AdminRestoreTenant of an ungoverned tenant with the secret", err, connect.CodeFailedPrecondition)
	unpaused, err := operator.AdminRestoreTenant(ctx, connect.NewRequest(&identitypb.AdminRestoreTenantRequest{
		ProjectId: h.ProjectID, TenantId: bareID, Reason: "resumed",
	}))
	if err != nil || unpaused.Msg.GetTenant().GetStatus() != service.TenantStatusClaimed {
		t.Fatalf("AdminRestoreTenant of the tenant the credential created = %+v (%v), want claimed", unpaused, err)
	}
	if actors := waitForAuditActors(t, h.ProjectID, audit.EventTenantRestored, bareID, 1); len(actors) != 1 || actors[0] != actor {
		t.Fatalf("tenant_restored actors = %v, want [%s]", actors, actor)
	}

	other, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name: "Another Project", StorageScopeId: fmt.Sprintf("operator-other-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	otherProjectID := other.Msg.GetProjectId()
	otherTenant, err := admin.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId: otherProjectID, Name: "Other Tenant", PrimaryDomain: fmt.Sprintf("other-%d.example", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateTenant in another project with the secret: %v", err)
	}
	_, err = operator.AdminListTenants(ctx, connect.NewRequest(&identitypb.AdminListTenantsRequest{
		ProjectId: otherProjectID,
	}))
	requireConnectCode(t, "AdminListTenants of another project", err, connect.CodePermissionDenied)
	_, err = operator.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId: otherProjectID, Name: "Not Mine", PrimaryDomain: fmt.Sprintf("not-mine-%d.example", unique),
	}))
	requireConnectCode(t, "AdminCreateTenant in another project", err, connect.CodePermissionDenied)
	_, err = operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: otherProjectID, TenantId: otherTenant.Msg.GetTenantId(), UserId: ownerID,
	}))
	requireConnectCode(t, "AdminAddTenantAdmin in another project", err, connect.CodePermissionDenied)
	_, err = operator.AdminAddTenantMember(ctx, connect.NewRequest(&identitypb.AdminAddTenantMemberRequest{
		ProjectId: otherProjectID, TenantId: otherTenant.Msg.GetTenantId(), UserId: memberID,
	}))
	requireConnectCode(t, "AdminAddTenantMember in another project", err, connect.CodePermissionDenied)
	_, err = operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: otherTenant.Msg.GetTenantId(), UserId: ownerID,
	}))
	requireConnectCode(t, "AdminAddTenantAdmin naming another project's tenant", err, connect.CodeNotFound)
	if m, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, otherTenant.Msg.GetTenantId(), ownerID); err != nil || m != nil {
		t.Fatalf("a refused grant wrote %+v (%v)", m, err)
	}

	_, err = operator.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: h.ProjectID, Kind: service.CredentialKindTenantOperator,
	}))
	requireConnectCode(t, "AdminCreateProjectCredential with the credential", err, connect.CodePermissionDenied)
	_, err = operator.DeleteLoginPolicy(ctx, connect.NewRequest(&identitypb.DeleteLoginPolicyRequest{
		ProjectId: h.ProjectID, TenantId: tenantID,
	}))
	requireConnectCode(t, "DeleteLoginPolicy with the credential", err, connect.CodePermissionDenied)

	if _, err := admin.AdminRevokeProjectCredential(ctx, connect.NewRequest(&identitypb.AdminRevokeProjectCredentialRequest{
		ProjectId: h.ProjectID, CredentialId: minted.Msg.GetCredentialId(),
	})); err != nil {
		t.Fatalf("AdminRevokeProjectCredential: %v", err)
	}
	_, err = operator.AdminGetTenant(ctx, connect.NewRequest(&identitypb.AdminGetTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID,
	}))
	requireConnectCode(t, "AdminGetTenant with a revoked credential", err, connect.CodePermissionDenied)
	_, err = operator.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId: h.ProjectID, Name: "After Revocation", PrimaryDomain: fmt.Sprintf("revoked-%d.example", unique),
	}))
	requireConnectCode(t, "AdminCreateTenant with a revoked credential", err, connect.CodePermissionDenied)
	_, err = operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, UserId: ownerID, Role: service.RoleAdmin,
	}))
	requireConnectCode(t, "AdminAddTenantAdmin with a revoked credential", err, connect.CodePermissionDenied)
	_, err = operator.AdminAddTenantMember(ctx, connect.NewRequest(&identitypb.AdminAddTenantMemberRequest{
		ProjectId: h.ProjectID, TenantId: provisionedID, UserId: memberID,
	}))
	requireConnectCode(t, "AdminAddTenantMember with a revoked credential", err, connect.CodePermissionDenied)

	reasons := waitForTenantOperatorRefusals(t, h.ProjectID, actor, 8)
	want := []string{"other_project", "other_project", "other_project", "other_project", "revoked", "revoked", "revoked", "revoked"}
	if fmt.Sprint(reasons) != fmt.Sprint(want) {
		t.Fatalf("tenant_operator_refused reasons = %v, want %v", reasons, want)
	}
}

// waitForAuditActors returns the actor of every audit event of eventType that
// names tenantID in projectID, waiting up to five seconds for at least n.
func waitForAuditActors(t *testing.T, projectID string, eventType audit.EventType, tenantID string, n int) []string {
	t.Helper()
	return pollAuditColumn(t, n, `
		SELECT actor FROM audit_events
		 WHERE project_id = $1 AND event_type = $2 AND details->>'tenant_id' = $3
		 ORDER BY occurred_at_ms`, projectID, string(eventType), tenantID)
}

// waitForTenantOperatorRefusals returns the sorted reasons of every
// tenant_operator_refused event of actor in projectID, waiting up to five
// seconds for at least n.
func waitForTenantOperatorRefusals(t *testing.T, projectID, actor string, n int) []string {
	t.Helper()
	reasons := pollAuditColumn(t, n, `
		SELECT details->>'reason' FROM audit_events
		 WHERE project_id = $1 AND event_type = $2 AND actor = $3 AND success = false`,
		projectID, string(audit.EventTenantOperatorRefused), actor)
	sort.Strings(reasons)
	return reasons
}

// pollAuditColumn runs query, which selects one text column of audit_events,
// until it returns at least n rows or five seconds pass. The audit trail is
// written asynchronously, so a read straight after the call can miss it.
func pollAuditColumn(t *testing.T, n int, query string, args ...any) []string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("GATEWAY_POSTGRES_DSN"))
	if err != nil {
		t.Fatalf("connect to read the audit trail: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := conn.Query(ctx, query, args...)
		if err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		if len(out) >= n || time.Now().After(deadline) {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
}
