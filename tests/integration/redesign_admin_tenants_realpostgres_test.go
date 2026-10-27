//go:build integration && realpostgres

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// TestRedesign_AdminTenantReads drives an operator's reads of a project's
// tenants over the wire against a real Postgres: AdminListTenants pages
// through every tenant of the project, whatever its status, newest first,
// and AdminGetTenant reads one, refusing another project's tenant.
func TestRedesign_AdminTenantReads(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	projResp, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "Tenant Reads",
		StorageScopeId: fmt.Sprintf("tenant-reads-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := projResp.Msg.GetProjectId()

	// Three operator-created (claimed) tenants and one auto-formed (latent)
	// tenant, a millisecond apart so newest first is a known order.
	var want []string
	for i := 0; i < 3; i++ {
		resp, err := admin.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
			ProjectId:     projectID,
			Name:          fmt.Sprintf("Division %d", i),
			PrimaryDomain: fmt.Sprintf("division-%d-%d.example", i, unique),
		}))
		if err != nil {
			t.Fatalf("AdminCreateTenant %d: %v", i, err)
		}
		want = append([]string{resp.Msg.GetTenantId()}, want...)
		time.Sleep(2 * time.Millisecond)
	}
	latentID, err := h.Stores.tenants.CreateTenant(ctx, &service.Tenant{
		ProjectID: projectID, Name: "latent.example", PrimaryDomain: fmt.Sprintf("latent-%d.example", unique),
		Status: service.TenantStatusLatent,
	})
	if err != nil {
		t.Fatalf("CreateTenant latent: %v", err)
	}
	want = append([]string{latentID}, want...)

	var got []string
	statuses := map[string]string{}
	cursor := ""
	for page := 0; ; page++ {
		if page > 5 {
			t.Fatal("AdminListTenants never ended")
		}
		resp, err := admin.AdminListTenants(ctx, connect.NewRequest(&identitypb.AdminListTenantsRequest{
			ProjectId: projectID, Limit: 3, Cursor: cursor,
		}))
		if err != nil {
			t.Fatalf("AdminListTenants page %d: %v", page, err)
		}
		for _, tn := range resp.Msg.GetTenants() {
			got = append(got, tn.GetId())
			statuses[tn.GetId()] = tn.GetStatus()
		}
		if cursor = resp.Msg.GetNextCursor(); cursor == "" {
			break
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("AdminListTenants = %v, want %v", got, want)
	}
	if statuses[latentID] != service.TenantStatusLatent || statuses[want[1]] != service.TenantStatusClaimed {
		t.Fatalf("statuses = %v, want the latent tenant listed with the claimed ones", statuses)
	}

	getResp, err := admin.AdminGetTenant(ctx, connect.NewRequest(&identitypb.AdminGetTenantRequest{
		ProjectId: projectID, TenantId: want[3],
	}))
	if err != nil {
		t.Fatalf("AdminGetTenant: %v", err)
	}
	if tn := getResp.Msg.GetTenant(); tn.GetName() != "Division 0" || tn.GetStatus() != service.TenantStatusClaimed || tn.GetCreatedAt() == nil {
		t.Fatalf("AdminGetTenant = %+v", tn)
	}

	_, err = admin.AdminGetTenant(ctx, connect.NewRequest(&identitypb.AdminGetTenantRequest{
		ProjectId: h.ProjectID, TenantId: want[3],
	}))
	requireConnectCode(t, "AdminGetTenant from another project", err, connect.CodeNotFound)
	_, err = admin.AdminListTenants(ctx, connect.NewRequest(&identitypb.AdminListTenantsRequest{
		ProjectId: projectID, Cursor: "not-a-cursor!",
	}))
	requireConnectCode(t, "AdminListTenants with a malformed cursor", err, connect.CodeInvalidArgument)
	_, err = h.adminClient("wrong-secret").AdminListTenants(ctx, connect.NewRequest(&identitypb.AdminListTenantsRequest{
		ProjectId: projectID,
	}))
	requireConnectCode(t, "AdminListTenants with a wrong secret", err, connect.CodePermissionDenied)
}

// TestRedesign_AdminTenantSuspension drives an operator suspending and
// restoring a tenant over the wire against a real Postgres: suspension ends
// a token that chose the tenant at its next request, refuses a new
// selection and stops the tenant's owner administering it; restoring gives
// all three back; asking for the status a tenant already has changes
// nothing; a latent tenant cannot be suspended; and each change is audited
// once with the operator's reason.
func TestRedesign_AdminTenantSuspension(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	addr := fmt.Sprintf("suspend-owner-%d@example.com", unique)
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	verifyMailedEmail(t, h, h.Client, addr)
	owner := h.AuthedClient(signup.Msg.GetAccessToken())
	created, err := owner.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Acme Suspended"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()
	selected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: signup.Msg.GetRefreshToken(), TenantId: tenantID,
	}))
	if err != nil {
		t.Fatalf("RefreshToken selecting the tenant: %v", err)
	}
	inTenant := h.AuthedClient(selected.Msg.GetAccessToken())

	_, err = h.adminClient("wrong-secret").AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "billing dispute",
	}))
	requireConnectCode(t, "AdminSuspendTenant with a wrong secret", err, connect.CodePermissionDenied)
	_, err = admin.AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID,
	}))
	requireConnectCode(t, "AdminSuspendTenant with no reason", err, connect.CodeInvalidArgument)

	suspended, err := admin.AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "billing dispute",
	}))
	if err != nil {
		t.Fatalf("AdminSuspendTenant: %v", err)
	}
	if tn := suspended.Msg.GetTenant(); tn.GetId() != tenantID || tn.GetStatus() != service.TenantStatusSuspended {
		t.Fatalf("AdminSuspendTenant = %+v, want %s suspended", tn, tenantID)
	}
	again, err := admin.AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "retried",
	}))
	if err != nil {
		t.Fatalf("AdminSuspendTenant again: %v", err)
	}
	if !again.Msg.GetTenant().GetUpdatedAt().AsTime().Equal(suspended.Msg.GetTenant().GetUpdatedAt().AsTime()) {
		t.Fatal("suspending a suspended tenant changed it")
	}

	_, err = inTenant.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	requireConnectCode(t, "a suspended tenant's token", err, connect.CodeUnauthenticated)
	_, err = h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: selected.Msg.GetRefreshToken(), TenantId: tenantID,
	}))
	requireConnectCode(t, "selecting a suspended tenant", err, connect.CodePermissionDenied)
	_, err = owner.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: fmt.Sprintf("colleague-%d@example.com", unique), Role: service.RoleMember,
	}))
	requireConnectCode(t, "inviting into a suspended tenant", err, connect.CodePermissionDenied)

	restored, err := admin.AdminRestoreTenant(ctx, connect.NewRequest(&identitypb.AdminRestoreTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "dispute settled",
	}))
	if err != nil {
		t.Fatalf("AdminRestoreTenant: %v", err)
	}
	if tn := restored.Msg.GetTenant(); tn.GetStatus() != service.TenantStatusClaimed {
		t.Fatalf("AdminRestoreTenant = %+v, want claimed", tn)
	}
	if _, err := admin.AdminRestoreTenant(ctx, connect.NewRequest(&identitypb.AdminRestoreTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "retried",
	})); err != nil {
		t.Fatalf("restoring a claimed tenant: %v", err)
	}

	reselected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: selected.Msg.GetRefreshToken(), TenantId: tenantID,
	}))
	if err != nil {
		t.Fatalf("selecting the restored tenant: %v", err)
	}
	if got := decodeTokenTenantClaim(t, reselected.Msg.GetAccessToken()); got != tenantID {
		t.Fatalf("restored selection's tenant claim = %q, want %q", got, tenantID)
	}
	if _, err := h.AuthedClient(reselected.Msg.GetAccessToken()).ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{})); err != nil {
		t.Fatalf("an authenticated RPC with the restored tenant's token: %v", err)
	}
	if _, err := owner.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: fmt.Sprintf("colleague-%d@example.com", unique), Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("inviting into the restored tenant: %v", err)
	}

	latentID, err := h.Stores.tenants.CreateTenant(ctx, &service.Tenant{
		ProjectID: h.ProjectID, Name: "latent.example", PrimaryDomain: fmt.Sprintf("latent-%d.example", unique),
		Status: service.TenantStatusLatent,
	})
	if err != nil {
		t.Fatalf("CreateTenant latent: %v", err)
	}
	_, err = admin.AdminSuspendTenant(ctx, connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: latentID, Reason: "billing dispute",
	}))
	requireConnectCode(t, "suspending a latent tenant", err, connect.CodeFailedPrecondition)

	for event, reason := range map[audit.EventType]string{
		audit.EventTenantSuspended: "billing dispute",
		audit.EventTenantRestored:  "dispute settled",
	} {
		details := waitForTenantAuditEvents(t, h.ProjectID, tenantID, event)
		if len(details) != 1 || details[0]["reason"] != reason || details[0]["project_id"] != h.ProjectID {
			t.Fatalf("%s events = %v, want one with reason %q", event, details, reason)
		}
	}
}

// waitForTenantAuditEvents returns the details of every audit event of
// eventType that names tenantID in projectID, waiting for the first to be
// written. It reads the table: an operator's change has no user to look the
// events up by.
func waitForTenantAuditEvents(t *testing.T, projectID, tenantID string, eventType audit.EventType) []map[string]any {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("GATEWAY_POSTGRES_DSN"))
	if err != nil {
		t.Fatalf("connect to read the audit trail: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := conn.Query(ctx, `
			SELECT details FROM audit_events
			 WHERE project_id = $1 AND details->>'tenant_id' = $2
			   AND event_type = $3
			 ORDER BY occurred_at_ms`, projectID, tenantID, string(eventType))
		if err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		var out []map[string]any
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				t.Fatalf("scan an audit event: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("decode an audit event: %v", err)
			}
			out = append(out, m)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		if len(out) > 0 || time.Now().After(deadline) {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
}
