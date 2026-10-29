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
// reads, lists, suspends and restores its own project's tenants and reads
// their login policy, and its changes name it as their actor. It is refused
// another project's tenants and every operator call outside the six, and a
// revocation holds from the next call. The refusals of the credential are
// recorded under its project with their reasons.
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

	other, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name: "Another Project", StorageScopeId: fmt.Sprintf("operator-other-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	_, err = operator.AdminListTenants(ctx, connect.NewRequest(&identitypb.AdminListTenantsRequest{
		ProjectId: other.Msg.GetProjectId(),
	}))
	requireConnectCode(t, "AdminListTenants of another project", err, connect.CodePermissionDenied)

	_, err = operator.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId: h.ProjectID, Name: "Not Mine", PrimaryDomain: fmt.Sprintf("not-mine-%d.example", unique),
	}))
	requireConnectCode(t, "AdminCreateTenant with the credential", err, connect.CodePermissionDenied)
	_, err = operator.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: h.ProjectID, Kind: service.CredentialKindTenantOperator,
	}))
	requireConnectCode(t, "AdminCreateProjectCredential with the credential", err, connect.CodePermissionDenied)
	_, err = operator.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, UserId: signup.Msg.GetUser().GetId(),
	}))
	requireConnectCode(t, "AdminAddTenantAdmin with the credential", err, connect.CodePermissionDenied)
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

	reasons := waitForTenantOperatorRefusals(t, h.ProjectID, actor, 2)
	if want := []string{"other_project", "revoked"}; fmt.Sprint(reasons) != fmt.Sprint(want) {
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
