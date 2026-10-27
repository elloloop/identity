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
