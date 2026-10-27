package connect

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
)

// listedTenantStore holds a project's tenants newest first and pages them as
// the postgres store does; every other read is connectTenantStore's.
type listedTenantStore struct {
	connectTenantStore
	tenants []*service.Tenant
}

func (s *listedTenantStore) GetTenant(_ context.Context, projectID, tenantID string) (*service.Tenant, error) {
	for _, t := range s.tenants {
		if t.ProjectID == projectID && t.ID == tenantID {
			return t, nil
		}
	}
	return nil, nil
}

func (s *listedTenantStore) ListTenants(_ context.Context, q service.TenantListQuery) ([]*service.Tenant, error) {
	var out []*service.Tenant
	for _, t := range s.tenants {
		if t.ProjectID != q.ProjectID {
			continue
		}
		if a := q.After; a != nil && (t.CreatedAtMs > a.CreatedAtMs || (t.CreatedAtMs == a.CreatedAtMs && t.ID >= a.ID)) {
			continue
		}
		out = append(out, t)
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func startTenantReadServer(t *testing.T) identityconnectgen.IdentityServiceClient {
	t.Helper()
	store := &listedTenantStore{tenants: []*service.Tenant{
		{ID: "t-3", ProjectID: "proj", Name: "Gamma", Status: service.TenantStatusSuspended, CreatedAtMs: 3000, UpdatedAtMs: 3500},
		{ID: "t-2", ProjectID: "proj", Name: "Beta", PrimaryDomain: "beta.example", Status: service.TenantStatusLatent, CreatedAtMs: 2000, UpdatedAtMs: 2000},
		{ID: "t-1", ProjectID: "proj", Name: "Alpha", Status: service.TenantStatusClaimed, CreatedBy: "u-1", CreatedAtMs: 1000, UpdatedAtMs: 1500},
	}}
	svc := service.NewControlPlaneAdminService(handlerAdminSecret, false, handlerSecretsKey(), &adminControlStore{}, store, &connectMembershipStore{}, &adminLoginPolicyStore{}, &connectPlatformAdminStore{}, &adminDNSResolver{txt: map[string][]string{}}, nil, zap.NewNop())
	return startAdminServer(t, svc)
}

func TestAdminTenantReads_NilService_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)
	ctx := context.Background()

	_, err := client.AdminGetTenant(ctx, withAdminSecret(&identitypb.AdminGetTenantRequest{ProjectId: "proj", TenantId: "t-1"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.AdminListTenants(ctx, withAdminSecret(&identitypb.AdminListTenantsRequest{ProjectId: "proj"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
}

func TestAdminTenantReads_BadSecret_Denied(t *testing.T) {
	t.Parallel()
	client := startTenantReadServer(t)
	ctx := context.Background()

	for _, secret := range []string{"", "wrong"} {
		_, err := client.AdminGetTenant(ctx, withAdminSecret(&identitypb.AdminGetTenantRequest{ProjectId: "proj", TenantId: "t-1"}, secret))
		requireCode(t, err, connect.CodePermissionDenied)
		_, err = client.AdminListTenants(ctx, withAdminSecret(&identitypb.AdminListTenantsRequest{ProjectId: "proj"}, secret))
		requireCode(t, err, connect.CodePermissionDenied)
	}
}

func TestAdminGetTenant_Handler(t *testing.T) {
	t.Parallel()
	client := startTenantReadServer(t)
	ctx := context.Background()

	resp, err := client.AdminGetTenant(ctx, withAdminSecret(&identitypb.AdminGetTenantRequest{ProjectId: "proj", TenantId: "t-1"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminGetTenant: %v", err)
	}
	got := resp.Msg.GetTenant()
	if got.GetId() != "t-1" || got.GetName() != "Alpha" || got.GetStatus() != service.TenantStatusClaimed || got.GetCreatedBy() != "u-1" {
		t.Fatalf("tenant = %+v", got)
	}
	if got.GetCreatedAt().AsTime().UnixMilli() != 1000 || got.GetUpdatedAt().AsTime().UnixMilli() != 1500 {
		t.Fatalf("timestamps = %v / %v, want 1000ms / 1500ms", got.GetCreatedAt(), got.GetUpdatedAt())
	}

	_, err = client.AdminGetTenant(ctx, withAdminSecret(&identitypb.AdminGetTenantRequest{ProjectId: "proj", TenantId: "t-9"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeNotFound)
	_, err = client.AdminGetTenant(ctx, withAdminSecret(&identitypb.AdminGetTenantRequest{ProjectId: "proj"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeInvalidArgument)
}

func TestAdminListTenants_Handler(t *testing.T) {
	t.Parallel()
	client := startTenantReadServer(t)
	ctx := context.Background()

	first, err := client.AdminListTenants(ctx, withAdminSecret(&identitypb.AdminListTenantsRequest{ProjectId: "proj", Limit: 2}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminListTenants: %v", err)
	}
	if ids := protoTenantIDs(first.Msg.GetTenants()); ids != "[t-3 t-2]" || first.Msg.GetNextCursor() == "" {
		t.Fatalf("first page = %s cursor %q, want [t-3 t-2] and a cursor", ids, first.Msg.GetNextCursor())
	}
	if d := first.Msg.GetTenants()[1].GetPrimaryDomain(); d != "beta.example" {
		t.Fatalf("primary_domain = %q, want beta.example", d)
	}

	second, err := client.AdminListTenants(ctx, withAdminSecret(&identitypb.AdminListTenantsRequest{ProjectId: "proj", Limit: 2, Cursor: first.Msg.GetNextCursor()}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminListTenants page 2: %v", err)
	}
	if ids := protoTenantIDs(second.Msg.GetTenants()); ids != "[t-1]" || second.Msg.GetNextCursor() != "" {
		t.Fatalf("second page = %s cursor %q, want [t-1] and no cursor", ids, second.Msg.GetNextCursor())
	}

	_, err = client.AdminListTenants(ctx, withAdminSecret(&identitypb.AdminListTenantsRequest{ProjectId: "proj", Cursor: "%%%"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeInvalidArgument)
	_, err = client.AdminListTenants(ctx, withAdminSecret(&identitypb.AdminListTenantsRequest{}, handlerAdminSecret))
	requireCode(t, err, connect.CodeInvalidArgument)
}

func protoTenantIDs(ts []*identitypb.Tenant) string {
	ids := make([]string, 0, len(ts))
	for _, t := range ts {
		ids = append(ids, t.GetId())
	}
	return "[" + strings.Join(ids, " ") + "]"
}
