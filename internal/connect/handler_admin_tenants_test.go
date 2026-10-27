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

// adminTenantStore holds a project's tenants newest first, and reads, pages
// and moves them as the postgres store does; every other call is
// connectTenantStore's.
type adminTenantStore struct {
	connectTenantStore
	tenants []*service.Tenant
}

func (s *adminTenantStore) GetTenant(_ context.Context, projectID, tenantID string) (*service.Tenant, error) {
	for _, t := range s.tenants {
		if t.ProjectID == projectID && t.ID == tenantID {
			return t, nil
		}
	}
	return nil, nil
}

func (s *adminTenantStore) ListTenants(_ context.Context, q service.TenantListQuery) ([]*service.Tenant, error) {
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

// SetTenantStatus moves one of the held tenants as the postgres store does:
// only a tenant in from moves.
func (s *adminTenantStore) SetTenantStatus(_ context.Context, projectID, tenantID, from, to string) (bool, error) {
	for _, t := range s.tenants {
		if t.ProjectID == projectID && t.ID == tenantID && t.Status == from {
			t.Status = to
			t.UpdatedAtMs++
			return true, nil
		}
	}
	return false, nil
}

func startAdminTenantServer(t *testing.T) identityconnectgen.IdentityServiceClient {
	t.Helper()
	store := &adminTenantStore{tenants: []*service.Tenant{
		{ID: "t-3", ProjectID: "proj", Name: "Gamma", Status: service.TenantStatusSuspended, CreatedAtMs: 3000, UpdatedAtMs: 3500},
		{ID: "t-2", ProjectID: "proj", Name: "Beta", PrimaryDomain: "beta.example", Status: service.TenantStatusLatent, CreatedAtMs: 2000, UpdatedAtMs: 2000},
		{ID: "t-1", ProjectID: "proj", Name: "Alpha", Status: service.TenantStatusClaimed, CreatedBy: "u-1", CreatedAtMs: 1000, UpdatedAtMs: 1500},
	}}
	svc := service.NewControlPlaneAdminService(handlerAdminSecret, false, handlerSecretsKey(), &adminControlStore{}, store, &connectMembershipStore{}, nil, &adminLoginPolicyStore{}, &connectPlatformAdminStore{}, &adminDNSResolver{txt: map[string][]string{}}, nil, zap.NewNop())
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
	client := startAdminTenantServer(t)
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
	client := startAdminTenantServer(t)
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
	client := startAdminTenantServer(t)
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

func TestAdminTenantStatus_NilService_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)
	ctx := context.Background()

	_, err := client.AdminSuspendTenant(ctx, withAdminSecret(&identitypb.AdminSuspendTenantRequest{ProjectId: "proj", TenantId: "t-1", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.AdminRestoreTenant(ctx, withAdminSecret(&identitypb.AdminRestoreTenantRequest{ProjectId: "proj", TenantId: "t-1", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
}

func TestAdminTenantStatus_BadSecret_Denied(t *testing.T) {
	t.Parallel()
	client := startAdminTenantServer(t)
	ctx := context.Background()

	for _, secret := range []string{"", "wrong"} {
		_, err := client.AdminSuspendTenant(ctx, withAdminSecret(&identitypb.AdminSuspendTenantRequest{ProjectId: "proj", TenantId: "t-1", Reason: "why"}, secret))
		requireCode(t, err, connect.CodePermissionDenied)
		_, err = client.AdminRestoreTenant(ctx, withAdminSecret(&identitypb.AdminRestoreTenantRequest{ProjectId: "proj", TenantId: "t-3", Reason: "why"}, secret))
		requireCode(t, err, connect.CodePermissionDenied)
	}
}

func TestAdminTenantStatus_Handler(t *testing.T) {
	t.Parallel()
	client := startAdminTenantServer(t)
	ctx := context.Background()

	suspended, err := client.AdminSuspendTenant(ctx, withAdminSecret(&identitypb.AdminSuspendTenantRequest{ProjectId: "proj", TenantId: "t-1", Reason: "why"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminSuspendTenant: %v", err)
	}
	if got := suspended.Msg.GetTenant(); got.GetId() != "t-1" || got.GetStatus() != service.TenantStatusSuspended || got.GetName() != "Alpha" {
		t.Fatalf("suspended tenant = %+v", got)
	}

	restored, err := client.AdminRestoreTenant(ctx, withAdminSecret(&identitypb.AdminRestoreTenantRequest{ProjectId: "proj", TenantId: "t-1", Reason: "why"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminRestoreTenant: %v", err)
	}
	if got := restored.Msg.GetTenant(); got.GetStatus() != service.TenantStatusClaimed {
		t.Fatalf("restored tenant = %+v", got)
	}

	// t-2 is latent: neither change applies to it.
	_, err = client.AdminSuspendTenant(ctx, withAdminSecret(&identitypb.AdminSuspendTenantRequest{ProjectId: "proj", TenantId: "t-2", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeFailedPrecondition)
	_, err = client.AdminRestoreTenant(ctx, withAdminSecret(&identitypb.AdminRestoreTenantRequest{ProjectId: "proj", TenantId: "t-2", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeFailedPrecondition)

	_, err = client.AdminSuspendTenant(ctx, withAdminSecret(&identitypb.AdminSuspendTenantRequest{ProjectId: "proj", TenantId: "t-9", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeNotFound)
	_, err = client.AdminSuspendTenant(ctx, withAdminSecret(&identitypb.AdminSuspendTenantRequest{ProjectId: "proj", TenantId: "t-1"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeInvalidArgument)
	_, err = client.AdminRestoreTenant(ctx, withAdminSecret(&identitypb.AdminRestoreTenantRequest{ProjectId: "proj", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeInvalidArgument)
}

func TestAdminRecoverTenantOwnership_NilService_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)

	_, err := client.AdminRecoverTenantOwnership(context.Background(), withAdminSecret(&identitypb.AdminRecoverTenantOwnershipRequest{ProjectId: "proj", TenantId: "t-1", UserId: "heir", Reason: "why"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
}

func TestAdminRecoverTenantOwnership_Handler(t *testing.T) {
	t.Parallel()
	store := &adminTenantStore{tenants: []*service.Tenant{
		{ID: "t-1", ProjectID: testProjectID, Status: service.TenantStatusClaimed},
		{ID: "t-2", ProjectID: testProjectID, Status: service.TenantStatusLatent},
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"heir":       {ID: "heir", Email: "heir@example.test", Status: service.StatusActive, EmailVerified: true},
		"unverified": {ID: "unverified", Email: "u@example.test", Status: service.StatusActive},
	}}
	svc := service.NewControlPlaneAdminService(handlerAdminSecret, false, handlerSecretsKey(), &adminControlStore{}, store, &connectMembershipStore{}, users, &adminLoginPolicyStore{}, &connectPlatformAdminStore{}, &adminDNSResolver{txt: map[string][]string{}}, nil, zap.NewNop())
	client := startAdminServer(t, svc)
	ctx := context.Background()
	appoint := func(secret, tenantID, userID, reason string) (*connect.Response[identitypb.AdminRecoverTenantOwnershipResponse], error) {
		return client.AdminRecoverTenantOwnership(ctx, withAdminSecret(&identitypb.AdminRecoverTenantOwnershipRequest{
			ProjectId: testProjectID, TenantId: tenantID, UserId: userID, Reason: reason,
		}, secret))
	}

	resp, err := appoint(handlerAdminSecret, "t-1", "heir", "the owner left")
	if err != nil {
		t.Fatalf("AdminRecoverTenantOwnership: %v", err)
	}
	if m := resp.Msg.GetMembership(); m.GetUserId() != "heir" || m.GetTenantId() != "t-1" || m.GetRole() != service.RoleOwner {
		t.Fatalf("membership = %+v", m)
	}

	_, err = appoint("wrong", "t-1", "heir", "why")
	requireCode(t, err, connect.CodePermissionDenied)
	_, err = appoint(handlerAdminSecret, "t-1", "heir", "")
	requireCode(t, err, connect.CodeInvalidArgument)
	_, err = appoint(handlerAdminSecret, "t-1", "nobody", "why")
	requireCode(t, err, connect.CodeNotFound)
	_, err = appoint(handlerAdminSecret, "t-1", "unverified", "why")
	requireCode(t, err, connect.CodeFailedPrecondition)
	_, err = appoint(handlerAdminSecret, "t-2", "heir", "why")
	requireCode(t, err, connect.CodeFailedPrecondition)
}
