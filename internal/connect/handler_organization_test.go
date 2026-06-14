package connect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// orgSignupServer wires an IdentityHandler into a Connect test server
// configured for either single or multi mode. multi mode shares a
// process-local fake TenantAdmin + per-tenant repo registry so the
// test can assert on what was written.
type orgSignupServer struct {
	client identityconnectgen.IdentityServiceClient
	server *httptest.Server
	cfg    *config.Config
}

func (s *orgSignupServer) Close() { s.server.Close() }

// ── single-mode test fixture: orgSignupSvc is nil; handler must
// return CodeUnimplemented without touching the service layer.

func startSingleModeServer(t *testing.T) *orgSignupServer {
	t.Helper()
	cfg := testConfig()
	cfg.IdentityMode = config.IdentityModeSingle
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, cfg)
	return startOrgSignupServer(t, h, cfg)
}

func startMultiModeServer(t *testing.T) *orgSignupServer {
	t.Helper()
	cfg := testConfig()
	cfg.IdentityMode = config.IdentityModeMulti

	admin := &connectFakeTenantAdmin{
		tenants:     map[string]string{},
		memberships: map[string]string{},
	}
	repos := &connectTenantRepoRegistry{byTenant: map[string]service.Repository{}}
	auditLog := audit.NewLogger(nil, "test", zap.NewNop())
	keyRing := testKeyRing(t)

	orgSvc := service.NewOrganizationSignupService(admin, repos.factory(), cfg, keyRing, auditLog, zap.NewNop())
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, orgSvc, nil, nil, cfg)
	srv := startOrgSignupServer(t, h, cfg)
	srv.cfg = cfg
	return srv
}

func startOrgSignupServer(t *testing.T, h *IdentityHandler, cfg *config.Config) *orgSignupServer {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)
	return &orgSignupServer{client: client, server: srv, cfg: cfg}
}

func TestOrganizationSignup_SingleMode_ReturnsUnimplemented(t *testing.T) {
	t.Parallel()
	srv := startSingleModeServer(t)

	req := connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          "acmecorp",
		DisplayName:   "Acme Corp",
		AdminEmail:    "owner@acme.example.com",
		AdminPassword: "MyStr0ng!Pass",
		AdminName:     "Owner",
	})
	_, err := srv.client.OrganizationSignup(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error in single mode, got nil")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	if connectErr.Code() != connect.CodeUnimplemented {
		t.Fatalf("expected CodeUnimplemented, got %v: %v", connectErr.Code(), err)
	}
}

func TestOrganizationSignup_MultiMode_NilService_ReturnsUnimplemented(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IdentityMode = config.IdentityModeMulti
	// Multi-mode config but nil orgSignup wiring (e.g. boot guard didn't run).
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, cfg)
	srv := startOrgSignupServer(t, h, cfg)

	req := connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          "acmecorp",
		DisplayName:   "Acme Corp",
		AdminEmail:    "owner@acme.example.com",
		AdminPassword: "MyStr0ng!Pass",
		AdminName:     "Owner",
	})
	_, err := srv.client.OrganizationSignup(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	if connectErr.Code() != connect.CodeUnimplemented {
		t.Fatalf("expected CodeUnimplemented when orgSignup is nil, got %v", connectErr.Code())
	}
}

func TestOrganizationSignup_MultiMode_HappyPath(t *testing.T) {
	t.Parallel()
	srv := startMultiModeServer(t)

	req := connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          "acmecorp",
		DisplayName:   "Acme Corp",
		AdminEmail:    "owner@acme.example.com",
		AdminPassword: "MyStr0ng!Pass",
		AdminName:     "Owner",
	})
	resp, err := srv.client.OrganizationSignup(context.Background(), req)
	if err != nil {
		t.Fatalf("OrganizationSignup: %v", err)
	}
	if resp.Msg.Organization == nil || resp.Msg.Organization.Slug != "acmecorp" {
		t.Fatalf("expected organization 'acmecorp', got %#v", resp.Msg.Organization)
	}
	if resp.Msg.AdminUser == nil || resp.Msg.AdminUser.Email != "owner@acme.example.com" {
		t.Fatalf("expected admin user 'owner@acme.test', got %#v", resp.Msg.AdminUser)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatalf("expected tokens, got access=%q refresh=%q", resp.Msg.AccessToken, resp.Msg.RefreshToken)
	}
}

func TestOrganizationSignup_MultiMode_InvalidSlug_ReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	srv := startMultiModeServer(t)

	req := connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          "BAD SLUG!",
		DisplayName:   "Acme",
		AdminEmail:    "owner@acme.example.com",
		AdminPassword: "MyStr0ng!Pass",
	})
	_, err := srv.client.OrganizationSignup(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for invalid slug")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Fatalf("expected CodeInvalidArgument, got %v", connectErr.Code())
	}
}

// ── Local in-package fakes shared across the connect-layer tests for
// the OrganizationSignup wiring. They are intentionally separate from
// the service-package fakes because the connect tests live in the
// `connect` package and cannot import `service`'s test files.

type connectFakeTenantAdmin struct {
	tenants     map[string]string
	memberships map[string]string
}

func (a *connectFakeTenantAdmin) CreateTenant(_ context.Context, tenantID, displayName string) error {
	if _, ok := a.tenants[tenantID]; ok {
		return service.ErrAlreadyExists
	}
	a.tenants[tenantID] = displayName
	return nil
}

func (a *connectFakeTenantAdmin) PromoteTenantMember(_ context.Context, tenantID, userID, role string) error {
	a.memberships[tenantID+"|"+userID] = role
	return nil
}

func (a *connectFakeTenantAdmin) RemoveTenantMember(_ context.Context, tenantID, userID string) error {
	delete(a.memberships, tenantID+"|"+userID)
	return nil
}

type connectTenantRepoRegistry struct {
	byTenant map[string]service.Repository
}

func (r *connectTenantRepoRegistry) factory() service.RepositoryForTenant {
	return func(tenantID string) service.Repository {
		if existing, ok := r.byTenant[tenantID]; ok {
			return existing
		}
		repo := newFakeRepo()
		r.byTenant[tenantID] = repo
		return repo
	}
}
