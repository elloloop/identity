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
)

const authUserHeader = "X-Authenticated-User-Id"

// ── Fakes implementing the exported governance store interfaces ─────────

type connectDomainStore struct {
	byID     map[string]*service.Domain
	listResp []*service.Domain
}

func newConnectDomainStore() *connectDomainStore {
	return &connectDomainStore{byID: map[string]*service.Domain{}}
}

func (s *connectDomainStore) CreateDomain(_ context.Context, d *service.Domain) (string, error) {
	d.ID = "dom-1"
	cp := *d
	s.byID[d.ID] = &cp
	return d.ID, nil
}

func (s *connectDomainStore) GetDomain(_ context.Context, _, domainID string) (*service.Domain, error) {
	return s.byID[domainID], nil
}

func (s *connectDomainStore) GetDomainByName(_ context.Context, _, _ string) (*service.Domain, error) {
	return nil, nil
}

func (s *connectDomainStore) SetDomainStatus(_ context.Context, _, domainID, status string, _ int64) error {
	if d, ok := s.byID[domainID]; ok {
		d.Status = status
	}
	return nil
}

func (s *connectDomainStore) ListDomainsByTenant(_ context.Context, _, _ string) ([]*service.Domain, error) {
	return s.listResp, nil
}

type connectTenantStore struct {
	tenant *service.Tenant
}

func (s *connectTenantStore) CreateTenant(context.Context, *service.Tenant) (string, error) {
	return "", nil
}

func (s *connectTenantStore) GetTenant(_ context.Context, _, _ string) (*service.Tenant, error) {
	return s.tenant, nil
}

func (s *connectTenantStore) GetTenantByPrimaryDomain(context.Context, string, string) (*service.Tenant, error) {
	return nil, nil
}

func (s *connectTenantStore) SetTenantStatus(_ context.Context, _, _, status string) error {
	if s.tenant != nil {
		s.tenant.Status = status
	}
	return nil
}

func (s *connectTenantStore) ListTenants(context.Context, string) ([]*service.Tenant, error) {
	return nil, nil
}

type connectMembershipStore struct {
	member   *service.TenantMembership
	upserted *service.TenantMembership
}

func (s *connectMembershipStore) UpsertMembership(_ context.Context, m *service.TenantMembership) (string, error) {
	cp := *m
	s.upserted = &cp
	return "mem-1", nil
}

func (s *connectMembershipStore) GetMembership(_ context.Context, _, _, _ string) (*service.TenantMembership, error) {
	return s.member, nil
}

func (s *connectMembershipStore) ListMembershipsForUser(context.Context, string, string) ([]*service.TenantMembership, error) {
	return nil, nil
}

func (s *connectMembershipStore) ListMembershipsForTenant(context.Context, string, string) ([]*service.TenantMembership, error) {
	return nil, nil
}

func (s *connectMembershipStore) RemoveMembership(context.Context, string, string, string) error {
	return nil
}

// connectFakeResolver satisfies the service package's DNSResolver
// parameter of NewDomainService. Its record set
// is mutable so a test can publish the exact challenge it received back
// from CreateDomain before calling VerifyDomain.
type connectFakeResolver struct {
	records []string
}

func (r *connectFakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return r.records, nil
}

// ── Harness ─────────────────────────────────────────────────────────────

type domainServer struct {
	client identityconnectgen.IdentityServiceClient
}

const testProjectID = "proj-1"

func startDomainServer(t *testing.T, svc *service.DomainService) *domainServer {
	t.Helper()
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, svc, nil, nil, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	// Inject the resolved project scope on the SERVER-side request context,
	// the way the project-resolution middleware does in the real chain — it
	// does not travel over the wire from the client context.
	scoped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := service.WithProjectScope(r.Context(), &service.ProjectScope{ProjectID: testProjectID})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(scoped)
	t.Cleanup(srv.Close)
	return &domainServer{client: identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)}
}

// withAuth returns a request whose header carries the verified caller id,
// as the auth middleware would inject after verifying the JWT.
func withAuth[T any](msg *T, userID string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set(authUserHeader, userID)
	return req
}

func newDomainSvc(domains service.DomainStore, tenants service.TenantStore, members service.MembershipStore, resolver *connectFakeResolver) *service.DomainService {
	return service.NewDomainService(domains, tenants, members, resolver, &config.Config{}, zap.NewNop())
}

// ── nil service → Unimplemented ─────────────────────────────────────────

func TestDomainRPCs_NilService_ReturnUnimplemented(t *testing.T) {
	t.Parallel()
	srv := startDomainServer(t, nil)

	_, err := srv.client.CreateDomain(context.Background(),
		withAuth(&identitypb.CreateDomainRequest{TenantId: "t", Domain: "acme.com"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.VerifyDomain(context.Background(),
		withAuth(&identitypb.VerifyDomainRequest{DomainId: "d"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.ListTenantDomains(context.Background(),
		withAuth(&identitypb.ListTenantDomainsRequest{TenantId: "t"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)
}

// ── CreateDomain happy path through the handler ─────────────────────────

func TestCreateDomain_Handler_ReturnsChallenge(t *testing.T) {
	domains := newConnectDomainStore()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	svc := newDomainSvc(domains, &connectTenantStore{}, members, &connectFakeResolver{})
	srv := startDomainServer(t, svc)

	resp, err := srv.client.CreateDomain(context.Background(),
		withAuth(&identitypb.CreateDomainRequest{
			TenantId:           "tenant-1",
			Domain:             "acme.com",
			VerificationMethod: service.DomainVerificationDNSTXT,
		}, "user-1"))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if resp.Msg.Domain.GetDomain() != "acme.com" {
		t.Fatalf("domain = %q, want acme.com", resp.Msg.Domain.GetDomain())
	}
	if resp.Msg.GetDnsTxtName() != "acme.com" {
		t.Fatalf("txt name = %q, want acme.com", resp.Msg.GetDnsTxtName())
	}
	if resp.Msg.GetDnsTxtValue() == "" {
		t.Fatalf("expected a non-empty TXT challenge value")
	}
}

func TestCreateDomain_Handler_MissingAuth_Unauthenticated(t *testing.T) {
	domains := newConnectDomainStore()
	svc := newDomainSvc(domains, &connectTenantStore{}, &connectMembershipStore{}, &connectFakeResolver{})
	srv := startDomainServer(t, svc)

	// No auth header set.
	_, err := srv.client.CreateDomain(context.Background(),
		connect.NewRequest(&identitypb.CreateDomainRequest{TenantId: "t", Domain: "acme.com"}))
	requireCode(t, err, connect.CodeUnauthenticated)
}

// ── VerifyDomain happy path through the handler ─────────────────────────

func TestVerifyDomain_Handler_Success(t *testing.T) {
	domains := newConnectDomainStore()
	tenants := &connectTenantStore{tenant: &service.Tenant{
		ID: "tenant-1", ProjectID: "proj-1", Status: service.TenantStatusLatent,
	}}
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	resolver := &connectFakeResolver{}
	svc := newDomainSvc(domains, tenants, members, resolver)
	srv := startDomainServer(t, svc)

	// Round-trip the real challenge: register the domain, then publish the
	// exact TXT value the server handed back before verifying. This avoids
	// duplicating the challenge formula in the test.
	created, err := srv.client.CreateDomain(context.Background(),
		withAuth(&identitypb.CreateDomainRequest{
			TenantId: "tenant-1", Domain: "acme.com",
			VerificationMethod: service.DomainVerificationDNSTXT,
		}, "user-1"))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	resolver.records = []string{created.Msg.GetDnsTxtValue()}

	resp, err := srv.client.VerifyDomain(context.Background(),
		withAuth(&identitypb.VerifyDomainRequest{DomainId: created.Msg.Domain.GetId()}, "user-1"))
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	if resp.Msg.Domain.GetStatus() != service.DomainStatusVerified {
		t.Fatalf("status = %q, want verified", resp.Msg.Domain.GetStatus())
	}
	if members.upserted == nil || members.upserted.Role != service.RoleOwner {
		t.Fatalf("caller was not made an owner: %+v", members.upserted)
	}
	if tenants.tenant.Status != service.TenantStatusClaimed {
		t.Fatalf("tenant status = %q, want claimed", tenants.tenant.Status)
	}
}

// ── ListTenantDomains happy path ────────────────────────────────────────

func TestListTenantDomains_Handler(t *testing.T) {
	domains := newConnectDomainStore()
	domains.listResp = []*service.Domain{
		{ID: "d1", TenantID: "tenant-1", Domain: "acme.com", Status: service.DomainStatusVerified},
		{ID: "d2", TenantID: "tenant-1", Domain: "acme.io", Status: service.DomainStatusPending},
	}
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	}}
	svc := newDomainSvc(domains, &connectTenantStore{}, members, &connectFakeResolver{})
	srv := startDomainServer(t, svc)

	resp, err := srv.client.ListTenantDomains(context.Background(),
		withAuth(&identitypb.ListTenantDomainsRequest{TenantId: "tenant-1"}, "user-1"))
	if err != nil {
		t.Fatalf("ListTenantDomains: %v", err)
	}
	if len(resp.Msg.GetDomains()) != 2 {
		t.Fatalf("got %d domains, want 2", len(resp.Msg.GetDomains()))
	}
}

func requireCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", want)
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	if ce.Code() != want {
		t.Fatalf("code = %v, want %v: %v", ce.Code(), want, err)
	}
}
