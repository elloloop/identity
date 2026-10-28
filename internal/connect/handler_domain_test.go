package connect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

const authUserHeader = "X-Authenticated-User-Id"

// ── Fakes implementing the exported governance store interfaces ─────────

type connectDomainStore struct {
	byID       map[string]*service.Domain
	listResp   []*service.Domain
	attemptErr error
	// verified is what GetVerifiedDomain answers for every domain.
	verified *service.Domain
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

func (s *connectDomainStore) GetVerifiedDomain(_ context.Context, _, _ string) (*service.Domain, error) {
	return s.verified, nil
}

// RecordDomainAttempt refuses with attemptErr when set, else admits.
func (s *connectDomainStore) RecordDomainAttempt(context.Context, service.DomainAttempt) error {
	return s.attemptErr
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

func (s *connectDomainStore) SetDomainAllowJoin(_ context.Context, _, domainID string, allowJoin bool) (*service.Domain, bool, error) {
	d, ok := s.byID[domainID]
	if !ok {
		return nil, false, nil
	}
	changed := d.AllowJoin != allowJoin
	d.AllowJoin = allowJoin
	cp := *d
	return &cp, changed, nil
}

type connectTenantStore struct {
	tenant *service.Tenant
	// ownedReq records the last CreateOwnedTenant request; ownedErr fails it.
	ownedReq *service.OwnedTenantRequest
	ownedErr error
}

func (s *connectTenantStore) CreateTenant(context.Context, *service.Tenant) (string, error) {
	return "", nil
}

func (s *connectTenantStore) GetTenant(_ context.Context, _, _ string) (*service.Tenant, error) {
	return s.tenant, nil
}

// GetTenantStatus reads the one tenant the store holds as every id.
func (s *connectTenantStore) GetTenantStatus(context.Context, string, string) (string, error) {
	if s.tenant == nil {
		return "", nil
	}
	return s.tenant.Status, nil
}

// claimedTenantStore holds one claimed tenant, which every id reads as.
func claimedTenantStore() *connectTenantStore {
	return &connectTenantStore{tenant: &service.Tenant{ID: "t-1", Status: service.TenantStatusClaimed}}
}

func (s *connectTenantStore) GetTenantByPrimaryDomain(context.Context, string, string) (*service.Tenant, error) {
	return nil, nil
}

// SetTenantStatus moves the store's one tenant, which every id reads as.
func (s *connectTenantStore) SetTenantStatus(_ context.Context, _, _, from, to string) (bool, error) {
	if s.tenant == nil || s.tenant.Status != from {
		return false, nil
	}
	s.tenant.Status = to
	return true, nil
}

// ListTenants is not reached by the domain handler tests; the listing is
// covered against adminTenantStore.
func (s *connectTenantStore) ListTenants(context.Context, service.TenantListQuery) ([]*service.Tenant, error) {
	return nil, nil
}

func (s *connectTenantStore) CreateOwnedTenant(_ context.Context, req service.OwnedTenantRequest) (*service.Tenant, *service.TenantMembership, error) {
	s.ownedReq = &req
	if s.ownedErr != nil {
		return nil, nil, s.ownedErr
	}
	t := &service.Tenant{ID: "tenant-new", ProjectID: req.ProjectID, Name: req.Name, Status: service.TenantStatusClaimed, CreatedBy: req.OwnerID}
	m := &service.TenantMembership{
		ID: "mem-new", ProjectID: req.ProjectID, TenantID: t.ID, UserID: req.OwnerID,
		Source: service.MembershipSourceCreated, Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}
	return t, m, nil
}

type connectMembershipStore struct {
	member   *service.TenantMembership
	upserted *service.TenantMembership
	// active is what ListActiveTenantsForUser returns.
	active []*service.UserTenant
	// changeErr, when set, is what SuspendMembership and RestoreMembership
	// return.
	changeErr error
}

func (s *connectMembershipStore) UpsertMembership(_ context.Context, m *service.TenantMembership) (string, error) {
	cp := *m
	s.upserted = &cp
	return "mem-1", nil
}

func (s *connectMembershipStore) GrantMembership(_ context.Context, m *service.TenantMembership) (*service.TenantMembership, bool, error) {
	cp := *m
	cp.ID = "mem-1"
	s.upserted = &cp
	return &cp, true, nil
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

// RemoveMembership mirrors the postgres store's last-owner rule for the one
// membership this fake holds: an active owner is the tenant's last.
func (s *connectMembershipStore) RemoveMembership(context.Context, string, string, string) (*service.TenantMembership, error) {
	if s.member != nil && s.member.Role == service.RoleOwner && s.member.Status == service.MembershipStatusActive {
		return nil, service.ErrLastOwner
	}
	return s.member, nil
}

// JoinByDomain grants a domain member, as GrantMembership records it.
func (s *connectMembershipStore) JoinByDomain(ctx context.Context, projectID, tenantID, userID, _ string) (*service.TenantMembership, bool, error) {
	return s.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: userID,
		Source: service.MembershipSourceDomain, Role: service.RoleMember, Status: service.MembershipStatusActive,
	})
}

func (s *connectMembershipStore) IsRemoved(context.Context, string, string, string) (bool, error) {
	return false, nil
}

// SuspendMembership reports userID's invited membership as suspended, or
// changeErr.
func (s *connectMembershipStore) SuspendMembership(_ context.Context, projectID, tenantID, userID string) (*service.TenantMembership, bool, error) {
	return s.changed(projectID, tenantID, userID, service.MembershipStatusSuspended)
}

// RestoreMembership reports userID's invited membership as active again, or
// changeErr.
func (s *connectMembershipStore) RestoreMembership(_ context.Context, projectID, tenantID, userID, _ string) (*service.TenantMembership, bool, error) {
	return s.changed(projectID, tenantID, userID, service.MembershipStatusActive)
}

func (s *connectMembershipStore) changed(projectID, tenantID, userID, status string) (*service.TenantMembership, bool, error) {
	if s.changeErr != nil {
		return nil, false, s.changeErr
	}
	return &service.TenantMembership{
		ID: "mem-" + userID, ProjectID: projectID, TenantID: tenantID, UserID: userID,
		Source: service.MembershipSourceInvited, Role: service.RoleMember, Status: status,
	}, true, nil
}

// TransferOwnership reports the transfer as made: toUserID an added owner,
// fromUserID an admin.
func (s *connectMembershipStore) TransferOwnership(_ context.Context, projectID, tenantID, fromUserID, toUserID string) (*service.TenantMembership, *service.TenantMembership, error) {
	from := &service.TenantMembership{
		ID: "mem-from", ProjectID: projectID, TenantID: tenantID, UserID: fromUserID,
		Source: service.MembershipSourceCreated, Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	}
	to := &service.TenantMembership{
		ID: "mem-to", ProjectID: projectID, TenantID: tenantID, UserID: toUserID,
		Source: service.MembershipSourceAdded, Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}
	return from, to, nil
}

func (s *connectMembershipStore) ListActiveTenantsForUser(context.Context, string, string, string) ([]*service.UserTenant, error) {
	return s.active, nil
}

func (s *connectMembershipStore) GetActiveTenantForUser(_ context.Context, _, tenantID, _, _ string) (*service.UserTenant, error) {
	for _, t := range s.active {
		if t.TenantID == tenantID {
			return t, nil
		}
	}
	return nil, nil
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
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, svc, nil, nil, nil, testConfig())
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

	_, err = srv.client.SetDomainJoin(context.Background(),
		withAuth(&identitypb.SetDomainJoinRequest{DomainId: "d", AllowJoin: true}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)
}

// ── CreateDomain happy path through the handler ─────────────────────────

func TestCreateDomain_Handler_ReturnsChallenge(t *testing.T) {
	domains := newConnectDomainStore()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	svc := newDomainSvc(domains, claimedTenantStore(), members, &connectFakeResolver{})
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

	_, err = srv.client.SetDomainJoin(context.Background(),
		connect.NewRequest(&identitypb.SetDomainJoinRequest{DomainId: "d", AllowJoin: true}))
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
	svc := newDomainSvc(domains, claimedTenantStore(), members, &connectFakeResolver{})
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

// ── SetDomainJoin through the handler ───────────────────────────────────

func TestSetDomainJoin_Handler(t *testing.T) {
	t.Parallel()
	domains := newConnectDomainStore()
	domains.byID["d1"] = &service.Domain{ID: "d1", TenantID: "t-1", Domain: "acme.com", Status: service.DomainStatusVerified}
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	}}
	srv := startDomainServer(t, newDomainSvc(domains, claimedTenantStore(), members, &connectFakeResolver{}))
	ctx := context.Background()

	resp, err := srv.client.SetDomainJoin(ctx, withAuth(&identitypb.SetDomainJoinRequest{DomainId: "d1", AllowJoin: true}, "admin-1"))
	if err != nil {
		t.Fatalf("SetDomainJoin: %v", err)
	}
	if d := resp.Msg.GetDomain(); d.GetId() != "d1" || !d.GetAllowJoin() || d.GetDomain() != "acme.com" {
		t.Fatalf("domain = %+v, want d1 allowing join", d)
	}
	if !domains.byID["d1"].AllowJoin {
		t.Fatal("the setting was not stored")
	}

	_, err = srv.client.SetDomainJoin(ctx, withAuth(&identitypb.SetDomainJoinRequest{DomainId: "d-unknown", AllowJoin: true}, "admin-1"))
	requireCode(t, err, connect.CodeNotFound)
	members.member.Role = service.RoleMember
	_, err = srv.client.SetDomainJoin(ctx, withAuth(&identitypb.SetDomainJoinRequest{DomainId: "d1"}, "admin-1"))
	requireCode(t, err, connect.CodePermissionDenied)
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
