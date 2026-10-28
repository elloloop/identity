package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
)

// ── Fakes specific to the membership handler tests ───────────────────────
//
// connectTenantStore / connectMembershipStore / withAuth / requireCode are
// reused from handler_domain_test.go in this same package.

// connectInvitationStore is a minimal in-memory InvitationStore for the
// handler happy-path tests.
type connectInvitationStore struct {
	byHash   map[string]*service.TenantInvitation
	byID     map[string]*service.TenantInvitation
	listResp []*service.TenantInvitation
	nextID   int
}

func newConnectInvitationStore() *connectInvitationStore {
	return &connectInvitationStore{
		byHash: map[string]*service.TenantInvitation{},
		byID:   map[string]*service.TenantInvitation{},
	}
}

func (s *connectInvitationStore) CreateInvitation(_ context.Context, inv *service.TenantInvitation, _ service.InvitationLimits) (string, error) {
	s.nextID++
	id := "inv-1"
	cp := *inv
	cp.ID = id
	cp.Status = service.InvitationStatusPending
	s.byHash[inv.TokenHash] = &cp
	s.byID[id] = &cp
	inv.ID = id
	inv.Status = service.InvitationStatusPending
	return id, nil
}

func (s *connectInvitationStore) GetInvitationByTokenHash(_ context.Context, _, tokenHash string) (*service.TenantInvitation, error) {
	return s.byHash[tokenHash], nil
}

func (s *connectInvitationStore) SetInvitationStatus(_ context.Context, _, invitationID, status string, acceptedAtMs int64) error {
	if inv, ok := s.byID[invitationID]; ok {
		inv.Status = status
		inv.AcceptedAtMs = acceptedAtMs
	}
	return nil
}

func (s *connectInvitationStore) ListInvitationsForTenant(_ context.Context, _, _ string) ([]*service.TenantInvitation, error) {
	return s.listResp, nil
}

// connectUserDirectory resolves users by id in the scope's project, the one
// these handler tests serve; a lookup in any other project finds no one.
type connectUserDirectory struct {
	byID map[string]*service.User
}

func (d *connectUserDirectory) GetUserInProject(_ context.Context, projectID, userID string) (*service.User, error) {
	if projectID != testProjectID {
		return nil, nil
	}
	return d.byID[userID], nil
}

// ── Harness ──────────────────────────────────────────────────────────────

type membershipServer struct {
	client identityconnectgen.IdentityServiceClient
}

func startMembershipServer(t *testing.T, svc *service.MembershipService) *membershipServer {
	t.Helper()
	return startMembershipServerInScope(t, svc, &service.ProjectScope{ProjectID: testProjectID})
}

// startMembershipServerInScope serves svc with scope as the resolved project.
func startMembershipServerInScope(t *testing.T, svc *service.MembershipService, scope *service.ProjectScope) *membershipServer {
	t.Helper()
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, svc, nil, nil, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	// Inject the resolved project scope server-side, as the project-resolution
	// middleware does in the real chain.
	scoped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := service.WithProjectScope(r.Context(), scope)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(scoped)
	t.Cleanup(srv.Close)
	return &membershipServer{client: identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)}
}

func newMembershipSvc(
	inv service.InvitationStore,
	mem service.MembershipStore,
	tnt service.TenantStore,
	users service.UserDirectory,
) *service.MembershipService {
	// mailerConfigured=false so the raw token surfaces in the response, which
	// the AcceptTenantInvitation handler test round-trips.
	return service.NewMembershipService(inv, mem, tnt, users, email.NewLogOnly(zap.NewNop()), false, &config.Config{}, zap.NewNop())
}

// ── nil service → Unimplemented ─────────────────────────────────────────

func TestMembershipRPCs_NilService_ReturnUnimplemented(t *testing.T) {
	t.Parallel()
	srv := startMembershipServer(t, nil)
	ctx := context.Background()

	_, err := srv.client.CreateTenantInvitation(ctx,
		withAuth(&identitypb.CreateTenantInvitationRequest{TenantId: "t", Email: "a@b.com"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.AcceptTenantInvitation(ctx,
		withAuth(&identitypb.AcceptTenantInvitationRequest{Token: "tok"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.ListTenantInvitations(ctx,
		withAuth(&identitypb.ListTenantInvitationsRequest{TenantId: "t"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.ListTenantMembers(ctx,
		withAuth(&identitypb.ListTenantMembersRequest{TenantId: "t"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.RemoveTenantMember(ctx,
		withAuth(&identitypb.RemoveTenantMemberRequest{TenantId: "t", UserId: "u2"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.TransferTenantOwnership(ctx,
		withAuth(&identitypb.TransferTenantOwnershipRequest{TenantId: "t", UserId: "u2"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.CreateTenant(ctx,
		withAuth(&identitypb.CreateTenantRequest{Name: "Acme"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.ListMyTenants(ctx,
		withAuth(&identitypb.ListMyTenantsRequest{}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.ListJoinableTenants(ctx,
		withAuth(&identitypb.ListJoinableTenantsRequest{}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.JoinTenantByDomain(ctx,
		withAuth(&identitypb.JoinTenantByDomainRequest{TenantId: "t"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)
}

// ── missing auth → Unauthenticated ──────────────────────────────────────

func TestMembershipRPCs_MissingAuth_Unauthenticated(t *testing.T) {
	t.Parallel()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	svc := newMembershipSvc(newConnectInvitationStore(), members, &connectTenantStore{}, &connectUserDirectory{})
	srv := startMembershipServer(t, svc)
	ctx := context.Background()

	// No auth header set on any of these.
	_, err := srv.client.CreateTenantInvitation(ctx,
		connect.NewRequest(&identitypb.CreateTenantInvitationRequest{TenantId: "t", Email: "a@b.com"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.AcceptTenantInvitation(ctx,
		connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: "tok"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.ListTenantInvitations(ctx,
		connect.NewRequest(&identitypb.ListTenantInvitationsRequest{TenantId: "t"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.ListTenantMembers(ctx,
		connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: "t"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.RemoveTenantMember(ctx,
		connect.NewRequest(&identitypb.RemoveTenantMemberRequest{TenantId: "t", UserId: "u2"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.TransferTenantOwnership(ctx,
		connect.NewRequest(&identitypb.TransferTenantOwnershipRequest{TenantId: "t", UserId: "u2"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.CreateTenant(ctx,
		connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Acme"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.ListMyTenants(ctx,
		connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.ListJoinableTenants(ctx,
		connect.NewRequest(&identitypb.ListJoinableTenantsRequest{}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.JoinTenantByDomain(ctx,
		connect.NewRequest(&identitypb.JoinTenantByDomainRequest{TenantId: "t"}))
	requireCode(t, err, connect.CodeUnauthenticated)
}

// ── Invite → Accept happy path through the handler ──────────────────────

func TestMembership_InviteThenAccept_Handler(t *testing.T) {
	invitations := newConnectInvitationStore()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"invitee": {ID: "invitee", Email: "invitee@acme.com", EmailVerified: true},
	}}
	svc := newMembershipSvc(invitations, members, claimedTenantStore(), users)
	srv := startMembershipServer(t, svc)
	ctx := context.Background()

	// Admin invites — no mailer, so the raw token is returned.
	created, err := srv.client.CreateTenantInvitation(ctx,
		withAuth(&identitypb.CreateTenantInvitationRequest{
			TenantId: "tenant-1", Email: "invitee@acme.com", Role: service.RoleMember,
		}, "owner-1"))
	if err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	if created.Msg.GetRawToken() == "" {
		t.Fatal("expected a raw token when no mailer is configured")
	}
	if created.Msg.GetInvitation().GetEmail() != "invitee@acme.com" {
		t.Fatalf("invitation email = %q", created.Msg.GetInvitation().GetEmail())
	}

	// The invitee redeems it and becomes a member.
	accepted, err := srv.client.AcceptTenantInvitation(ctx,
		withAuth(&identitypb.AcceptTenantInvitationRequest{Token: created.Msg.GetRawToken()}, "invitee"))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	m := accepted.Msg.GetMembership()
	if m.GetUserId() != "invitee" || m.GetRole() != service.RoleMember || m.GetSource() != service.MembershipSourceInvited {
		t.Fatalf("membership = %+v", m)
	}
	if members.upserted == nil || members.upserted.UserID != "invitee" {
		t.Fatalf("membership was not upserted: %+v", members.upserted)
	}
}

// ── ListTenantMembers happy path ────────────────────────────────────────

func TestListTenantMembers_Handler(t *testing.T) {
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	}}
	svc := newMembershipSvc(newConnectInvitationStore(), members, claimedTenantStore(), &connectUserDirectory{})
	srv := startMembershipServer(t, svc)

	// connectMembershipStore.ListMembershipsForTenant returns nil; assert the
	// call succeeds and yields an empty list (the gate, not the data, is the
	// point at the handler layer).
	resp, err := srv.client.ListTenantMembers(context.Background(),
		withAuth(&identitypb.ListTenantMembersRequest{TenantId: "tenant-1"}, "admin-1"))
	if err != nil {
		t.Fatalf("ListTenantMembers: %v", err)
	}
	if len(resp.Msg.GetMembers()) != 0 {
		t.Fatalf("got %d members, want 0", len(resp.Msg.GetMembers()))
	}
}

// ── TransferTenantOwnership through the handler ─────────────────────────

func TestTransferTenantOwnership_Handler(t *testing.T) {
	t.Parallel()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"heir":       {ID: "heir", Email: "heir@example.test", Status: service.StatusActive, EmailVerified: true},
		"unverified": {ID: "unverified", Email: "u@example.test", Status: service.StatusActive},
	}}
	srv := startMembershipServer(t, newMembershipSvc(newConnectInvitationStore(), members, claimedTenantStore(), users))
	ctx := context.Background()

	resp, err := srv.client.TransferTenantOwnership(ctx,
		withAuth(&identitypb.TransferTenantOwnershipRequest{TenantId: "t-1", UserId: "heir"}, "owner-1"))
	if err != nil {
		t.Fatalf("TransferTenantOwnership: %v", err)
	}
	if o := resp.Msg.GetOwner(); o.GetUserId() != "heir" || o.GetRole() != service.RoleOwner || o.GetTenantId() != "t-1" {
		t.Fatalf("owner = %+v", o)
	}
	if p := resp.Msg.GetPreviousOwner(); p.GetUserId() != "owner-1" || p.GetRole() != service.RoleAdmin {
		t.Fatalf("previous owner = %+v", p)
	}

	_, err = srv.client.TransferTenantOwnership(ctx,
		withAuth(&identitypb.TransferTenantOwnershipRequest{TenantId: "t-1", UserId: "unverified"}, "owner-1"))
	requireCode(t, err, connect.CodeFailedPrecondition)
	_, err = srv.client.TransferTenantOwnership(ctx,
		withAuth(&identitypb.TransferTenantOwnershipRequest{TenantId: "t-1", UserId: "owner-1"}, "owner-1"))
	requireCode(t, err, connect.CodeInvalidArgument)

	members.member.Role = service.RoleAdmin
	_, err = srv.client.TransferTenantOwnership(ctx,
		withAuth(&identitypb.TransferTenantOwnershipRequest{TenantId: "t-1", UserId: "heir"}, "owner-1"))
	requireCode(t, err, connect.CodePermissionDenied)
}

// ── ListJoinableTenants / JoinTenantByDomain through the handler ────────

func TestJoinTenantByDomain_Handler(t *testing.T) {
	t.Parallel()
	domains := newConnectDomainStore()
	domains.verified = &service.Domain{ID: "d1", TenantID: "t-1", Domain: "acme.com", Status: service.DomainStatusVerified, AllowJoin: true}
	tenants := &connectTenantStore{tenant: &service.Tenant{ID: "t-1", Name: "Acme", Status: service.TenantStatusClaimed}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"joiner":     {ID: "joiner", Email: "joiner@acme.com", Status: service.StatusActive, EmailVerified: true},
		"unverified": {ID: "unverified", Email: "u@acme.com", Status: service.StatusActive},
	}}
	members := &connectMembershipStore{}
	svc := newMembershipSvc(newConnectInvitationStore(), members, tenants, users).WithDomains(domains)
	srv := startMembershipServer(t, svc)
	ctx := context.Background()

	list, err := srv.client.ListJoinableTenants(ctx, withAuth(&identitypb.ListJoinableTenantsRequest{}, "joiner"))
	if err != nil {
		t.Fatalf("ListJoinableTenants: %v", err)
	}
	if got := list.Msg.GetTenants(); len(got) != 1 || got[0].GetTenantId() != "t-1" || got[0].GetName() != "Acme" {
		t.Fatalf("joinable tenants = %+v, want t-1 Acme", got)
	}

	joined, err := srv.client.JoinTenantByDomain(ctx, withAuth(&identitypb.JoinTenantByDomainRequest{TenantId: "t-1"}, "joiner"))
	if err != nil {
		t.Fatalf("JoinTenantByDomain: %v", err)
	}
	if m := joined.Msg.GetMembership(); m.GetTenantId() != "t-1" || m.GetUserId() != "joiner" ||
		m.GetRole() != service.RoleMember || m.GetSource() != service.MembershipSourceDomain {
		t.Fatalf("membership = %+v, want joiner a domain member of t-1", m)
	}

	_, err = srv.client.JoinTenantByDomain(ctx, withAuth(&identitypb.JoinTenantByDomainRequest{TenantId: "t-other"}, "joiner"))
	requireCode(t, err, connect.CodePermissionDenied)
	_, err = srv.client.JoinTenantByDomain(ctx, withAuth(&identitypb.JoinTenantByDomainRequest{TenantId: "t-1"}, "unverified"))
	requireCode(t, err, connect.CodeFailedPrecondition)
	_, err = srv.client.ListJoinableTenants(ctx, withAuth(&identitypb.ListJoinableTenantsRequest{}, "user-unknown"))
	requireCode(t, err, connect.CodeNotFound)
}

// ── CreateTenant / ListMyTenants through the handler ────────────────────

func selfServiceScope(on bool) *service.ProjectScope {
	return &service.ProjectScope{ProjectID: testProjectID, Tenants: service.ProjectTenantsConfig{SelfService: on}}
}

func TestCreateTenant_Handler(t *testing.T) {
	tenants := &connectTenantStore{}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"owner-1": {ID: "owner-1", Email: "owner@example.test", Status: service.StatusActive, EmailVerified: true},
	}}
	svc := newMembershipSvc(newConnectInvitationStore(), &connectMembershipStore{}, tenants, users)
	srv := startMembershipServerInScope(t, svc, selfServiceScope(true))

	resp, err := srv.client.CreateTenant(context.Background(),
		withAuth(&identitypb.CreateTenantRequest{Name: " Acme "}, "owner-1"))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if resp.Msg.GetTenantId() != "tenant-new" || resp.Msg.GetName() != "Acme" {
		t.Fatalf("response = %+v", resp.Msg)
	}
	m := resp.Msg.GetMembership()
	if m.GetUserId() != "owner-1" || m.GetRole() != service.RoleOwner || m.GetSource() != service.MembershipSourceCreated ||
		m.GetStatus() != service.MembershipStatusActive || m.GetTenantId() != "tenant-new" {
		t.Fatalf("membership = %+v", m)
	}
	if tenants.ownedReq == nil || tenants.ownedReq.ProjectID != testProjectID || tenants.ownedReq.OwnerID != "owner-1" {
		t.Fatalf("store request = %+v", tenants.ownedReq)
	}
}

func TestCreateTenant_Handler_Refusals(t *testing.T) {
	users := &connectUserDirectory{byID: map[string]*service.User{
		"owner-1": {ID: "owner-1", Email: "owner@example.test", Status: service.StatusActive, EmailVerified: true},
	}}
	ctx := context.Background()

	off := startMembershipServerInScope(t,
		newMembershipSvc(newConnectInvitationStore(), &connectMembershipStore{}, &connectTenantStore{}, users), selfServiceScope(false))
	_, err := off.client.CreateTenant(ctx, withAuth(&identitypb.CreateTenantRequest{Name: "Acme"}, "owner-1"))
	requireCode(t, err, connect.CodeFailedPrecondition)

	on := startMembershipServerInScope(t,
		newMembershipSvc(newConnectInvitationStore(), &connectMembershipStore{}, &connectTenantStore{}, users), selfServiceScope(true))
	_, err = on.client.CreateTenant(ctx, withAuth(&identitypb.CreateTenantRequest{Name: "  "}, "owner-1"))
	requireCode(t, err, connect.CodeInvalidArgument)

	limited := startMembershipServerInScope(t,
		newMembershipSvc(newConnectInvitationStore(), &connectMembershipStore{},
			&connectTenantStore{ownedErr: service.ErrTenantCreationLimited}, users), selfServiceScope(true))
	_, err = limited.client.CreateTenant(ctx, withAuth(&identitypb.CreateTenantRequest{Name: "Acme"}, "owner-1"))
	requireCode(t, err, connect.CodeResourceExhausted)
}

func TestListMyTenants_Handler(t *testing.T) {
	members := &connectMembershipStore{active: []*service.UserTenant{
		{TenantID: "t-a", Name: "Alpha", Role: service.RoleAdmin},
		{TenantID: "t-b", Name: "Beta", Role: service.RoleMember},
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"user-1": {ID: "user-1", Email: "user@example.test", Status: service.StatusActive},
	}}
	svc := newMembershipSvc(newConnectInvitationStore(), members, &connectTenantStore{}, users)
	srv := startMembershipServer(t, svc)

	resp, err := srv.client.ListMyTenants(context.Background(), withAuth(&identitypb.ListMyTenantsRequest{}, "user-1"))
	if err != nil {
		t.Fatalf("ListMyTenants: %v", err)
	}
	got := resp.Msg.GetTenants()
	if len(got) != 2 || got[0].GetTenantId() != "t-a" || got[0].GetName() != "Alpha" || got[0].GetRole() != service.RoleAdmin ||
		got[1].GetTenantId() != "t-b" || got[1].GetRole() != service.RoleMember {
		t.Fatalf("tenants = %+v", got)
	}
}
