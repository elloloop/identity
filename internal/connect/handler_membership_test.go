package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
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

func (s *connectInvitationStore) CreateInvitation(_ context.Context, inv *service.TenantInvitation) (string, error) {
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

// connectUserDirectory resolves users by id for the email-match policy.
type connectUserDirectory struct {
	byID map[string]*service.User
}

func (d *connectUserDirectory) GetUser(_ context.Context, userID string) (*service.User, error) {
	return d.byID[userID], nil
}

// ── Harness ──────────────────────────────────────────────────────────────

type membershipServer struct {
	client identityconnectgen.IdentityServiceClient
}

func startMembershipServer(t *testing.T, svc *service.MembershipService) *membershipServer {
	t.Helper()
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, svc, nil, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	// Inject the resolved project scope server-side, as the project-resolution
	// middleware does in the real chain.
	scoped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := service.WithProjectScope(r.Context(), &service.ProjectScope{ProjectID: testProjectID})
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
}

// ── Invite → Accept happy path through the handler ──────────────────────

func TestMembership_InviteThenAccept_Handler(t *testing.T) {
	invitations := newConnectInvitationStore()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"invitee": {ID: "invitee", Email: "invitee@acme.com"},
	}}
	svc := newMembershipSvc(invitations, members, &connectTenantStore{}, users)
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
	svc := newMembershipSvc(newConnectInvitationStore(), members, &connectTenantStore{}, &connectUserDirectory{})
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
