package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
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

func (s *connectInvitationStore) OpenInvitationForEmail(_ context.Context, _, _ string, _ int64) (*service.TenantInvitation, error) {
	return nil, nil
}

func (s *connectInvitationStore) RevokeInvitation(_ context.Context, _, tenantID, invitationID string) (*service.TenantInvitation, bool, error) {
	inv, ok := s.byID[invitationID]
	if !ok || inv.TenantID != tenantID {
		return nil, false, service.ErrNotFound
	}
	switch inv.Status {
	case service.InvitationStatusPending:
		inv.Status = service.InvitationStatusRevoked
		cp := *inv
		return &cp, true, nil
	case service.InvitationStatusAccepted:
		return nil, false, service.ErrInvitationUsed
	}
	cp := *inv
	return &cp, false, nil
}

// OpenInvitationForToken counts every pending, unexpired invitation open: the
// store keeps no tenants or inviters to filter by.
func (s *connectInvitationStore) OpenInvitationForToken(_ context.Context, _, tokenHash string, nowMs int64) (*service.TenantInvitation, error) {
	if inv := s.byHash[tokenHash]; inv != nil && inv.Status == service.InvitationStatusPending &&
		(inv.ExpiresAtMs == 0 || inv.ExpiresAtMs >= nowMs) {
		return inv, nil
	}
	return nil, nil
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
	// mailerDelivers=false so the raw token surfaces in the response, which
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

	_, err = srv.client.RevokeTenantInvitation(ctx,
		withAuth(&identitypb.RevokeTenantInvitationRequest{TenantId: "t", InvitationId: "inv-1"}, "u1"))
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

	_, err = srv.client.SuspendTenantMember(ctx,
		withAuth(&identitypb.SuspendTenantMemberRequest{TenantId: "t", UserId: "u2"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.RestoreTenantMember(ctx,
		withAuth(&identitypb.RestoreTenantMemberRequest{TenantId: "t", UserId: "u2"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = srv.client.SetTenantMemberRole(ctx,
		withAuth(&identitypb.SetTenantMemberRoleRequest{TenantId: "t", UserId: "u2", Role: service.RoleAdmin}, "u1"))
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

	_, err = srv.client.RevokeTenantInvitation(ctx,
		connect.NewRequest(&identitypb.RevokeTenantInvitationRequest{TenantId: "t", InvitationId: "inv-1"}))
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

	_, err = srv.client.SuspendTenantMember(ctx,
		connect.NewRequest(&identitypb.SuspendTenantMemberRequest{TenantId: "t", UserId: "u2"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.RestoreTenantMember(ctx,
		connect.NewRequest(&identitypb.RestoreTenantMemberRequest{TenantId: "t", UserId: "u2"}))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = srv.client.SetTenantMemberRole(ctx,
		connect.NewRequest(&identitypb.SetTenantMemberRoleRequest{TenantId: "t", UserId: "u2", Role: service.RoleAdmin}))
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
	if got := created.Msg.GetEmailSendStatus(); got != identitypb.EmailSendStatus_EMAIL_SEND_STATUS_NOT_CONFIGURED {
		t.Fatalf("email_send_status = %v, want NOT_CONFIGURED", got)
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

// ── Revoke through the handler ──────────────────────────────────────────

// A revoked invitation comes back with status "revoked", again unchanged on a
// retry, and its token no longer redeems; another tenant's or an unknown id is
// NOT_FOUND, and an accepted one FAILED_PRECONDITION.
func TestMembership_RevokeTenantInvitation_Handler(t *testing.T) {
	invitations := newConnectInvitationStore()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleOwner, Status: service.MembershipStatusActive,
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"invitee": {ID: "invitee", Email: "invitee@acme.com", EmailVerified: true},
	}}
	srv := startMembershipServer(t, newMembershipSvc(invitations, members, claimedTenantStore(), users))
	ctx := context.Background()
	invite := func() string {
		created, err := srv.client.CreateTenantInvitation(ctx, withAuth(&identitypb.CreateTenantInvitationRequest{
			TenantId: "tenant-1", Email: "invitee@acme.com",
		}, "owner-1"))
		if err != nil {
			t.Fatalf("CreateTenantInvitation: %v", err)
		}
		return created.Msg.GetRawToken()
	}
	revoke := func(tenantID, invitationID string) (*connect.Response[identitypb.RevokeTenantInvitationResponse], error) {
		return srv.client.RevokeTenantInvitation(ctx, withAuth(&identitypb.RevokeTenantInvitationRequest{
			TenantId: tenantID, InvitationId: invitationID,
		}, "owner-1"))
	}

	token := invite()
	for range 2 {
		revoked, err := revoke("tenant-1", "inv-1")
		if err != nil {
			t.Fatalf("RevokeTenantInvitation: %v", err)
		}
		if got := revoked.Msg.GetInvitation(); got.GetId() != "inv-1" || got.GetStatus() != service.InvitationStatusRevoked {
			t.Fatalf("invitation = %+v, want inv-1 revoked", got)
		}
	}
	_, err := srv.client.AcceptTenantInvitation(ctx, withAuth(&identitypb.AcceptTenantInvitationRequest{Token: token}, "invitee"))
	requireCode(t, err, connect.CodePermissionDenied)

	_, err = revoke("tenant-2", "inv-1")
	requireCode(t, err, connect.CodeNotFound)
	_, err = revoke("tenant-1", "inv-unknown")
	requireCode(t, err, connect.CodeNotFound)
	_, err = revoke("tenant-1", " ")
	requireCode(t, err, connect.CodeInvalidArgument)

	token = invite()
	if _, err := srv.client.AcceptTenantInvitation(ctx, withAuth(&identitypb.AcceptTenantInvitationRequest{Token: token}, "invitee")); err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	_, err = revoke("tenant-1", "inv-1")
	requireCode(t, err, connect.CodeFailedPrecondition)
}

type fixedResultMailer struct{ err error }

func (m fixedResultMailer) Send(context.Context, email.Message) error { return m.err }

func TestCreateTenantInvitation_Handler_ReportsEmailSendStatus(t *testing.T) {
	cases := []struct {
		name       string
		mailer     email.Transport
		configured bool
		want       identitypb.EmailSendStatus
		wantToken  bool
	}{
		{"provider accepted", fixedResultMailer{}, true, identitypb.EmailSendStatus_EMAIL_SEND_STATUS_SENT, false},
		{"every provider failed", fixedResultMailer{err: email.ErrTransport}, true, identitypb.EmailSendStatus_EMAIL_SEND_STATUS_FAILED, false},
		{"no provider configured", email.NewLogOnly(zap.NewNop()), false, identitypb.EmailSendStatus_EMAIL_SEND_STATUS_NOT_CONFIGURED, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			members := &connectMembershipStore{member: &service.TenantMembership{
				Role: service.RoleOwner, Status: service.MembershipStatusActive,
			}}
			svc := service.NewMembershipService(newConnectInvitationStore(), members, claimedTenantStore(),
				&connectUserDirectory{}, tc.mailer, tc.configured, &config.Config{}, zap.NewNop())
			srv := startMembershipServer(t, svc)

			created, err := srv.client.CreateTenantInvitation(context.Background(),
				withAuth(&identitypb.CreateTenantInvitationRequest{
					TenantId: "tenant-1", Email: "invitee@acme.com", Role: service.RoleMember,
				}, "owner-1"))
			if err != nil {
				t.Fatalf("CreateTenantInvitation: %v", err)
			}
			if got := created.Msg.GetEmailSendStatus(); got != tc.want {
				t.Fatalf("email_send_status = %v, want %v", got, tc.want)
			}
			if got := created.Msg.GetRawToken() != ""; got != tc.wantToken {
				t.Fatalf("raw token returned = %v, want %v", got, tc.wantToken)
			}
			if created.Msg.GetInvitation().GetId() == "" {
				t.Fatal("the invitation is created whatever its email's status")
			}
		})
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

// ── SuspendTenantMember / RestoreTenantMember through the handler ───────

func TestSuspendAndRestoreTenantMember_Handler(t *testing.T) {
	t.Parallel()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	}}
	srv := startMembershipServer(t, newMembershipSvc(newConnectInvitationStore(), members, claimedTenantStore(), &connectUserDirectory{}))
	ctx := context.Background()

	suspended, err := srv.client.SuspendTenantMember(ctx,
		withAuth(&identitypb.SuspendTenantMemberRequest{TenantId: "t-1", UserId: "bob"}, "admin-1"))
	if err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	if m := suspended.Msg.GetMembership(); m.GetUserId() != "bob" || m.GetTenantId() != "t-1" ||
		m.GetStatus() != service.MembershipStatusSuspended || m.GetRole() != service.RoleMember {
		t.Fatalf("suspended membership = %+v", m)
	}
	restored, err := srv.client.RestoreTenantMember(ctx,
		withAuth(&identitypb.RestoreTenantMemberRequest{TenantId: "t-1", UserId: "bob"}, "admin-1"))
	if err != nil {
		t.Fatalf("RestoreTenantMember: %v", err)
	}
	if m := restored.Msg.GetMembership(); m.GetUserId() != "bob" || m.GetStatus() != service.MembershipStatusActive {
		t.Fatalf("restored membership = %+v", m)
	}

	_, err = srv.client.SuspendTenantMember(ctx,
		withAuth(&identitypb.SuspendTenantMemberRequest{TenantId: "t-1", UserId: "admin-1"}, "admin-1"))
	requireCode(t, err, connect.CodeInvalidArgument)
	_, err = srv.client.RestoreTenantMember(ctx,
		withAuth(&identitypb.RestoreTenantMemberRequest{TenantId: "t-1"}, "admin-1"))
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = srv.client.RestoreTenantMember(ctx,
		withAuth(&identitypb.RestoreTenantMemberRequest{TenantId: "t-1", UserId: "admin-1"}, "admin-1"))
	requireCode(t, err, connect.CodeInvalidArgument)

	members.changeErr = service.ErrLastOwner
	_, err = srv.client.SuspendTenantMember(ctx,
		withAuth(&identitypb.SuspendTenantMemberRequest{TenantId: "t-1", UserId: "bob"}, "admin-1"))
	requireCode(t, err, connect.CodeFailedPrecondition)
	for err, code := range map[error]connect.Code{
		service.ErrNotFound:         connect.CodeNotFound,
		service.ErrPermissionDenied: connect.CodePermissionDenied,
	} {
		members.changeErr = err
		_, got := srv.client.RestoreTenantMember(ctx,
			withAuth(&identitypb.RestoreTenantMemberRequest{TenantId: "t-1", UserId: "bob"}, "admin-1"))
		requireCode(t, got, code)
	}
	members.changeErr = service.ErrNotFound
	_, err = srv.client.SuspendTenantMember(ctx,
		withAuth(&identitypb.SuspendTenantMemberRequest{TenantId: "t-1", UserId: "bob"}, "admin-1"))
	requireCode(t, err, connect.CodeNotFound)

	members.changeErr = nil
	members.member.Status = service.MembershipStatusSuspended
	_, err = srv.client.SuspendTenantMember(ctx,
		withAuth(&identitypb.SuspendTenantMemberRequest{TenantId: "t-1", UserId: "bob"}, "admin-1"))
	requireCode(t, err, connect.CodePermissionDenied)
	_, err = srv.client.RestoreTenantMember(ctx,
		withAuth(&identitypb.RestoreTenantMemberRequest{TenantId: "t-1", UserId: "admin-1"}, "admin-1"))
	requireCode(t, err, connect.CodePermissionDenied)
}

// ── SetTenantMemberRole through the handler ─────────────────────────────

// A promotion and a demotion come back as the membership then stands; a
// missing id or a role other than admin or member is INVALID_ARGUMENT, a
// caller who does not govern PERMISSION_DENIED, and each refusal the store
// makes keeps its code.
func TestSetTenantMemberRole_Handler(t *testing.T) {
	t.Parallel()
	members := &connectMembershipStore{member: &service.TenantMembership{
		Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	}}
	users := &connectUserDirectory{byID: map[string]*service.User{
		"bob": {ID: "bob", Email: "bob@example.test", Status: service.StatusActive, EmailVerified: true},
	}}
	srv := startMembershipServer(t, newMembershipSvc(newConnectInvitationStore(), members, claimedTenantStore(), users))
	ctx := context.Background()
	setRole := func(userID, role string) (*connect.Response[identitypb.SetTenantMemberRoleResponse], error) {
		return srv.client.SetTenantMemberRole(ctx, withAuth(&identitypb.SetTenantMemberRoleRequest{
			TenantId: "t-1", UserId: userID, Role: role,
		}, "admin-1"))
	}

	for _, role := range []string{service.RoleAdmin, service.RoleMember} {
		resp, err := setRole("bob", role)
		if err != nil {
			t.Fatalf("SetTenantMemberRole(%s): %v", role, err)
		}
		if m := resp.Msg.GetMembership(); m.GetUserId() != "bob" || m.GetTenantId() != "t-1" ||
			m.GetRole() != role || m.GetStatus() != service.MembershipStatusActive {
			t.Fatalf("membership = %+v, want bob %s", m, role)
		}
	}

	for _, role := range []string{service.RoleOwner, "", "superuser"} {
		_, err := setRole("bob", role)
		requireCode(t, err, connect.CodeInvalidArgument)
	}
	_, err := setRole(" ", service.RoleAdmin)
	requireCode(t, err, connect.CodeInvalidArgument)
	_, err = setRole("nobody", service.RoleAdmin)
	requireCode(t, err, connect.CodeNotFound)

	for err, code := range map[error]connect.Code{
		service.ErrMemberIsOwner:         connect.CodeFailedPrecondition,
		service.ErrIneligibleTenantAdmin: connect.CodeFailedPrecondition,
		service.ErrLastTenantGovernor:    connect.CodeFailedPrecondition,
		service.ErrNotFound:              connect.CodeNotFound,
		service.ErrPermissionDenied:      connect.CodePermissionDenied,
	} {
		members.changeErr = err
		_, got := setRole("bob", service.RoleMember)
		requireCode(t, got, code)
	}

	members.changeErr = nil
	members.member.Role = service.RoleMember
	_, err = setRole("bob", service.RoleAdmin)
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

func TestManagedAccountRPCs_ReturnUnimplemented(t *testing.T) {
	t.Parallel()
	for _, svc := range []*service.MembershipService{nil, newMembershipSvc(nil, nil, nil, nil)} {
		srv := startMembershipServer(t, svc)
		ctx := context.Background()

		_, err := srv.client.CheckManagedAddresses(ctx,
			withAuth(&identitypb.CheckManagedAddressesRequest{TenantId: "t", Addresses: []*identitypb.ManagedAddress{{Username: "ann", Domain: "acme.example.com"}}}, "u1"))
		requireCode(t, err, connect.CodeUnimplemented)

		_, err = srv.client.ResetManagedAccount(ctx,
			withAuth(&identitypb.ResetManagedAccountRequest{TenantId: "t", UserId: "u2", DeliveryAddress: "ann@example.com"}, "u1"))
		requireCode(t, err, connect.CodeUnimplemented)
	}
}

// A request for a tenant-managed account is refused with POLICY wherever
// the server or the project does not admit managed accounts, so it never
// becomes an ordinary invitation to its delivery address; a server with no
// managed store answers Unimplemented, and with no membership service the
// call is Unimplemented, as every membership call is.
func TestCreateTenantInvitation_ManagedAccountFieldsRefused(t *testing.T) {
	t.Parallel()
	_, err := startMembershipServer(t, nil).client.CreateTenantInvitation(context.Background(),
		withAuth(&identitypb.CreateTenantInvitationRequest{TenantId: "t", Email: "ann.home@example.com", AccountUsername: "ann"}, "u1"))
	requireCode(t, err, connect.CodeUnimplemented)

	admin := &connectMembershipStore{member: &service.TenantMembership{Role: service.RoleOwner, Status: service.MembershipStatusActive}}
	requests := map[string]*identitypb.CreateTenantInvitationRequest{
		"all": {TenantId: "tenant-1", Email: "ann.home@example.com", AccountUsername: "ann", AccountDomain: "acme.example.com", DisplayName: "Ann"},
	}
	for dark, cfg := range map[string]*config.Config{
		"server flag off":                {},
		"project not opted in (flag on)": {ManagedAccountsEnabled: true},
	} {
		svc := service.NewMembershipService(newConnectInvitationStore(), admin, claimedTenantStore(), &connectUserDirectory{},
			email.NewLogOnly(zap.NewNop()), true, cfg, zap.NewNop()).WithManagedSetups(unusedManagedSetups{})
		srv := startMembershipServer(t, svc)
		for name, req := range requests {
			_, err := srv.client.CreateTenantInvitation(context.Background(), withAuth(req, "admin-1"))
			requireCode(t, err, connect.CodeFailedPrecondition)
			var cerr *connect.Error
			require.ErrorAs(t, err, &cerr, name)
			var reasons []identitypb.ManagedAccountRefusal
			for _, d := range cerr.Details() {
				v, derr := d.Value()
				require.NoError(t, derr, name)
				if refused, ok := v.(*identitypb.ManagedAccountRefusedDetails); ok {
					reasons = append(reasons, refused.GetReason())
				}
			}
			require.Equal(t, []identitypb.ManagedAccountRefusal{identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_POLICY}, reasons, "%s: %s", dark, name)
		}
	}
}

// unusedManagedSetups is a managed store no test call reaches: a dark
// server refuses before it writes.
type unusedManagedSetups struct{ service.ManagedSetupStore }

// A request naming any of the managed-account fields is a managed account's
// set-up link, which a server without the managed store cannot write.
func TestCreateTenantInvitation_ManagedFieldsRouteToTheManagedSetup(t *testing.T) {
	t.Parallel()
	srv := startMembershipServer(t, newMembershipSvc(nil, nil, nil, nil))
	for _, req := range []*identitypb.CreateTenantInvitationRequest{
		{TenantId: "t", Email: "a@example.com", AccountUsername: "ann"},
		{TenantId: "t", Email: "a@example.com", AccountDomain: "acme.example.com"},
		{TenantId: "t", Email: "a@example.com", DisplayName: "Ann"},
	} {
		_, err := srv.client.CreateTenantInvitation(context.Background(), withAuth(req, "u1"))
		requireCode(t, err, connect.CodeUnimplemented)
	}
}

func TestInvitationToProto_ManagedSetupLink(t *testing.T) {
	t.Parallel()
	got := invitationToProto(&service.TenantInvitation{
		ID: "inv", TenantID: "t", Email: "ann@acme.example.com", UserID: "u", DeliveryEmail: "ann@example.net",
	})
	if !got.GetIsManagedSetup() || got.GetEmail() != "ann@example.net" || got.GetAccountAddress() != "ann@acme.example.com" || got.GetUserId() != "u" {
		t.Fatalf("managed = %+v", got)
	}
	plain := invitationToProto(&service.TenantInvitation{ID: "inv", TenantID: "t", Email: "bob@example.com"})
	if plain.GetIsManagedSetup() || plain.GetEmail() != "bob@example.com" || plain.GetAccountAddress() != "" || plain.GetUserId() != "" {
		t.Fatalf("ordinary = %+v", plain)
	}
}

func TestAccountKindToProto(t *testing.T) {
	t.Parallel()
	for kind, want := range map[string]identitypb.AccountKind{
		service.AccountKindPersonal: identitypb.AccountKind_ACCOUNT_KIND_PERSONAL,
		service.AccountKindManaged:  identitypb.AccountKind_ACCOUNT_KIND_MANAGED,
		"":                          identitypb.AccountKind_ACCOUNT_KIND_UNSPECIFIED,
	} {
		if got := accountKindToProto(kind); got != want {
			t.Fatalf("%q = %v, want %v", kind, got, want)
		}
	}
}
