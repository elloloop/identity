//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
)

// TestRedesign_Membership_InviteAcceptList drives the slice-8b membership flow
// end-to-end over the Connect client against a real Postgres: an owner invites
// a user by email, the invited user (already signed up) accepts the raw token,
// becomes an active member, and ListTenantMembers then shows both the owner
// and the new member. ListTenantInvitations shows the invitation as accepted.
func TestRedesign_Membership_InviteAcceptList(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	owner := signupOwner(t, h, "mem-owner")

	// The user to be invited signs up first (the redeemer must be an
	// authenticated account whose email matches the invitation).
	inviteeEmail := fmt.Sprintf("mem-invitee-%d@example-corp.com", time.Now().UnixNano())
	invitee := signupMembershipUser(t, h, inviteeEmail)

	// Owner invites the user as an admin.
	created, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID,
		Email:    inviteeEmail,
		Role:     service.RoleAdmin,
	}))
	if err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	inv := created.Msg.GetInvitation()
	if inv.GetId() == "" || inv.GetStatus() != service.InvitationStatusPending {
		t.Fatalf("unexpected invitation: %+v", inv)
	}
	if inv.GetEmail() != inviteeEmail {
		t.Fatalf("invitation email = %q, want %q", inv.GetEmail(), inviteeEmail)
	}

	// The harness wires a RecordingMailer (a real, non-log-only transport), so
	// the raw token is delivered by email, NOT returned in the response.
	if created.Msg.GetRawToken() != "" {
		t.Fatalf("raw token must not be returned when a mailer is configured")
	}
	rawToken := extractInvitationToken(t, h, inviteeEmail)

	// The invitee redeems the token and becomes a member.
	accepted, err := invitee.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: rawToken,
	}))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	m := accepted.Msg.GetMembership()
	if m.GetUserId() != invitee.userID || m.GetRole() != service.RoleAdmin || m.GetSource() != service.MembershipSourceInvited {
		t.Fatalf("accepted membership = %+v", m)
	}

	// ListTenantMembers (owner-gated, over RPC) shows BOTH the owner and the
	// newly-accepted invitee.
	list, err := owner.client.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{
		TenantId: owner.tenantID,
	}))
	if err != nil {
		t.Fatalf("ListTenantMembers: %v", err)
	}
	gotUsers := map[string]string{}
	for _, mem := range list.Msg.GetMembers() {
		gotUsers[mem.GetUserId()] = mem.GetRole()
	}
	if gotUsers[owner.userID] != service.RoleOwner {
		t.Fatalf("owner missing/with wrong role in members: %+v", gotUsers)
	}
	if gotUsers[invitee.userID] != service.RoleAdmin {
		t.Fatalf("invitee missing/with wrong role in members: %+v", gotUsers)
	}

	// ListTenantInvitations shows the invitation as accepted.
	invs, err := owner.client.ListTenantInvitations(ctx, connect.NewRequest(&identitypb.ListTenantInvitationsRequest{
		TenantId: owner.tenantID,
	}))
	if err != nil {
		t.Fatalf("ListTenantInvitations: %v", err)
	}
	if len(invs.Msg.GetInvitations()) != 1 || invs.Msg.GetInvitations()[0].GetStatus() != service.InvitationStatusAccepted {
		t.Fatalf("invitations = %+v, want one accepted", invs.Msg.GetInvitations())
	}
}

// TestRedesign_Membership_WrongEmailDenied asserts a leaked token cannot be
// redeemed by an account whose email differs from the invitation's.
func TestRedesign_Membership_WrongEmailDenied(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	owner := signupOwner(t, h, "mem-wrongemail-owner")
	inviteeEmail := fmt.Sprintf("mem-wrong-target-%d@example-corp.com", time.Now().UnixNano())

	created, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID,
		Email:    inviteeEmail,
		Role:     service.RoleMember,
	}))
	if err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	_ = created
	rawToken := extractInvitationToken(t, h, inviteeEmail)

	// A DIFFERENT user (different email) tries to redeem the token.
	eve := signupMembershipUser(t, h, fmt.Sprintf("eve-%d@example-corp.com", time.Now().UnixNano()))
	_, err = eve.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: rawToken,
	}))
	if err == nil {
		t.Fatal("AcceptTenantInvitation by wrong-email caller: want error, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong-email accept code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Eve gained no membership.
	mem, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, owner.tenantID, eve.userID)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if mem != nil {
		t.Fatalf("wrong-email caller gained a membership: %+v", mem)
	}
}

// TestRedesign_Membership_LastOwnerGuard asserts the sole owner cannot be
// removed (which would strand the tenant ownerless).
func TestRedesign_Membership_LastOwnerGuard(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	owner := signupOwner(t, h, "mem-lastowner")

	_, err := owner.client.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{
		TenantId: owner.tenantID,
		UserId:   owner.userID,
	}))
	if err == nil {
		t.Fatal("RemoveTenantMember on sole owner: want error, got nil")
	}
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("last-owner removal code = %v, want FailedPrecondition", connect.CodeOf(err))
	}

	// The owner is still a member.
	mem, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, owner.tenantID, owner.userID)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if mem == nil || mem.Role != service.RoleOwner {
		t.Fatalf("sole owner was removed despite the guard: %+v", mem)
	}
}

// membershipUser is a signed-up user with an authed Connect client.
type membershipUser struct {
	client identityconnectgen.IdentityServiceClient
	userID string
}

// signupMembershipUser signs up a plain user (no tenant) and returns an authed
// client carrying their bearer token — the realistic state of an invitee who
// has an account but no membership yet.
func signupMembershipUser(t *testing.T, h *RedesignHarness, emailAddr string) membershipUser {
	t.Helper()
	signup, err := h.Client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    emailAddr,
		Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("signupMembershipUser PasswordSignup(%s): %v", emailAddr, err)
	}
	return membershipUser{
		client: h.AuthedClient(signup.Msg.GetAccessToken()),
		userID: signup.Msg.GetUser().GetId(),
	}
}

// extractInvitationToken pulls the raw token out of the most recent recorded
// invitation email sent to addr. The token is the value of the ?token= query
// parameter in the acceptance link the template embeds — how a real recipient
// obtains it, proving the token travels by email, not in the RPC response.
func extractInvitationToken(t *testing.T, h *RedesignHarness, addr string) string {
	t.Helper()
	for _, msg := range reversedMessages(h.Mailer.Sent()) {
		if msg.To == addr {
			return extractToken(t, msg.Text)
		}
	}
	t.Fatalf("no invitation email recorded for %s", addr)
	return ""
}

// reversedMessages returns msgs newest-first so the latest email to a
// recipient is found before any earlier one.
func reversedMessages(msgs []email.Message) []email.Message {
	out := make([]email.Message, len(msgs))
	for i, m := range msgs {
		out[len(msgs)-1-i] = m
	}
	return out
}
