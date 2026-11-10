//go:build integration && realpostgres

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestRedesign_InviteOnly_InvitedAddressSignsUpAndAccepts drives an invite-only
// project end to end against a real Postgres, on the branded host whose
// project config the control plane resolves: a tenant owner invites an address
// that has no account, the address signs in with an emailed code, which
// creates its account, and the new account accepts the invitation. An address
// with no invitation gets no code and no account, and the invited address
// still cannot sign up with a password.
func TestRedesign_InviteOnly_InvitedAddressSignsUpAndAccepts(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invited-signup-owner")

	cp := h.Stores.controlPlane
	_, version, err := cp.GetProjectConfig(ctx, h.ProjectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if _, _, err := cp.UpdateProjectConfig(ctx, h.ProjectID, version, `{"access":{"mode":"invite"}}`); err != nil {
		t.Fatalf("UpdateProjectConfig(invite): %v", err)
	}

	invitee := fmt.Sprintf("invited-%d@example-corp.com", time.Now().UnixNano())
	if _, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID, Email: invitee, Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	inviteToken := extractMailedToken(t, h, invitee)
	branded := h.ClientWithHost(h.BrandedAuthDomain, nil)

	_, err = branded.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: invitee, Password: validPassword,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("PasswordSignup of an invited address = %v, want PermissionDenied", err)
	}

	h.Mailer.Reset()
	if _, err := branded.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: invitee})); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	signedIn, err := branded.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: invitee, Code: extractRedesignLoginCode(t, h),
	}))
	if err != nil {
		t.Fatalf("VerifyEmailLoginCode for the invited address: %v", err)
	}

	accepted, err := h.AuthedClient(signedIn.Msg.GetAccessToken()).AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: inviteToken,
	}))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	if got := accepted.Msg.GetMembership(); got.GetTenantId() != owner.tenantID || got.GetUserId() != signedIn.Msg.GetUser().GetId() {
		t.Fatalf("membership = %+v, want the new account in the inviting tenant", got)
	}

	stranger := fmt.Sprintf("stranger-%d@example-corp.com", time.Now().UnixNano())
	h.Mailer.Reset()
	if _, err := branded.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: stranger})); err != nil {
		t.Fatalf("RequestEmailLoginCode(stranger): %v", err)
	}
	if sent := h.Mailer.Sent(); len(sent) != 0 {
		t.Fatalf("an address with no invitation got %d emails, want none", len(sent))
	}
	u, err := h.Stores.users.FindUserByEmail(ctx, stranger)
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("FindUserByEmail(stranger): %v", err)
	}
	if u != nil {
		t.Fatalf("an address with no invitation got an account")
	}
}
