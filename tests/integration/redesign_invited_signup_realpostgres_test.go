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
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// TestRedesign_InviteOnly_InvitedAddressSignsUpAndAccepts drives an invite-only
// project with admit_tenant_invitations end to end against a real Postgres, on
// the branded host whose
// project config the control plane resolves: a tenant owner invites an address
// that has no account, the address signs in with an emailed code, which
// creates its account, and the new account accepts the invitation. An address
// with no invitation gets no code and no account, and the invited address
// still cannot sign up with a password.
func TestRedesign_InviteOnly_InvitedAddressSignsUpAndAccepts(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invited-signup-owner")
	setProjectConfig(t, h, `{"access":{"mode":"invite","admit_tenant_invitations":true}}`)
	var err error

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

// setProjectConfig writes configJSON as the harness project's config_json,
// which the branded host resolves.
func setProjectConfig(t *testing.T, h *RedesignHarness, configJSON string) {
	t.Helper()
	ctx := context.Background()
	_, version, err := h.Stores.controlPlane.GetProjectConfig(ctx, h.ProjectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if _, _, err := h.Stores.controlPlane.UpdateProjectConfig(ctx, h.ProjectID, version, configJSON); err != nil {
		t.Fatalf("UpdateProjectConfig(%s): %v", configJSON, err)
	}
}

// requestCode asks the branded host for a sign-in code for addr and returns
// how many emails it sent.
func requestCode(t *testing.T, h *RedesignHarness, addr string) int {
	t.Helper()
	h.Mailer.Reset()
	if _, err := h.ClientWithHost(h.BrandedAuthDomain, nil).RequestEmailLoginCode(context.Background(),
		connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: addr})); err != nil {
		t.Fatalf("RequestEmailLoginCode(%s): %v", addr, err)
	}
	return len(h.Mailer.Sent())
}

// TestRedesign_InviteOnly_SelfServiceTenantInvitationAdmitsNobody: with
// self-service tenants on, a person who makes a tenant and invites someone does
// not let them into an invite-only project, even with admit_tenant_invitations.
func TestRedesign_InviteOnly_SelfServiceTenantInvitationAdmitsNobody(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) { c.SelfServiceTenantsEnabled = true })
	ctx := context.Background()
	maker := signupVerifiedUser(t, h, fmt.Sprintf("maker-%d@example-corp.com", time.Now().UnixNano()))
	made, err := maker.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Made by a person"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	setProjectConfig(t, h, `{"access":{"mode":"invite","admit_tenant_invitations":true},"tenants":{"self_service":true}}`)

	friend := fmt.Sprintf("friend-%d@example-corp.com", time.Now().UnixNano())
	if _, err := maker.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: made.Msg.GetTenantId(), Email: friend, Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	if sent := requestCode(t, h, friend); sent != 0 {
		t.Fatalf("a self-service tenant's invitee got %d sign-in emails, want none", sent)
	}
	u, err := h.Stores.users.FindUserByEmail(ctx, friend)
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if u != nil {
		t.Fatal("a self-service tenant's invitee got an account")
	}
}

// TestRedesign_InviteOnly_RevokedAfterSignUpKeepsTheAccountWithoutMembership:
// the account an invitation admitted outlives the invitation. Revoking it
// afterwards leaves an account that signs in but belongs to no tenant;
// removing access means suspending or deleting the account.
func TestRedesign_InviteOnly_RevokedAfterSignUpKeepsTheAccountWithoutMembership(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "revoked-after-signup-owner")
	setProjectConfig(t, h, `{"access":{"mode":"invite","admit_tenant_invitations":true}}`)

	invitee := fmt.Sprintf("revoked-%d@example-corp.com", time.Now().UnixNano())
	created, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID, Email: invitee, Role: service.RoleMember,
	}))
	if err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	inviteToken := extractMailedToken(t, h, invitee)
	branded := h.ClientWithHost(h.BrandedAuthDomain, nil)
	signIn := func() *connect.Response[identitypb.VerifyEmailLoginCodeResponse] {
		t.Helper()
		if sent := requestCode(t, h, invitee); sent != 1 {
			t.Fatalf("sign-in emails = %d, want 1", sent)
		}
		resp, err := branded.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
			Email: invitee, Code: extractRedesignLoginCode(t, h),
		}))
		if err != nil {
			t.Fatalf("VerifyEmailLoginCode: %v", err)
		}
		return resp
	}
	signIn()

	if err := h.Stores.invitations.SetInvitationStatus(ctx, h.ProjectID, created.Msg.GetInvitation().GetId(), service.InvitationStatusRevoked, 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	again := signIn()
	if _, err := h.AuthedClient(again.Msg.GetAccessToken()).AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: inviteToken,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("AcceptTenantInvitation after revoke = %v, want PermissionDenied", err)
	}
	m, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, owner.tenantID, again.Msg.GetUser().GetId())
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetMembership: %v", err)
	}
	if m != nil {
		t.Fatalf("membership = %+v, want none", m)
	}
}
