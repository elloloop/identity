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

const invitedSignupConfig = `{"access":{"mode":"invite","admit_tenant_invitations":true}}`

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

// signInWithCode signs addr in on the branded host with a mailed code.
func signInWithCode(t *testing.T, h *RedesignHarness, addr string) *identitypb.VerifyEmailLoginCodeResponse {
	t.Helper()
	if sent := requestCode(t, h, addr); sent != 1 {
		t.Fatalf("sign-in emails to %s = %d, want 1", addr, sent)
	}
	resp, err := h.ClientWithHost(h.BrandedAuthDomain, nil).VerifyEmailLoginCode(context.Background(),
		connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: addr, Code: extractRedesignLoginCode(t, h)}))
	if err != nil {
		t.Fatalf("VerifyEmailLoginCode(%s): %v", addr, err)
	}
	return resp.Msg
}

// inviteFrom has owner invite addr to its tenant and returns the invitation id
// and the mailed token.
func inviteFrom(t *testing.T, h *RedesignHarness, owner ownerCaller, addr string) (string, string) {
	t.Helper()
	created, err := owner.client.CreateTenantInvitation(context.Background(), connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID, Email: addr, Role: service.RoleMember,
	}))
	if err != nil {
		t.Fatalf("CreateTenantInvitation(%s): %v", addr, err)
	}
	return created.Msg.GetInvitation().GetId(), extractMailedToken(t, h, addr)
}

// requireNoAccount fails when addr has an account in the harness project.
func requireNoAccount(t *testing.T, h *RedesignHarness, addr string) {
	t.Helper()
	u, err := h.Stores.users.FindUserByEmail(context.Background(), addr)
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("FindUserByEmail(%s): %v", addr, err)
	}
	if u != nil {
		t.Fatalf("%s got an account", addr)
	}
}

// requireNoMemberships fails when userID holds any membership in the project.
func requireNoMemberships(t *testing.T, h *RedesignHarness, userID string) {
	t.Helper()
	ms, err := h.Stores.memberships.ListMembershipsForUser(context.Background(), h.ProjectID, userID)
	if err != nil {
		t.Fatalf("ListMembershipsForUser: %v", err)
	}
	if len(ms) != 0 {
		t.Fatalf("memberships = %+v, want none", ms)
	}
}

// TestRedesign_InviteOnly_InvitedAddressSignsUpAndAccepts drives an invite-only
// project with admit_tenant_invitations end to end against a real Postgres, on
// the branded host whose project config the control plane resolves: a tenant
// owner invites an address that has no account, the address signs in with an
// emailed code, which creates its account, and the new account accepts the
// invitation. An address with no invitation gets no code and no account, and
// the invited address still cannot sign up with a password.
func TestRedesign_InviteOnly_InvitedAddressSignsUpAndAccepts(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invited-signup-owner")
	setProjectConfig(t, h, invitedSignupConfig)

	invitee := fmt.Sprintf("invited-%d@example-corp.com", time.Now().UnixNano())
	_, inviteToken := inviteFrom(t, h, owner, invitee)

	_, err := h.ClientWithHost(h.BrandedAuthDomain, nil).PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: invitee, Password: validPassword,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("PasswordSignup of an invited address = %v, want PermissionDenied", err)
	}

	signedIn := signInWithCode(t, h, invitee)
	requireNoMemberships(t, h, signedIn.GetUser().GetId())
	accepted, err := h.AuthedClient(signedIn.GetAccessToken()).AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: inviteToken,
	}))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation: %v", err)
	}
	if got := accepted.Msg.GetMembership(); got.GetTenantId() != owner.tenantID || got.GetUserId() != signedIn.GetUser().GetId() {
		t.Fatalf("membership = %+v, want the new account in the inviting tenant", got)
	}

	stranger := fmt.Sprintf("stranger-%d@example-corp.com", time.Now().UnixNano())
	if sent := requestCode(t, h, stranger); sent != 0 {
		t.Fatalf("an address with no invitation got %d emails, want none", sent)
	}
	requireNoAccount(t, h, stranger)
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
	requireNoAccount(t, h, friend)
}

// TestRedesign_InviteOnly_RevokedAfterSignUpKeepsTheAccountWithoutMembership:
// the account an invitation admitted outlives the invitation. Revoking it
// afterwards leaves an account that signs in but belongs to no tenant;
// removing access means suspending or deleting the account.
func TestRedesign_InviteOnly_RevokedAfterSignUpKeepsTheAccountWithoutMembership(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "revoked-after-signup-owner")
	setProjectConfig(t, h, invitedSignupConfig)

	invitee := fmt.Sprintf("revoked-%d@example-corp.com", time.Now().UnixNano())
	invitationID, inviteToken := inviteFrom(t, h, owner, invitee)
	signInWithCode(t, h, invitee)

	if err := h.Stores.invitations.SetInvitationStatus(ctx, h.ProjectID, invitationID, service.InvitationStatusRevoked, 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	again := signInWithCode(t, h, invitee)
	if _, err := h.AuthedClient(again.GetAccessToken()).AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: inviteToken,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("AcceptTenantInvitation after revoke = %v, want PermissionDenied", err)
	}
	requireNoMemberships(t, h, again.GetUser().GetId())
}

// TestRedesign_InviteOnly_InviteeJoinsNoDomainTenant: an invitee whose email
// domain another tenant has verified does not join that tenant through the
// domain: the invitation admits it to the inviting tenant alone, on
// acceptance. A sign-up on the same domain that no invitation admitted does
// join it, which shows the domain tenant was ready to take members.
func TestRedesign_InviteOnly_InviteeJoinsNoDomainTenant(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) { c.SelfServiceTenantsEnabled = true })
	domainTenant, domain := companyWithVerifiedDomain(t, h)
	owner := signupOwner(t, h, "domain-invite-owner")
	setProjectConfig(t, h, invitedSignupConfig)

	invitee := "invitee@" + domain
	inviteFrom(t, h, owner, invitee)
	signedIn := signInWithCode(t, h, invitee)

	control := signupDomainMember(t, h, "control@"+domain, domainTenant)
	if control.userID == "" {
		t.Fatal("the control sign-up has no account")
	}
	requireNoMemberships(t, h, signedIn.GetUser().GetId())
}
