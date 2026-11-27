//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// requireManagedAccountRefused fails unless err is PERMISSION_DENIED
// naming a managed account.
func requireManagedAccountRefused(t *testing.T, what string, err error) {
	t.Helper()
	if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "managed_account") {
		t.Fatalf("%s = %v, want PermissionDenied for a managed account", what, err)
	}
}

// TestRedesign_ManagedAccounts_RefusedSelfServicePaths drives, against a
// real Postgres, what a managed account may not do for itself: create a
// tenant, join one by domain, accept another tenant's invitation (which that
// tenant could send, as to any address), change its email, delete itself,
// leave its tenant or merge with another account; each is refused and
// changes nothing, and the account still signs in.
func TestRedesign_ManagedAccounts_RefusedSelfServicePaths(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) {
		enableManagedAccounts(c)
		c.AccountMergeEnabled = true
	})
	setProjectConfig(t, h, `{"access":{"mode":"open","admit_managed_accounts":true},"tenants":{"self_service":true}}`)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-refused")
	delivery := fmt.Sprintf("nia-%d@example.net", time.Now().UnixNano())
	if _, err := createManaged(mt.owner, "nia", mt.domain, "Nia", delivery, service.RoleAdmin); err != nil {
		t.Fatalf("create: %v", err)
	}
	done, err := setUp(h, extractMailedToken(t, h, delivery), validPassword)
	if err != nil {
		t.Fatalf("set up: %v", err)
	}
	address := "nia@" + mt.domain
	nia := brandedClient(h, done.GetAccessToken())

	_, err = nia.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Side project"}))
	requireManagedAccountRefused(t, "CreateTenant", err)
	_, err = nia.JoinTenantByDomain(ctx, connect.NewRequest(&identitypb.JoinTenantByDomainRequest{TenantId: mt.tenantID}))
	requireManagedAccountRefused(t, "JoinTenantByDomain", err)

	other := newManagedTenant(t, h, "managed-other")
	inviteID, token := inviteFrom(t, h, other.owner, address)
	_, err = nia.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: token}))
	requireManagedAccountRefused(t, "accepting another tenant's invitation", err)
	listed, err := other.owner.client.ListTenantInvitations(ctx, connect.NewRequest(&identitypb.ListTenantInvitationsRequest{TenantId: other.tenantID}))
	if err != nil {
		t.Fatalf("ListTenantInvitations: %v", err)
	}
	if invs := listed.Msg.GetInvitations(); len(invs) != 1 || invs[0].GetId() != inviteID || invs[0].GetStatus() != service.InvitationStatusPending {
		t.Fatalf("the other tenant's invitations = %+v, want its one invitation still pending", invs)
	}

	_, err = nia.RequestEmailChange(ctx, connect.NewRequest(&identitypb.RequestEmailChangeRequest{NewEmail: "nia@example.net", CurrentPassword: validPassword}))
	requireManagedAccountRefused(t, "RequestEmailChange", err)
	_, err = nia.DeleteMyAccount(ctx, connect.NewRequest(&identitypb.DeleteMyAccountRequest{}))
	requireManagedAccountRefused(t, "DeleteMyAccount", err)
	_, err = nia.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{TenantId: mt.tenantID, UserId: done.GetUser().GetId()}))
	requireManagedAccountRefused(t, "leaving the tenant", err)

	personal := fmt.Sprintf("nia-personal-%d@example.net", time.Now().UnixNano())
	signupBranded(t, h, personal)
	_, err = nia.MergeAccounts(ctx, connect.NewRequest(&identitypb.MergeAccountsRequest{OtherIdentifier: personal, OtherPassword: validPassword}))
	requireManagedAccountRefused(t, "MergeAccounts", err)

	if a := accountAt(t, h, address); a == nil || a.Status != service.StatusActive || a.ManagedByTenantID != mt.tenantID {
		t.Fatalf("account after the refusals = %+v", a)
	}
	if m, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, mt.tenantID, done.GetUser().GetId()); err != nil || m == nil || m.Status != service.MembershipStatusActive {
		t.Fatalf("membership after the refusals = %+v %v", m, err)
	}
	if _, err := brandedClient(h, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: address, Password: validPassword})); err != nil {
		t.Fatalf("the account still signs in: %v", err)
	}
}

// TestRedesign_ManagedAccounts_WaitingAccountGetsNoSignInCode: an account
// waiting for its set-up gets neither a sign-in code nor a magic link, and
// the request answers as for any address.
func TestRedesign_ManagedAccounts_WaitingAccountGetsNoSignInCode(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedSignIn)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-waiting")
	if _, err := createManaged(mt.owner, "oli", mt.domain, "Oli", "oli@example.net", service.RoleMember); err != nil {
		t.Fatalf("create: %v", err)
	}
	address := "oli@" + mt.domain
	client := brandedClient(h, "")
	h.Mailer.Reset()
	if _, err := client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: address})); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	if _, err := client.RequestMagicLink(ctx, connect.NewRequest(&identitypb.RequestMagicLinkRequest{Email: address, ReturnTo: managedReturnTo})); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	if sent := h.Mailer.Sent(); len(sent) != 0 {
		t.Fatalf("a waiting managed account was sent %d emails, want none", len(sent))
	}
}
