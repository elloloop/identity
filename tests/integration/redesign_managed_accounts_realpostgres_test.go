//go:build integration && realpostgres

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

const managedAccountsConfig = `{"access":{"mode":"open","admit_managed_accounts":true}}`

// enableManagedAccounts is the server configuration managed accounts need,
// with a one-second resend cooldown so a test can resend a set-up link.
func enableManagedAccounts(c *config.Config) {
	c.ManagedAccountsEnabled = true
	c.RevocationMode = config.RevocationModeSession
	c.TenantInvitationResendCooldownSeconds = 1
}

// brandedClient is a client on the harness's branded host, which resolves
// the project's config_json, carrying accessToken when it is not "".
func brandedClient(h *RedesignHarness, accessToken string) identityconnectgen.IdentityServiceClient {
	headers := map[string]string{}
	if accessToken != "" {
		headers["Authorization"] = "Bearer " + accessToken
	}
	return h.ClientWithHost(h.BrandedAuthDomain, headers)
}

// managedTenant is a tenant an operator made, with an owner and an admin
// signed in on the branded host and a domain verified for it.
type managedTenant struct {
	tenantID, domain string
	owner, admin     ownerCaller
}

// signupBranded signs addr up on the branded host and returns a client
// carrying its access token, and its id.
func signupBranded(t *testing.T, h *RedesignHarness, addr string) (identityconnectgen.IdentityServiceClient, string) {
	t.Helper()
	signup, err := brandedClient(h, "").PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(%s): %v", addr, err)
	}
	return brandedClient(h, signup.Msg.GetAccessToken()), signup.Msg.GetUser().GetId()
}

// newManagedTenant makes a tenant as an operator does, with an owner and an
// admin, and verifies a fresh domain for it.
func newManagedTenant(t *testing.T, h *RedesignHarness, label string) managedTenant {
	t.Helper()
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	tenantID, err := h.Stores.tenants.CreateTenant(ctx, &service.Tenant{
		ProjectID: h.ProjectID, Name: label + " tenant",
		PrimaryDomain: fmt.Sprintf("%s-primary-%d.example.com", label, stamp), Status: service.TenantStatusLatent,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	mt := managedTenant{tenantID: tenantID, domain: fmt.Sprintf("%s-%d.example.com", label, stamp)}
	for role, caller := range map[string]*ownerCaller{service.RoleOwner: &mt.owner, service.RoleAdmin: &mt.admin} {
		client, userID := signupBranded(t, h, fmt.Sprintf("%s-%s-%d@example-corp.com", label, role, stamp))
		if _, err := h.Stores.memberships.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: h.ProjectID, TenantID: tenantID, UserID: userID,
			Source: service.MembershipSourceAdded, Role: role, Status: service.MembershipStatusActive,
		}); err != nil {
			t.Fatalf("UpsertMembership(%s): %v", role, err)
		}
		*caller = ownerCaller{client: client, userID: userID, tenantID: tenantID}
	}
	claim, err := mt.owner.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId: tenantID, Domain: mt.domain, VerificationMethod: service.DomainVerificationDNSTXT,
	}))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	h.DNS.publish(claim.Msg.GetDnsTxtName(), claim.Msg.GetDnsTxtValue())
	if _, err := mt.owner.client.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{
		DomainId: claim.Msg.GetDomain().GetId(),
	})); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	return mt
}

// createManaged asks caller for a managed account username@domain named
// name, its link sent to delivery.
func createManaged(caller ownerCaller, username, domain, name, delivery, role string) (*identitypb.CreateTenantInvitationResponse, error) {
	resp, err := caller.client.CreateTenantInvitation(context.Background(), connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: caller.tenantID, Email: delivery, Role: role,
		AccountUsername: username, AccountDomain: domain, DisplayName: name,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// requireManagedRefusal fails unless err is code with reason in its
// ManagedAccountRefusedDetails.
func requireManagedRefusal(t *testing.T, what string, err error, code connect.Code, reason identitypb.ManagedAccountRefusal) {
	t.Helper()
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != code {
		t.Fatalf("%s = %v, want %v", what, err, code)
	}
	for _, d := range cerr.Details() {
		msg, derr := d.Value()
		if derr != nil {
			continue
		}
		if details, ok := msg.(*identitypb.ManagedAccountRefusedDetails); ok {
			if details.GetReason() != reason {
				t.Fatalf("%s reason = %v, want %v", what, details.GetReason(), reason)
			}
			return
		}
	}
	t.Fatalf("%s carries no ManagedAccountRefusedDetails: %v", what, err)
}

// accountAt reads the project's account at addr, nil for none.
func accountAt(t *testing.T, h *RedesignHarness, addr string) *service.User {
	t.Helper()
	u, err := h.Stores.users.WithProject(h.ProjectID).FindUserByEmail(context.Background(), addr)
	if err != nil {
		t.Fatalf("FindUserByEmail(%s): %v", addr, err)
	}
	return u
}

// readBranded reads the invitation token names on the branded host.
func readBranded(t *testing.T, h *RedesignHarness, token string) *identitypb.GetTenantInvitationResponse {
	t.Helper()
	resp, err := brandedClient(h, "").GetTenantInvitation(context.Background(), connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: token}))
	if err != nil {
		t.Fatalf("GetTenantInvitation: %v", err)
	}
	return resp.Msg
}

// setUp redeems a set-up token with password on the branded host.
func setUp(h *RedesignHarness, token, password string) (*identitypb.SignUpWithTenantInvitationResponse, error) {
	resp, err := brandedClient(h, "").SignUpWithTenantInvitation(context.Background(), connect.NewRequest(&identitypb.SignUpWithTenantInvitationRequest{
		Token: token, Password: password,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestRedesign_ManagedAccounts_CreateReadSetUpAndList drives a managed
// account's life against a real Postgres: an owner creates it on the
// tenant's verified domain and its set-up link goes to the delivery address;
// the link describes the account; a resend replaces the link; the person sets
// a password with the current link only, which activates the account, joins
// the tenant and signs in; the used link no longer names the account and is
// accepted again only by its own account; and the member list and the
// invitation list say which accounts the tenant manages.
func TestRedesign_ManagedAccounts_CreateReadSetUpAndList(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedAccounts)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-life")
	address := "ann@" + mt.domain
	delivery := fmt.Sprintf("ann-home-%d@example.net", time.Now().UnixNano())

	created, err := createManaged(mt.owner, "Ann", mt.domain, "Ann Lee", delivery, service.RoleMember)
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	inv := created.GetInvitation()
	if !inv.GetIsManagedSetup() || inv.GetAccountAddress() != address || inv.GetEmail() != delivery ||
		inv.GetUserId() == "" || created.GetRawToken() != "" ||
		created.GetEmailSendStatus() != identitypb.EmailSendStatus_EMAIL_SEND_STATUS_SENT {
		t.Fatalf("created = %+v", created)
	}
	account := accountAt(t, h, address)
	if account == nil || account.ID != inv.GetUserId() || account.ManagedByTenantID != mt.tenantID ||
		account.Status != service.StatusInvited || account.SetUpAtMs != 0 || account.SetupEpoch != 1 || account.Name != "Ann Lee" {
		t.Fatalf("account = %+v", account)
	}
	firstToken := extractMailedToken(t, h, delivery)

	got := readBranded(t, h, firstToken)
	if !got.GetIsManagedSetup() || got.GetAccountAddress() != address || got.GetDisplayName() != "Ann Lee" ||
		got.GetEmail() != address || got.GetAccountExists() ||
		got.GetStatus() != service.InvitationStatusPending {
		t.Fatalf("set-up link read = %+v", got)
	}

	_, err = mt.owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: mt.tenantID, Email: address,
	}))
	requireManagedRefusal(t, "an ordinary invitation to the tenant's managed address", err,
		connect.CodeAlreadyExists, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_MANAGED_BY_THIS_TENANT)

	time.Sleep(1100 * time.Millisecond)
	newDelivery := fmt.Sprintf("ann-new-%d@example.net", time.Now().UnixNano())
	resent, err := createManaged(mt.admin, "ann", mt.domain, "Ignored Name", newDelivery, service.RoleMember)
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if resent.GetInvitation().GetUserId() != account.ID || resent.GetInvitation().GetEmail() != newDelivery {
		t.Fatalf("resent = %+v", resent)
	}
	if a := accountAt(t, h, address); a.SetupEpoch != 2 || a.Name != "Ann Lee" {
		t.Fatalf("after resend = %+v, want epoch 2 and the first name kept", a)
	}
	secondToken := extractMailedToken(t, h, newDelivery)
	if stale := readBranded(t, h, firstToken); stale.GetStatus() != service.InvitationStatusRevoked ||
		stale.GetAccountAddress() != "" || stale.GetDisplayName() != "" || stale.GetEmail() != address {
		t.Fatalf("replaced link read = %+v, want revoked and naming no account", stale)
	}
	if _, err := setUp(h, firstToken, validPassword); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("set-up with the replaced link = %v, want FailedPrecondition", err)
	}

	if _, err := mt.owner.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: secondToken})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an owner accepting a pending set-up link = %v, want PermissionDenied", err)
	}

	done, err := setUp(h, secondToken, validPassword)
	if err != nil {
		t.Fatalf("set-up: %v", err)
	}
	if done.GetAccessToken() == "" || done.GetRefreshToken() == "" || done.GetUser().GetId() != account.ID || done.GetUser().GetName() != "Ann Lee" {
		t.Fatalf("set-up = %+v", done)
	}
	a := accountAt(t, h, address)
	if a.Status != service.StatusActive || !a.EmailVerified || a.SetUpAtMs == 0 {
		t.Fatalf("after set-up = %+v", a)
	}
	m, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, mt.tenantID, account.ID)
	if err != nil || m == nil || m.Status != service.MembershipStatusActive || m.Role != service.RoleMember || m.Source != service.MembershipSourceInvited {
		t.Fatalf("membership = %+v %v", m, err)
	}
	if used := readBranded(t, h, secondToken); used.GetStatus() != service.InvitationStatusAccepted || used.GetAccountAddress() != "" {
		t.Fatalf("used link read = %+v", used)
	}
	if _, err := setUp(h, secondToken, validPassword); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("set-up twice = %v, want FailedPrecondition", err)
	}
	ann := brandedClient(h, done.GetAccessToken())
	again, err := ann.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: secondToken}))
	if err != nil || again.Msg.GetMembership().GetUserId() != account.ID || again.Msg.GetMembership().GetStatus() != service.MembershipStatusActive {
		t.Fatalf("the account accepting its own used link = %+v %v, want its membership", again, err)
	}
	if _, err := mt.owner.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: secondToken})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another account accepting a used set-up link = %v, want PermissionDenied", err)
	}
	if _, err := brandedClient(h, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: address, Password: validPassword})); err != nil {
		t.Fatalf("the set-up account signs in with its password: %v", err)
	}

	_, err = createManaged(mt.owner, "ann", mt.domain, "Ann Lee", delivery, service.RoleMember)
	requireManagedRefusal(t, "creating a set-up account again", err,
		connect.CodeAlreadyExists, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_MANAGED_BY_THIS_TENANT)

	members, err := mt.owner.client.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: mt.tenantID}))
	if err != nil {
		t.Fatalf("ListTenantMembers: %v", err)
	}
	kinds := map[string]identitypb.AccountKind{}
	for _, m := range members.Msg.GetMembers() {
		kinds[m.GetUserId()] = m.GetAccountKind()
	}
	if kinds[account.ID] != identitypb.AccountKind_ACCOUNT_KIND_MANAGED || kinds[mt.owner.userID] != identitypb.AccountKind_ACCOUNT_KIND_PERSONAL {
		t.Fatalf("member kinds = %v", kinds)
	}
	invs, err := mt.owner.client.ListTenantInvitations(ctx, connect.NewRequest(&identitypb.ListTenantInvitationsRequest{TenantId: mt.tenantID}))
	if err != nil {
		t.Fatalf("ListTenantInvitations: %v", err)
	}
	for _, i := range invs.Msg.GetInvitations() {
		if !i.GetIsManagedSetup() || i.GetUserId() != account.ID || i.GetAccountAddress() != address {
			t.Fatalf("listed invitation = %+v", i)
		}
	}
	if len(invs.Msg.GetInvitations()) != 2 {
		t.Fatalf("listed %d invitations, want the two set-up links", len(invs.Msg.GetInvitations()))
	}
}

// TestRedesign_ManagedAccounts_CreateRefusals: an address on a domain the
// tenant has not verified, one a person's account holds, an owner's account
// asked by an admin, and an address on the project's own account domain are
// each refused, creating nothing.
func TestRedesign_ManagedAccounts_CreateRefusals(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedAccounts)
	setProjectConfig(t, h, managedAccountsConfig)
	mt := newManagedTenant(t, h, "managed-refusals")
	delivery := "someone@example.net"

	unverified := fmt.Sprintf("unverified-%d.example.com", time.Now().UnixNano())
	_, err := createManaged(mt.owner, "bob", unverified, "Bob", delivery, service.RoleMember)
	requireManagedRefusal(t, "an unverified domain", err,
		connect.CodeFailedPrecondition, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_DOMAIN_UNVERIFIED)
	if accountAt(t, h, "bob@"+unverified) != nil {
		t.Fatal("an account was created on an unverified domain")
	}

	signupBranded(t, h, "carol@"+mt.domain)
	_, err = createManaged(mt.owner, "carol", mt.domain, "Carol", delivery, service.RoleMember)
	requireManagedRefusal(t, "an address a person's account holds", err,
		connect.CodeAlreadyExists, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_ADDRESS_UNAVAILABLE)
	if a := accountAt(t, h, "carol@"+mt.domain); a == nil || a.ManagedByTenantID != "" {
		t.Fatalf("the person's account changed: %+v", a)
	}

	if _, err := createManaged(mt.admin, "dave", mt.domain, "Dave", delivery, service.RoleOwner); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an admin creating an owner = %v, want PermissionDenied", err)
	}
	if accountAt(t, h, "dave@"+mt.domain) != nil {
		t.Fatal("an admin created an owner's account")
	}

	for name, req := range map[string][4]string{
		"no display name":  {"erin", mt.domain, "", delivery},
		"no delivery":      {"erin", mt.domain, "Erin", ""},
		"invalid username": {"erin..x", mt.domain, "Erin", delivery},
		"no domain":        {"erin", "", "Erin", delivery},
	} {
		if _, err := createManaged(mt.owner, req[0], req[1], req[2], req[3], service.RoleMember); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s = %v, want InvalidArgument", name, err)
		}
	}

	setProjectConfig(t, h, fmt.Sprintf(`{"access":{"mode":"open","admit_managed_accounts":true},"accounts":{"domain":%q}}`, mt.domain))
	_, err = createManaged(mt.owner, "frank", mt.domain, "Frank", delivery, service.RoleMember)
	requireManagedRefusal(t, "an address on the project's account domain", err,
		connect.CodeFailedPrecondition, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_POLICY)
}

// TestRedesign_ManagedAccounts_RevokeDeletesTheWaitingAccount: revoking a
// managed account's set-up link deletes the account while it has never been
// set up, whatever the link's status, and frees its address; a link already
// used is refused, keeping the account.
func TestRedesign_ManagedAccounts_RevokeDeletesTheWaitingAccount(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedAccounts)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-revoke")
	address := "gina@" + mt.domain

	created, err := createManaged(mt.owner, "gina", mt.domain, "Gina", "gina@example.net", service.RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	token := extractMailedToken(t, h, "gina@example.net")
	revoked, err := mt.admin.client.RevokeTenantInvitation(ctx, connect.NewRequest(&identitypb.RevokeTenantInvitationRequest{
		TenantId: mt.tenantID, InvitationId: created.GetInvitation().GetId(),
	}))
	if err != nil || revoked.Msg.GetInvitation().GetStatus() != service.InvitationStatusRevoked {
		t.Fatalf("revoke = %+v %v", revoked, err)
	}
	if accountAt(t, h, address) != nil {
		t.Fatal("revoking the set-up link kept the never-set-up account")
	}
	if _, err := setUp(h, token, validPassword); err == nil {
		t.Fatal("a revoked link set an account up")
	}

	time.Sleep(1100 * time.Millisecond)
	recreated, err := createManaged(mt.owner, "gina", mt.domain, "Gina", "gina@example.net", service.RoleMember)
	if err != nil {
		t.Fatalf("recreate on the freed address: %v", err)
	}
	if _, err := setUp(h, extractMailedToken(t, h, "gina@example.net"), validPassword); err != nil {
		t.Fatalf("set-up: %v", err)
	}
	if _, err := mt.owner.client.RevokeTenantInvitation(ctx, connect.NewRequest(&identitypb.RevokeTenantInvitationRequest{
		TenantId: mt.tenantID, InvitationId: recreated.GetInvitation().GetId(),
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("revoking a used set-up link = %v, want FailedPrecondition", err)
	}
	if a := accountAt(t, h, address); a == nil || a.Status != service.StatusActive {
		t.Fatalf("the set-up account = %+v, want kept active", a)
	}
}

// TestRedesign_ManagedAccounts_DarkWithoutTheFlagOrTheOptIn: with the
// server flag off, or the project not opted in, or a self-service tenant
// without its own opt-in, a managed account is refused with POLICY and
// nothing is written, while an ordinary invitation and its listing behave as
// before.
func TestRedesign_ManagedAccounts_DarkWithoutTheFlagOrTheOptIn(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate     func(*config.Config)
		configJSON string
	}{
		"server flag off":    {func(*config.Config) {}, managedAccountsConfig},
		"project opt-in off": {enableManagedAccounts, `{"access":{"mode":"open"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			h := startRedesignHarnessWith(t, tc.mutate)
			setProjectConfig(t, h, tc.configJSON)
			ctx := context.Background()
			mt := newManagedTenant(t, h, "managed-dark")
			_, err := createManaged(mt.owner, "hal", mt.domain, "Hal", "hal@example.net", service.RoleMember)
			requireManagedRefusal(t, "a managed account", err,
				connect.CodeFailedPrecondition, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_POLICY)
			if accountAt(t, h, "hal@"+mt.domain) != nil {
				t.Fatal("a managed account was created while dark")
			}
			invitee := "hal@" + mt.domain
			created, err := mt.owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
				TenantId: mt.tenantID, Email: invitee,
			}))
			if err != nil {
				t.Fatalf("ordinary invitation: %v", err)
			}
			inv := created.Msg.GetInvitation()
			if inv.GetIsManagedSetup() || inv.GetEmail() != invitee || inv.GetAccountAddress() != "" || inv.GetUserId() != "" {
				t.Fatalf("ordinary invitation = %+v", inv)
			}
			read := readBranded(t, h, extractMailedToken(t, h, invitee))
			if read.GetIsManagedSetup() || read.GetEmail() != invitee {
				t.Fatalf("ordinary invitation read = %+v", read)
			}
		})
	}

	t.Run("self-service tenant", func(t *testing.T) {
		h := startRedesignHarnessWith(t, enableManagedAccounts)
		setProjectConfig(t, h, managedAccountsConfig)
		mt := newManagedTenant(t, h, "managed-selfservice")
		markSelfService(t, h, mt.tenantID, mt.owner.userID)
		_, err := createManaged(mt.owner, "ivy", mt.domain, "Ivy", "ivy@example.net", service.RoleMember)
		requireManagedRefusal(t, "a self-service tenant without its opt-in", err,
			connect.CodeFailedPrecondition, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_POLICY)

		setProjectConfig(t, h, `{"access":{"mode":"open","admit_managed_accounts":true,"admit_managed_accounts_self_service":true}}`)
		if _, err := createManaged(mt.owner, "ivy", mt.domain, "Ivy", "ivy@example.net", service.RoleMember); err != nil {
			t.Fatalf("a self-service tenant with its opt-in: %v", err)
		}
		read := readBranded(t, h, extractMailedToken(t, h, "ivy@example.net"))
		if read.GetAccountAddress() != "ivy@"+mt.domain || read.GetDisplayName() != "" {
			t.Fatalf("self-service set-up link read = %+v, want the address and no name", read)
		}
	})
}

// markSelfService records tenantID as made through self-service CreateTenant
// by createdBy.
func markSelfService(t *testing.T, h *RedesignHarness, tenantID, createdBy string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("GATEWAY_POSTGRES_DSN"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `UPDATE tenants SET created_by = $3 WHERE project_id = $1 AND id = $2`,
		h.ProjectID, tenantID, createdBy); err != nil {
		t.Fatalf("mark self-service: %v", err)
	}
}

// TestRedesign_ManagedAccounts_SetUpNeedsItsIssuer: a set-up link stops
// working once the admin who issued it is no longer an owner or admin of the
// tenant, and the set-up is refused, writing nothing.
func TestRedesign_ManagedAccounts_SetUpNeedsItsIssuer(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedAccounts)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-issuer")
	delivery := fmt.Sprintf("quinn-%d@example.net", time.Now().UnixNano())
	if _, err := createManaged(mt.admin, "quinn", mt.domain, "Quinn", delivery, service.RoleMember); err != nil {
		t.Fatalf("create: %v", err)
	}
	token := extractMailedToken(t, h, delivery)
	if _, err := mt.owner.client.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{TenantId: mt.tenantID, UserId: mt.admin.userID})); err != nil {
		t.Fatalf("RemoveTenantMember(admin): %v", err)
	}
	if _, err := setUp(h, token, validPassword); err == nil {
		t.Fatal("a link whose issuer was removed set the account up")
	}
	if a := accountAt(t, h, "quinn@"+mt.domain); a != nil && a.Status != service.StatusInvited {
		t.Fatalf("account after the refused set-up = %+v, want still waiting", a)
	}
}
