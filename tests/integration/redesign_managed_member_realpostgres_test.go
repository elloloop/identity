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
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// managedMember is a managed account of a tenant an operator made, set up
// through its set-up link, and the tenant's owner and admin.
type managedMember struct {
	h        *RedesignHarness
	mt       managedTenant
	owner    identityconnectgen.IdentityServiceClient
	ownerID  string
	tenantID string
	address  string
	userID   string
	password string
}

// startManagedHarness boots the harness with managed accounts on and a
// session cache long enough that only an invalidation can end a session
// before the next request.
func startManagedHarness(t *testing.T, mutate func(*config.Config)) *RedesignHarness {
	t.Helper()
	return startRedesignHarnessWith(t, func(c *config.Config) {
		enableManagedAccounts(c)
		c.SessionCacheTTLSeconds = 60
		mutate(c)
	})
}

// newManagedMember makes a tenant with a verified domain and a managed
// account ann@ the domain, created and set up through the RPCs.
func newManagedMember(t *testing.T, h *RedesignHarness, label string) *managedMember {
	t.Helper()
	mt := newManagedTenant(t, h, label)
	setProjectConfig(t, h, managedAccountsConfig)
	userID, _ := setUpManagedAccount(t, h, mt, "ann")
	return &managedMember{
		h: h, mt: mt, owner: mt.owner.client, ownerID: mt.owner.userID, tenantID: mt.tenantID,
		address: "ann@" + mt.domain, userID: userID, password: validPassword,
	}
}

// signIn signs the managed account in with password.
func (m *managedMember) signIn(password string) (*identitypb.PasswordLoginResponse, error) {
	resp, err := brandedClient(m.h, "").PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: m.address, Password: password,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (m *managedMember) mustSignIn(t *testing.T) *identitypb.PasswordLoginResponse {
	t.Helper()
	login, err := m.signIn(m.password)
	if err != nil {
		t.Fatalf("managed PasswordLogin: %v", err)
	}
	return login
}

// requireSignedOut fails unless login's access token and refresh token no
// longer work.
func requireSignedOut(t *testing.T, h *RedesignHarness, what string, login *identitypb.PasswordLoginResponse) {
	t.Helper()
	ctx := context.Background()
	_, err := brandedClient(h, login.GetAccessToken()).ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{}))
	requireConnectCode(t, what+": the access token", err, connect.CodeUnauthenticated)
	_, err = refresh(h, login.GetRefreshToken())
	if err == nil {
		t.Fatalf("%s: the refresh token still works", what)
	}
}

func ownerAddress(t *testing.T, h *RedesignHarness, userID string) string {
	t.Helper()
	u, err := h.Stores.users.WithProject(h.ProjectID).GetUser(context.Background(), userID)
	if err != nil || u == nil {
		t.Fatalf("GetUser(%s): %v %v", userID, u, err)
	}
	return u.Email
}

func (m *managedMember) account(t *testing.T) *service.User {
	t.Helper()
	u, err := m.h.Stores.users.WithProject(m.h.ProjectID).GetUser(context.Background(), m.userID)
	if err != nil || u == nil {
		t.Fatalf("GetUser(%s): %v %v", m.userID, u, err)
	}
	return u
}

// TestRedesign_ManagedMember_SuspendSignsOutAtOnce: suspending a managed
// account ends its sessions in the same write, so its access token stops
// working on the very next request although the session cache would keep it
// for a minute, and its refresh token is gone. The suspension is audited as
// managed, and once an owner restores the account it signs in again.
func TestRedesign_ManagedMember_SuspendSignsOutAtOnce(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-suspend")
	ctx := context.Background()
	login := m.mustSignIn(t)
	if _, err := brandedClient(h, login.GetAccessToken()).ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{})); err != nil {
		t.Fatalf("ListMySessions before the suspension: %v", err)
	}

	suspended, err := m.owner.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	}))
	if err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	if got := suspended.Msg.GetMembership().GetStatus(); got != service.MembershipStatusSuspended {
		t.Fatalf("membership status = %q, want suspended", got)
	}
	requireSignedOut(t, h, "after the suspension", login)
	if _, err := m.signIn(m.password); err == nil {
		t.Fatal("a suspended managed account signed in")
	}
	event := waitForAuditEvent(t, h, m.userID, string(audit.EventTenantMemberSuspended))
	if event.ActorUserID != m.ownerID || event.Details["managed"] != true || event.Details["sessions_ended"] != float64(2) {
		t.Fatalf("suspension event = %+v, want the owner's managed suspension ending the set-up's and the sign-in's sessions", event)
	}

	if _, err := m.owner.RestoreTenantMember(ctx, connect.NewRequest(&identitypb.RestoreTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("RestoreTenantMember: %v", err)
	}
	m.mustSignIn(t)
}

// TestRedesign_ManagedMember_RemoveDeactivatesTheAccount: a managed account
// cannot remove itself; an owner's removal deactivates it, keeping its id and
// address, and ends its sessions at once; it can no longer sign in, and
// removing it again changes nothing.
func TestRedesign_ManagedMember_RemoveDeactivatesTheAccount(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-remove")
	ctx := context.Background()
	login := m.mustSignIn(t)

	_, err := brandedClient(h, login.GetAccessToken()).RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	}))
	requireConnectCode(t, "a managed account leaving", err, connect.CodePermissionDenied)

	if _, err := m.owner.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("RemoveTenantMember: %v", err)
	}
	requireSignedOut(t, h, "after the removal", login)
	if _, err := m.signIn(m.password); err == nil {
		t.Fatal("a removed managed account signed in")
	}
	if u := m.account(t); u.Status != service.StatusDeactivated || u.Email != m.address || u.ManagedByTenantID != m.tenantID {
		t.Fatalf("removed account = %+v, want it deactivated with its address, still the tenant's", u)
	}
	event := waitForAuditEvent(t, h, m.userID, string(audit.EventTenantMemberRemoved))
	if event.ActorUserID != m.ownerID || event.Details["managed"] != true {
		t.Fatalf("removal event = %+v, want the owner's managed removal", event)
	}
	if _, err := m.owner.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("RemoveTenantMember again: %v", err)
	}
}

// TestRedesign_ManagedMember_ResetTakesTheAccountBack drives
// ResetManagedAccount end to end: the account is signed out at once, its
// password stops working, the notice goes to its address before the new
// set-up link goes to the address the owner chose, the old password-reset
// link is spent, and the account sets up again from the new link only.
func TestRedesign_ManagedMember_ResetTakesTheAccountBack(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-reset")
	ctx := context.Background()
	login := m.mustSignIn(t)

	h.Mailer.Reset()
	if _, err := brandedClient(h, "").RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{Email: m.address})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	resetToken := extractMailedToken(t, h, m.address)

	_, err := m.owner.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.ownerID, DeliveryAddress: "owner.home@example.net",
	}))
	requireConnectCode(t, "resetting oneself", err, connect.CodeInvalidArgument)
	_, err = brandedClient(h, login.GetAccessToken()).ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.ownerID, DeliveryAddress: "x@example.net",
	}))
	requireConnectCode(t, "a member resetting", err, connect.CodePermissionDenied)

	h.Mailer.Reset()
	reset, err := m.owner.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.userID, DeliveryAddress: "Ann.Second@Example.net",
	}))
	if err != nil {
		t.Fatalf("ResetManagedAccount: %v", err)
	}
	inv := reset.Msg.GetInvitation()
	if reset.Msg.GetEmailSendStatus() != identitypb.EmailSendStatus_EMAIL_SEND_STATUS_SENT ||
		!inv.GetIsManagedSetup() || inv.GetAccountAddress() != m.address || inv.GetEmail() != "ann.second@example.net" ||
		inv.GetUserId() != m.userID || inv.GetRole() != service.RoleMember || inv.GetStatus() != service.InvitationStatusPending {
		t.Fatalf("reset response = %+v, want a sent, pending member set-up link for the account", reset.Msg)
	}
	requireSignedOut(t, h, "after the reset", login)
	if _, err := m.signIn(m.password); err == nil {
		t.Fatal("the old password still signs in after the reset")
	}
	var to []string
	for _, msg := range h.Mailer.Sent() {
		to = append(to, msg.To)
	}
	if strings.Join(to, ",") != m.address+",ann.second@example.net" {
		t.Fatalf("mail went to %v, want the notice to the account, then the link to the new address", to)
	}
	if !strings.Contains(mailedText(t, h, m.address), "reset") {
		t.Fatalf("the notice does not say the account was reset: %q", mailedText(t, h, m.address))
	}
	link := extractMailedToken(t, h, "ann.second@example.net")
	if u := m.account(t); u.Status != service.StatusInvited || u.PasswordHash != "" || u.SetupEpoch != 2 {
		t.Fatalf("reset account = %+v, want it invited, with no password, at epoch 2", u)
	}
	_, err = brandedClient(h, "").ConfirmPasswordReset(ctx, connect.NewRequest(&identitypb.ConfirmPasswordResetRequest{
		Token: resetToken, NewPassword: "Mall0ry$Pass",
	}))
	requireConnectCode(t, "a reset link mailed before the reset", err, connect.CodeUnauthenticated)
	h.Mailer.Reset()
	if _, err := brandedClient(h, "").RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{Email: m.address})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if sent := h.Mailer.Sent(); len(sent) != 0 {
		t.Fatalf("a reset account waiting to be set up was mailed a password reset: %+v", sent)
	}

	if _, err := setUp(h, link, "N3w$Password!"); err != nil {
		t.Fatalf("set up again: %v", err)
	}
	m.password = "N3w$Password!"
	m.mustSignIn(t)

	event := waitForAuditEvent(t, h, m.userID, string(audit.EventManagedAccountReset))
	if event.ActorUserID != m.ownerID || event.Details["tenant_id"] != m.tenantID || event.Details["sessions_ended"] != float64(2) ||
		event.Details["review"] == nil {
		t.Fatalf("reset event = %+v, want the owner's reset of the account in the tenant", event)
	}
}

// TestRedesign_ManagedMember_ResetIsCappedPerDeliveryAddress: the links sent
// to one delivery address are capped across the project, while the resend
// cooldown does not apply.
func TestRedesign_ManagedMember_ResetIsCappedPerDeliveryAddress(t *testing.T) {
	h := startManagedHarness(t, func(c *config.Config) {
		c.TenantInvitationMaxPerRecipient = 2
		c.TenantInvitationResendCooldownSeconds = 3600
	})
	m := newManagedMember(t, h, "managed-reset-cap")
	ctx := context.Background()
	reset := func() error {
		_, err := m.owner.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
			TenantId: m.tenantID, UserId: m.userID, DeliveryAddress: "capped@example.net",
		}))
		return err
	}
	for i := range 2 {
		if err := reset(); err != nil {
			t.Fatalf("reset %d: %v", i+1, err)
		}
	}
	requireConnectCode(t, "a third reset to the same address", reset(), connect.CodeResourceExhausted)
}

// TestRedesign_ManagedMember_ResetNeedsTheFlagAndTheProject: with the server
// switch off, or the project not admitting managed accounts, a reset is
// FAILED_PRECONDITION and the account keeps working.
func TestRedesign_ManagedMember_ResetNeedsTheFlagAndTheProject(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-reset-policy")
	ctx := context.Background()
	request := connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.userID, DeliveryAddress: "ann.other@example.net",
	})

	setProjectConfig(t, h, `{"access":{"mode":"open"}}`)
	_, err := m.owner.ResetManagedAccount(ctx, request)
	requireConnectCode(t, "a project that does not admit managed accounts", err, connect.CodeFailedPrecondition)

	setProjectConfig(t, h, managedAccountsConfig)
	off := bootRedesignHarnessOn(t, h.ProjectID, h.TenantID, h.BrandedAuthDomain, func(c *config.Config) {
		c.RevocationMode = config.RevocationModeSession
	}, NewRecordingMailer())
	ownerLogin, err := brandedClient(off, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: ownerAddress(t, h, m.ownerID), Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("owner PasswordLogin: %v", err)
	}
	_, err = brandedClient(off, ownerLogin.Msg.GetAccessToken()).ResetManagedAccount(ctx, request)
	requireConnectCode(t, "a server with managed accounts off", err, connect.CodeFailedPrecondition)
	m.mustSignIn(t)
}

// TestRedesign_ManagedMember_PersonalMembersUnchanged: with managed accounts
// off, suspending and removing a personal member behaves as before: their
// access token lasts until it expires.
func TestRedesign_ManagedMember_PersonalMembersUnchanged(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner, _, _ := operatorTenantWithDomain(t, h, "personal-unchanged")
	addr := fmt.Sprintf("personal-%d@example-corp.com", time.Now().UnixNano())
	member := signupVerifiedUser(t, h, addr)
	if _, err := h.Stores.memberships.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: h.ProjectID, TenantID: owner.tenantID, UserID: member.userID,
		Source: service.MembershipSourceAdded, Role: service.RoleMember, Status: service.MembershipStatusActive,
	}); err != nil {
		t.Fatalf("UpsertMembership: %v", err)
	}
	if _, err := owner.client.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: owner.tenantID, UserId: member.userID,
	})); err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	if _, err := member.client.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{})); err != nil {
		t.Fatalf("a suspended personal member's token stopped working: %v", err)
	}
	if _, err := owner.client.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{
		TenantId: owner.tenantID, UserId: member.userID,
	})); err != nil {
		t.Fatalf("RemoveTenantMember: %v", err)
	}
	if _, err := member.client.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{})); err != nil {
		t.Fatalf("a removed personal member's token stopped working: %v", err)
	}
	event := waitForAuditEvent(t, h, member.userID, string(audit.EventTenantMemberRemoved))
	if _, managed := event.Details["managed"]; managed {
		t.Fatalf("a personal member's removal is recorded as managed: %+v", event.Details)
	}
	_, err := owner.client.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: owner.tenantID, UserId: member.userID, DeliveryAddress: addr,
	}))
	requireConnectCode(t, "resetting a personal account with managed accounts off", err, connect.CodeFailedPrecondition)
}

// TestRedesign_ManagedMember_AdminResettingAnAdminTellsTheOwner: an admin may
// reset another admin's managed account, and the tenant's owner is mailed
// that it happened. The owner, a personal account, is no account to reset.
func TestRedesign_ManagedMember_AdminResettingAnAdminTellsTheOwner(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-admin-reset")
	ctx := context.Background()
	if _, err := m.owner.SetTenantMemberRole(ctx, connect.NewRequest(&identitypb.SetTenantMemberRoleRequest{
		TenantId: m.tenantID, UserId: m.userID, Role: service.RoleAdmin,
	})); err != nil {
		t.Fatalf("SetTenantMemberRole: %v", err)
	}
	admin := m.mt.admin.client
	_, err := admin.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.ownerID, DeliveryAddress: "owner.home@example.net",
	}))
	requireConnectCode(t, "resetting the owner, a personal account", err, connect.CodeNotFound)

	h.Mailer.Reset()
	if _, err := admin.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.userID, DeliveryAddress: "ann.admin@example.net",
	})); err != nil {
		t.Fatalf("an admin resetting an admin: %v", err)
	}
	owner, adminAddr := ownerAddress(t, h, m.ownerID), ownerAddress(t, h, m.mt.admin.userID)
	text := mailedText(t, h, owner)
	if !strings.Contains(text, adminAddr+" reset "+m.address+"'s sign-in") {
		t.Fatalf("owner's notice = %q, want who reset which account", text)
	}
	event := waitForAuditEvent(t, h, m.userID, string(audit.EventManagedAccountReset))
	if event.ActorUserID != m.mt.admin.userID || event.Details["owners_notice_due"] != true {
		t.Fatalf("reset event = %+v, want the admin's reset telling the owners", event)
	}
	told := waitForAuditEvent(t, h, m.userID, string(audit.EventManagedAccountResetOwnersNotified))
	if told.ActorUserID != m.mt.admin.userID || told.Details["owners_notified"] != float64(1) {
		t.Fatalf("owners-notified event = %+v, want the one owner reached", told)
	}
}

// TestRedesign_ManagedMember_SwitchedOffStillSignsOut: a server with
// managed accounts switched off, serving a managed account made while they
// were on, still ends its sessions at once when an owner suspends it.
func TestRedesign_ManagedMember_SwitchedOffStillSignsOut(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-switched-off")
	ctx := context.Background()
	off := bootRedesignHarnessOn(t, h.ProjectID, h.TenantID, h.BrandedAuthDomain, func(c *config.Config) {
		c.RevocationMode = config.RevocationModeSession
		c.SessionCacheTTLSeconds = 60
	}, NewRecordingMailer())
	setProjectConfig(t, h, managedAccountsConfig)
	login, err := brandedClient(off, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: m.address, Password: m.password}))
	if err != nil {
		t.Fatalf("managed PasswordLogin on the switched-off server: %v", err)
	}
	ann := brandedClient(off, login.Msg.GetAccessToken())
	if _, err := ann.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{})); err != nil {
		t.Fatalf("ListMySessions while live: %v", err)
	}
	ownerLogin, err := brandedClient(off, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: ownerAddress(t, h, m.ownerID), Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("owner PasswordLogin: %v", err)
	}
	if _, err := brandedClient(off, ownerLogin.Msg.GetAccessToken()).SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("SuspendTenantMember with managed accounts off: %v", err)
	}
	_, err = ann.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{}))
	requireConnectCode(t, "the suspended account's token on the switched-off server", err, connect.CodeUnauthenticated)
}
