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

// readInvitation reads the invitation token names with no session.
func readInvitation(t *testing.T, h *RedesignHarness, token string) *identitypb.GetTenantInvitationResponse {
	t.Helper()
	resp, err := h.Client.GetTenantInvitation(context.Background(), connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: token}))
	if err != nil {
		t.Fatalf("GetTenantInvitation: %v", err)
	}
	return resp.Msg
}

// TestRedesign_TenantInvitation_ReadByItsTokenWithoutASession drives the
// invitation link's read against a real Postgres: the mailed token describes
// the invitation with no session, says whether the address has an account
// once it has one, is still accepted afterwards, and reads accepted once it
// is; a token no invitation has is NOT_FOUND.
func TestRedesign_TenantInvitation_ReadByItsTokenWithoutASession(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invitation-read-owner")
	inviter, err := h.Stores.users.WithProject(h.ProjectID).GetUser(ctx, owner.userID)
	if err != nil || inviter == nil {
		t.Fatalf("inviter: %v %v", inviter, err)
	}
	invitee := fmt.Sprintf("read-%d@example-corp.com", time.Now().UnixNano())
	_, token := inviteFrom(t, h, owner, invitee)

	got := readInvitation(t, h, token)
	if got.GetTenantId() != owner.tenantID || got.GetTenantName() != "invitation-read-owner tenant" ||
		got.GetInviterName() != inviter.Name || got.GetInviterEmail() != inviter.Email ||
		got.GetEmail() != invitee || got.GetRole() != service.RoleMember ||
		got.GetStatus() != service.InvitationStatusPending || got.GetAccountExists() ||
		got.GetExpiresAtMs() <= time.Now().UnixMilli() {
		t.Fatalf("invitation = %+v", got)
	}

	member := signupVerifiedUser(t, h, invitee)
	if got := readInvitation(t, h, token); !got.GetAccountExists() || got.GetStatus() != service.InvitationStatusPending {
		t.Fatalf("after the address signed up: %+v, want account_exists and still pending", got)
	}
	if _, err := member.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: token})); err != nil {
		t.Fatalf("AcceptTenantInvitation after reading: %v", err)
	}
	if got := readInvitation(t, h, token); got.GetStatus() != service.InvitationStatusAccepted {
		t.Fatalf("status after accepting = %q, want accepted", got.GetStatus())
	}

	_, err = h.Client.GetTenantInvitation(ctx, connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: "0123456789abcdef"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown token = %v, want NotFound", err)
	}
}

// signUpFromInvitation creates the account token's invitation names on the
// branded host, whose project config the control plane resolves.
func signUpFromInvitation(h *RedesignHarness, token string) (*identitypb.SignUpWithTenantInvitationResponse, error) {
	resp, err := h.ClientWithHost(h.BrandedAuthDomain, nil).SignUpWithTenantInvitation(context.Background(),
		connect.NewRequest(&identitypb.SignUpWithTenantInvitationRequest{Token: token, Name: "Ravi Kumar", Password: validPassword}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestRedesign_TenantInvitation_SignUpFromTheLinkThenAccept drives the whole
// link against a real Postgres: an invite-only project that lets invitations
// create accounts, a tenant owner's invitation to an address with no account,
// the account created from the mailed token with a name and a password,
// verified and in no tenant, the invitation still pending until the new
// account accepts it, and the address then refused a second account.
func TestRedesign_TenantInvitation_SignUpFromTheLinkThenAccept(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invitation-signup-owner")
	setProjectConfig(t, h, invitedSignupConfig)
	invitee := fmt.Sprintf("signup-%d@example-corp.com", time.Now().UnixNano())
	_, token := inviteFrom(t, h, owner, invitee)

	signedUp, err := signUpFromInvitation(h, token)
	if err != nil {
		t.Fatalf("SignUpWithTenantInvitation: %v", err)
	}
	user := signedUp.GetUser()
	if user.GetEmail() != invitee || user.GetName() != "Ravi Kumar" || !user.GetEmailVerified() ||
		signedUp.GetAccessToken() == "" || signedUp.GetRefreshToken() == "" || signedUp.GetExpiresIn() <= 0 {
		t.Fatalf("sign-up = %+v", signedUp)
	}
	requireNoMemberships(t, h, user.GetId())
	if got := readInvitation(t, h, token); got.GetStatus() != service.InvitationStatusPending || !got.GetAccountExists() {
		t.Fatalf("after signing up: %+v, want still pending and the address with an account", got)
	}
	if _, err := signUpFromInvitation(h, token); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("a second sign-up = %v, want AlreadyExists", err)
	}

	accepted, err := h.AuthedClient(signedUp.GetAccessToken()).AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: token}))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation with the new session: %v", err)
	}
	if got := accepted.Msg.GetMembership(); got.GetTenantId() != owner.tenantID || got.GetUserId() != user.GetId() {
		t.Fatalf("membership = %+v, want the new account in the inviting tenant", got)
	}
	if _, err := signUpFromInvitation(h, token); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("sign-up from an accepted invitation = %v, want FailedPrecondition", err)
	}
	if _, err := h.ClientWithHost(h.BrandedAuthDomain, nil).PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: invitee, Password: validPassword,
	})); err != nil {
		t.Fatalf("PasswordLogin with the password set at sign-up: %v", err)
	}
}

// TestRedesign_TenantInvitation_RevokedLinkIsClosed: once an owner revokes an
// invitation, its link reads "revoked" and creates no account.
func TestRedesign_TenantInvitation_RevokedLinkIsClosed(t *testing.T) {
	h := startRedesignHarness(t)
	owner := signupOwner(t, h, "invitation-revoked-owner")
	setProjectConfig(t, h, invitedSignupConfig)
	invitee := fmt.Sprintf("revoked-%d@example-corp.com", time.Now().UnixNano())
	invitationID, token := inviteFrom(t, h, owner, invitee)

	if _, err := owner.client.RevokeTenantInvitation(context.Background(), connect.NewRequest(&identitypb.RevokeTenantInvitationRequest{
		TenantId: owner.tenantID, InvitationId: invitationID,
	})); err != nil {
		t.Fatalf("RevokeTenantInvitation: %v", err)
	}
	if got := readInvitation(t, h, token); got.GetStatus() != service.InvitationStatusRevoked || got.GetAccountExists() {
		t.Fatalf("a revoked invitation reads %+v, want revoked with no account", got)
	}
	_, err := signUpFromInvitation(h, token)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), service.ErrInvitationRevoked.Error()) {
		t.Fatalf("sign-up from a revoked invitation = %v, want FailedPrecondition %q", err, service.ErrInvitationRevoked)
	}
	requireNoAccount(t, h, invitee)
}

// TestRedesign_TenantInvitation_SignUpNeedsTheOptInAndAnOpenInvitation: a
// project that has not opted in creates no account from an invitation, and
// neither does an invitation from a tenant a person made through
// self-service CreateTenant, though the project has.
func TestRedesign_TenantInvitation_SignUpNeedsTheOptInAndAnOpenInvitation(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) { c.SelfServiceTenantsEnabled = true })
	ctx := context.Background()
	owner := signupOwner(t, h, "invitation-optin-owner")
	invitee := fmt.Sprintf("optin-%d@example-corp.com", time.Now().UnixNano())
	_, token := inviteFrom(t, h, owner, invitee)

	if _, err := signUpFromInvitation(h, token); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("open project = %v, want FailedPrecondition", err)
	}
	requireNoAccount(t, h, invitee)

	maker := signupVerifiedUser(t, h, fmt.Sprintf("maker-%d@example-corp.com", time.Now().UnixNano()))
	made, err := maker.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Made by a person"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	friend := fmt.Sprintf("friend-%d@example-corp.com", time.Now().UnixNano())
	if _, err := maker.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: made.Msg.GetTenantId(), Email: friend, Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	friendToken := extractMailedToken(t, h, friend)
	setProjectConfig(t, h, `{"access":{"mode":"invite","admit_tenant_invitations":true},"tenants":{"self_service":true}}`)

	if _, err := signUpFromInvitation(h, friendToken); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a self-service tenant's invitation = %v, want PermissionDenied", err)
	}
	requireNoAccount(t, h, friend)
	if _, err := signUpFromInvitation(h, token); err != nil {
		t.Fatalf("the operator tenant's invitation, once opted in: %v", err)
	}
}

// TestRedesign_TenantInvitation_NoMailProvider: a server with no mail
// settings hands the invitation's token to the inviter, so the token creates
// no account and the read does not say whether the address has one.
func TestRedesign_TenantInvitation_NoMailProvider(t *testing.T) {
	h := startRedesignHarnessWithoutMail(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invitation-nomail-owner")
	invitee := fmt.Sprintf("nomail-%d@example-corp.com", time.Now().UnixNano())
	signupMembershipUser(t, h, invitee)
	created, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID, Email: invitee, Role: service.RoleMember,
	}))
	if err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	token := created.Msg.GetRawToken()
	if token == "" || created.Msg.GetEmailSendStatus() != identitypb.EmailSendStatus_EMAIL_SEND_STATUS_NOT_CONFIGURED {
		t.Fatalf("without mail the inviter is handed the token: %+v", created.Msg)
	}
	setProjectConfig(t, h, invitedSignupConfig)

	if got := readInvitation(t, h, token); got.GetAccountExists() || got.GetEmail() != invitee {
		t.Fatalf("read without mail = %+v, want the invitation but not whether the address has an account", got)
	}
	_, err = signUpFromInvitation(h, token)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "invitation_signup_unavailable") {
		t.Fatalf("sign-up without mail = %v, want FailedPrecondition invitation_signup_unavailable, before the address's account is looked at", err)
	}
}

// TestRedesign_TenantInvitation_TokenHandedOutBeforeMailIsConfigured: a
// server with no mail settings hands an invitation's token to its inviter,
// and the invitation records that. Once the project is served with mail
// settings the token still creates no account, with the refusal a server
// without mail gives, while an invitation that server emails does; and the
// read still does not say whether the address has an account, even once it
// has one. The invitee accepts the invitation after a sign-in that proves
// the address.
func TestRedesign_TenantInvitation_TokenHandedOutBeforeMailIsConfigured(t *testing.T) {
	before := startRedesignHarnessWithoutMail(t)
	ctx := context.Background()
	owner := signupOwner(t, before, "invitation-mail-later-owner")
	invitee := fmt.Sprintf("mail-later-%d@example-corp.com", time.Now().UnixNano())
	created, err := owner.client.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: owner.tenantID, Email: invitee, Role: service.RoleMember,
	}))
	if err != nil {
		t.Fatalf("CreateTenantInvitation without mail: %v", err)
	}
	token := created.Msg.GetRawToken()
	if token == "" {
		t.Fatalf("without mail the inviter is handed the token: %+v", created.Msg)
	}

	after := startRedesignHarnessBeside(t, before)
	laterOwner := signupOwner(t, after, "invitation-mail-now-owner")
	setProjectConfig(t, after, invitedSignupConfig)

	_, err = signUpFromInvitation(after, token)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "invitation_signup_unavailable") {
		t.Fatalf("sign-up with mail from a token handed out without it = %v, want FailedPrecondition invitation_signup_unavailable", err)
	}
	requireNoAccount(t, after, invitee)

	emailedTo := fmt.Sprintf("mail-now-%d@example-corp.com", time.Now().UnixNano())
	_, emailedToken := inviteFrom(t, after, laterOwner, emailedTo)
	if _, err := signUpFromInvitation(after, emailedToken); err != nil {
		t.Fatalf("sign-up from an invitation the server emailed: %v", err)
	}

	signedIn := signInWithCode(t, after, invitee)
	if got := readInvitation(t, after, token); got.GetAccountExists() || got.GetStatus() != service.InvitationStatusPending {
		t.Fatalf("read once the address has an account = %+v, want pending without saying so", got)
	}
	accepted, err := after.AuthedClient(signedIn.GetAccessToken()).AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: token}))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation after a proven sign-in: %v", err)
	}
	if got := accepted.Msg.GetMembership(); got.GetTenantId() != owner.tenantID || got.GetUserId() != signedIn.GetUser().GetId() {
		t.Fatalf("membership = %+v, want the invitee in the inviting tenant", got)
	}
}

// TestRedesign_TenantInvitation_NoteFollowsTheServerSetting drives a note
// through the whole stack against a real Postgres: the default project takes
// its invitation-note switch from GATEWAY_TENANT_INVITATION_NOTES_ENABLED, so
// with it on an owner's note is in the mailed invitation, and with it off, the
// default, the same call is FAILED_PRECONDITION and sends nothing.
func TestRedesign_TenantInvitation_NoteFollowsTheServerSetting(t *testing.T) {
	const note = "Your mail address will be jane@example.com"
	invite := func(h *RedesignHarness, owner ownerCaller) (string, error) {
		invitee := fmt.Sprintf("note-%d@example-corp.com", time.Now().UnixNano())
		h.Mailer.Reset()
		_, err := owner.client.CreateTenantInvitation(context.Background(), connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
			TenantId: owner.tenantID, Email: invitee, Role: service.RoleMember, Note: note,
		}))
		return invitee, err
	}

	on := startRedesignHarnessWith(t, func(c *config.Config) { c.TenantInvitationNotesEnabled = true })
	invitee, err := invite(on, signupOwner(t, on, "invitation-note-on"))
	if err != nil {
		t.Fatalf("CreateTenantInvitation with notes on: %v", err)
	}
	sent := on.Mailer.Sent()
	if len(sent) != 1 || sent[0].To != invitee {
		t.Fatalf("emails = %+v, want the one invitation", sent)
	}
	if !strings.Contains(sent[0].Text, "> "+note) || !strings.Contains(sent[0].HTML, note) {
		t.Fatalf("the invitation does not carry the note:\n%s", sent[0].Text)
	}

	off := startRedesignHarness(t)
	if _, err := invite(off, signupOwner(t, off, "invitation-note-off")); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("CreateTenantInvitation with notes off = %v, want FailedPrecondition", err)
	}
	if sent := off.Mailer.Sent(); len(sent) != 0 {
		t.Fatalf("a refused invitation sent %d emails", len(sent))
	}
}
