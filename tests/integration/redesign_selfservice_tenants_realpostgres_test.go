//go:build integration && realpostgres

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// startSelfServiceHarness boots the redesign harness with self-service
// tenants on for the default project and tenant selection on, its status
// cache strict so a suspension is seen on the very next request.
func startSelfServiceHarness(t *testing.T) *RedesignHarness {
	t.Helper()
	return startRedesignHarnessWith(t, func(c *config.Config) {
		c.SelfServiceTenantsEnabled = true
		c.TenantSelectionEnabled = true
		c.TenantStatusCacheTTLSeconds = 0
	})
}

// TestRedesign_TenantSelection_OffByDefault: with the switch off, a refresh
// that names a tenant the caller owns is FAILED_PRECONDITION with the
// selection-refused detail, and the refresh token, unspent, still rotates
// without one.
func TestRedesign_TenantSelection_OffByDefault(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) { c.SelfServiceTenantsEnabled = true })
	ctx := context.Background()

	addr := fmt.Sprintf("ss-off-%d@example.com", time.Now().UnixNano())
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	verifyMailedEmail(t, h, h.Client, addr)
	created, err := h.AuthedClient(signup.Msg.GetAccessToken()).CreateTenant(ctx,
		connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Acme"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	_, err = h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: signup.Msg.GetRefreshToken(), TenantId: created.Msg.GetTenantId(),
	}))
	requireSelectionRefused(t, "selecting with selection off", err, connect.CodeFailedPrecondition,
		identitypb.TenantSelectionRefusal_TENANT_SELECTION_REFUSAL_NOT_ENABLED)
	if _, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: signup.Msg.GetRefreshToken(),
	})); err != nil {
		t.Fatalf("the refused refresh token must still rotate: %v", err)
	}
}

// TestRedesign_SelfServiceTenants_EndToEnd drives a self-service tenant
// through its life over the wire: a person signs up, verifies their email,
// creates a tenant and sees it in ListMyTenants; a refresh that selects it
// mints a token whose tenant claim is that tenant, and the token
// authenticates; suspending the tenant ends the token at its next request,
// refuses a new selection and stops its owner administering it, while a
// plain refresh still rotates; and the creation is audited.
func TestRedesign_SelfServiceTenants_EndToEnd(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()

	addr := fmt.Sprintf("ss-owner-%d@example.com", time.Now().UnixNano())
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	verifyMailedEmail(t, h, h.Client, addr)
	userID := signup.Msg.GetUser().GetId()
	owner := h.AuthedClient(signup.Msg.GetAccessToken())

	created, err := owner.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Acme Robotics"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()
	if m := created.Msg.GetMembership(); m.GetRole() != service.RoleOwner || m.GetSource() != service.MembershipSourceCreated {
		t.Fatalf("creator membership = %+v, want an owner with source created", m)
	}

	mine, err := owner.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListMyTenants: %v", err)
	}
	if !listsTenant(mine.Msg.GetTenants(), tenantID, service.RoleOwner) {
		t.Fatalf("ListMyTenants = %+v, want %s as owner", mine.Msg.GetTenants(), tenantID)
	}

	selected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: signup.Msg.GetRefreshToken(),
		TenantId:     tenantID,
	}))
	if err != nil {
		t.Fatalf("RefreshToken selecting the tenant: %v", err)
	}
	if got := decodeTokenTenantClaim(t, selected.Msg.GetAccessToken()); got != tenantID {
		t.Fatalf("selected token's tenant claim = %q, want %q", got, tenantID)
	}
	inTenant := h.AuthedClient(selected.Msg.GetAccessToken())
	if _, err := inTenant.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{})); err != nil {
		t.Fatalf("an authenticated RPC with the tenant's token: %v", err)
	}

	suspendTenant(t, h, tenantID)
	_, err = inTenant.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	requireConnectCode(t, "a suspended tenant's token", err, connect.CodeUnauthenticated)
	_, err = owner.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: "colleague@example.com", Role: service.RoleMember,
	}))
	requireConnectCode(t, "inviting into a suspended tenant", err, connect.CodePermissionDenied)

	_, err = h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: selected.Msg.GetRefreshToken(),
		TenantId:     tenantID,
	}))
	requireConnectCode(t, "selecting a suspended tenant", err, connect.CodePermissionDenied)
	plain, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: selected.Msg.GetRefreshToken(),
	}))
	if err != nil {
		t.Fatalf("a plain refresh after the refused selection: %v", err)
	}
	if plain.Msg.GetRefreshToken() == "" || plain.Msg.GetRefreshToken() == selected.Msg.GetRefreshToken() {
		t.Fatal("the plain refresh did not rotate the refresh token")
	}
	if got := decodeTokenTenantClaim(t, plain.Msg.GetAccessToken()); got != h.TenantID {
		t.Fatalf("plain refresh tenant claim = %q, want the default %q", got, h.TenantID)
	}

	event := waitForAuditEvent(t, h, userID, string(audit.EventTenantCreated))
	if event.ActorUserID != userID || event.TargetUserID != userID || !event.Success {
		t.Fatalf("tenant_created event = %+v, want a success with the creator as actor and target", event)
	}
	if event.Details["tenant_id"] != tenantID || event.Details["project_id"] != h.ProjectID {
		t.Fatalf("tenant_created details = %+v, want tenant %s in project %s", event.Details, tenantID, h.ProjectID)
	}
}

// TestRedesign_SelfServiceTenants_CallerInAnotherProject: a person who signed
// up in a project other than the deployment's default can create a tenant
// there and accept an invitation to one, each landing in that project.
func TestRedesign_SelfServiceTenants_CallerInAnotherProject(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	proj, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "Second Project",
		StorageScopeId: fmt.Sprintf("ss-second-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := proj.Msg.GetProjectId()
	host := fmt.Sprintf("ss-second-%d.acme.test", unique)
	if _, err := admin.AdminAddProjectAuthDomain(ctx, connect.NewRequest(&identitypb.AdminAddProjectAuthDomainRequest{
		ProjectId: projectID, Hostname: host, IsPrimary: true,
	})); err != nil {
		t.Fatalf("AdminAddProjectAuthDomain: %v", err)
	}
	_, version, err := h.Stores.controlPlane.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if _, _, err := h.Stores.controlPlane.UpdateProjectConfig(ctx, projectID, version,
		`{"access":{"mode":"open"},"tenants":{"self_service":true}}`); err != nil {
		t.Fatalf("UpdateProjectConfig: %v", err)
	}

	signupOnHost := func(label string) (identityconnectgen.IdentityServiceClient, string, string) {
		t.Helper()
		addr := fmt.Sprintf("%s-%d@corp.example.com", label, unique)
		resp, err := h.ClientWithHost(host, nil).PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
			Email: addr, Password: validPassword,
		}))
		if err != nil {
			t.Fatalf("PasswordSignup(%s) on %s: %v", label, host, err)
		}
		verifyMailedEmail(t, h, h.ClientWithHost(host, nil), addr)
		if got := decodeTokenProjectClaim(t, resp.Msg.GetAccessToken()); got != projectID {
			t.Fatalf("%s signed up into project %q, want %q", label, got, projectID)
		}
		client := identityconnectgen.NewIdentityServiceClient(
			&redesignHTTPClient{base: h.HTTP, token: resp.Msg.GetAccessToken(), host: host}, h.BaseURL)
		return client, resp.Msg.GetUser().GetId(), addr
	}

	owner, ownerID, _ := signupOnHost("ss-second-owner")
	created, err := owner.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Second Co"}))
	if err != nil {
		t.Fatalf("CreateTenant by a caller of %s: %v", projectID, err)
	}
	tenantID := created.Msg.GetTenantId()
	tenant, err := h.Stores.tenants.GetTenant(ctx, projectID, tenantID)
	if err != nil || tenant == nil || tenant.CreatedBy != ownerID {
		t.Fatalf("GetTenant(%s, %s) = %+v, %v; want the caller's tenant in that project", projectID, tenantID, tenant, err)
	}

	invitee, inviteeID, inviteeAddr := signupOnHost("ss-second-invitee")
	if _, err := owner.CreateTenantInvitation(ctx, connect.NewRequest(&identitypb.CreateTenantInvitationRequest{
		TenantId: tenantID, Email: inviteeAddr, Role: service.RoleMember,
	})); err != nil {
		t.Fatalf("CreateTenantInvitation: %v", err)
	}
	accepted, err := invitee.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{
		Token: extractMailedToken(t, h, inviteeAddr),
	}))
	if err != nil {
		t.Fatalf("AcceptTenantInvitation by a caller of %s: %v", projectID, err)
	}
	if m := accepted.Msg.GetMembership(); m.GetUserId() != inviteeID || m.GetTenantId() != tenantID {
		t.Fatalf("accepted membership = %+v", m)
	}
	mem, err := h.Stores.memberships.GetMembership(ctx, projectID, tenantID, inviteeID)
	if err != nil || mem == nil || mem.Status != service.MembershipStatusActive {
		t.Fatalf("GetMembership(%s) = %+v, %v; want an active membership in that project", projectID, mem, err)
	}
}

// TestRedesign_SelfServiceTenants_DomainSquatting: a person who creates a
// tenant and registers a company's domain they do not own captures none of
// the company's signups, and the company can still register and verify its
// domain; the record the company publishes does not verify the other claim.
func TestRedesign_SelfServiceTenants_DomainSquatting(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	unique := time.Now().UnixNano()
	domain := fmt.Sprintf("squatted-%d.example.com", unique)

	newTenantOwner := func(addr, name string) (identityconnectgen.IdentityServiceClient, string) {
		t.Helper()
		user := signupVerifiedUser(t, h, addr)
		created, err := user.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: name}))
		if err != nil {
			t.Fatalf("CreateTenant(%s): %v", name, err)
		}
		return user.client, created.Msg.GetTenantId()
	}
	registerDomain := func(client identityconnectgen.IdentityServiceClient, tenantID string) *identitypb.CreateDomainResponse {
		t.Helper()
		resp, err := client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
			TenantId: tenantID, Domain: domain, VerificationMethod: service.DomainVerificationDNSTXT,
		}))
		if err != nil {
			t.Fatalf("CreateDomain(%s) for %s: %v", domain, tenantID, err)
		}
		return resp.Msg
	}

	squatter, squatTenant := newTenantOwner(fmt.Sprintf("squatter-%d@corp.example.com", unique), "Not The Company")
	squat := registerDomain(squatter, squatTenant)

	early := signupMembershipUser(t, h, "early@"+domain)
	if m := waitForDomainMembership(t, h, early.userID); m.TenantID == squatTenant {
		t.Fatalf("a signup from %s joined the tenant that only registered the domain", domain)
	}

	company, companyTenant := newTenantOwner("it@"+domain, "The Company")
	own := registerDomain(company, companyTenant)
	if own.GetDnsTxtValue() == squat.GetDnsTxtValue() {
		t.Fatal("two tenants' claims on one domain were given the same challenge")
	}
	h.DNS.publish(own.GetDnsTxtName(), own.GetDnsTxtValue())

	_, err := squatter.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{DomainId: squat.GetDomain().GetId()}))
	requireConnectCode(t, "the squatter verifying with the company's record", err, connect.CodePermissionDenied)
	verified, err := company.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{DomainId: own.GetDomain().GetId()}))
	if err != nil {
		t.Fatalf("the company verifying its domain: %v", err)
	}
	if verified.Msg.GetDomain().GetStatus() != service.DomainStatusVerified {
		t.Fatalf("company domain status = %q, want verified", verified.Msg.GetDomain().GetStatus())
	}

	h.DNS.publish(own.GetDnsTxtName(), own.GetDnsTxtValue(), squat.GetDnsTxtValue())
	_, err = squatter.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{DomainId: squat.GetDomain().GetId()}))
	requireConnectCode(t, "verifying a domain another tenant verified", err, connect.CodeAlreadyExists)

	late := signupMembershipUser(t, h, "late@"+domain)
	if m := waitForDomainMembership(t, h, late.userID); m.TenantID != companyTenant {
		t.Fatalf("a signup after verification joined %s, want the company's tenant %s", m.TenantID, companyTenant)
	}
}

// TestRedesign_SelfServiceTenants_UnverifiedDomainMemberChangesEmail: an
// account that signs up unverified on a company's domain gets a domain
// membership that counts for nothing, and confirming an email change to an
// address it does control, which verifies the account, does not make it
// count: the change ends the membership, and a membership left active, as
// one from before the change ended them, still does not count off the
// domain. ListMyTenants never lists the tenant and a refresh never selects it.
func TestRedesign_SelfServiceTenants_UnverifiedDomainMemberChangesEmail(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	companyTenant, domain := companyWithVerifiedDomain(t, h)

	addr := "claimant@" + domain
	member := signupDomainMember(t, h, addr, companyTenant)
	member.refresh = requireNotInTenant(t, h, "unverified, on the domain", member.access, member.refresh, companyTenant)

	moved := fmt.Sprintf("claimant-%d@elsewhere.example.com", time.Now().UnixNano())
	member = changeEmailAndSignIn(t, h, member, moved)
	if m := domainMembership(t, h, member.userID, companyTenant); m.Status != service.MembershipStatusInactive {
		t.Fatalf("domain membership after the email change = %q, want inactive", m.Status)
	}
	member.refresh = requireNotInTenant(t, h, "verified, off the domain", member.access, member.refresh, companyTenant)

	if _, err := h.Stores.memberships.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: h.ProjectID, TenantID: companyTenant, UserID: member.userID,
		Source: service.MembershipSourceDomain, Role: service.RoleMember, Status: service.MembershipStatusActive,
	}); err != nil {
		t.Fatalf("UpsertMembership: %v", err)
	}
	requireNotInTenant(t, h, "verified, off the domain, membership active", member.access, member.refresh, companyTenant)
}

// TestRedesign_SelfServiceTenants_VerifiedDomainMemberMovesOffTheDomain: a
// verified account on a company's domain acts in the company's tenant
// through its domain membership until it moves its email off the domain;
// then neither ListMyTenants nor a refresh gives it the tenant.
func TestRedesign_SelfServiceTenants_VerifiedDomainMemberMovesOffTheDomain(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	companyTenant, domain := companyWithVerifiedDomain(t, h)

	addr := "person@" + domain
	member := signupDomainMember(t, h, addr, companyTenant)
	if _, err := h.Client.VerifyEmail(ctx, connect.NewRequest(&identitypb.VerifyEmailRequest{
		Token: extractMailedToken(t, h, addr),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	mine, err := h.AuthedClient(member.access).ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListMyTenants: %v", err)
	}
	if !listsTenant(mine.Msg.GetTenants(), companyTenant, service.RoleMember) {
		t.Fatalf("ListMyTenants = %+v, want the company's tenant once the email is verified", mine.Msg.GetTenants())
	}
	selected, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: member.refresh, TenantId: companyTenant,
	}))
	if err != nil {
		t.Fatalf("RefreshToken selecting the company's tenant: %v", err)
	}
	if got := decodeTokenTenantClaim(t, selected.Msg.GetAccessToken()); got != companyTenant {
		t.Fatalf("selected token's tenant claim = %q, want %q", got, companyTenant)
	}
	member.refresh = selected.Msg.GetRefreshToken()

	moved := fmt.Sprintf("person-%d@elsewhere.example.com", time.Now().UnixNano())
	member = changeEmailAndSignIn(t, h, member, moved)
	requireNotInTenant(t, h, "verified, moved off the domain", member.access, member.refresh, companyTenant)
}

// verifyMailedEmail verifies addr with the link signup mailed it, through
// client, which must reach addr's project.
func verifyMailedEmail(t *testing.T, h *RedesignHarness, client identityconnectgen.IdentityServiceClient, addr string) {
	t.Helper()
	if _, err := client.VerifyEmail(context.Background(), connect.NewRequest(&identitypb.VerifyEmailRequest{
		Token: extractMailedToken(t, h, addr),
	})); err != nil {
		t.Fatalf("VerifyEmail(%s): %v", addr, err)
	}
}

// signupVerifiedUser signs up addr and verifies it, as creating a tenant and
// accepting an invitation require.
func signupVerifiedUser(t *testing.T, h *RedesignHarness, addr string) membershipUser {
	t.Helper()
	user := signupMembershipUser(t, h, addr)
	verifyMailedEmail(t, h, h.Client, addr)
	return user
}

// suspendTenant suspends tenantID in the harness's project as an operator
// does, through AdminSuspendTenant.
func suspendTenant(t *testing.T, h *RedesignHarness, tenantID string) {
	t.Helper()
	if _, err := h.adminClient(harnessAdminSecret).AdminSuspendTenant(context.Background(), connect.NewRequest(&identitypb.AdminSuspendTenantRequest{
		ProjectId: h.ProjectID, TenantId: tenantID, Reason: "suspended by the test",
	})); err != nil {
		t.Fatalf("AdminSuspendTenant(%s): %v", tenantID, err)
	}
}

// domainSession is a signed-in account's id and tokens.
type domainSession struct {
	userID, password, access, refresh string
}

// companyWithVerifiedDomain signs up a company's owner, who creates the
// company's tenant and verifies a fresh domain for it, so later signups on
// the domain join that tenant through the domain.
func companyWithVerifiedDomain(t *testing.T, h *RedesignHarness) (tenantID, domain string) {
	t.Helper()
	ctx := context.Background()
	domain = fmt.Sprintf("company-%d.example.com", time.Now().UnixNano())
	owner := signupVerifiedUser(t, h, "owner@"+domain)
	created, err := owner.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "The Company"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	claim, err := owner.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId: created.Msg.GetTenantId(), Domain: domain, VerificationMethod: service.DomainVerificationDNSTXT,
	}))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	h.DNS.publish(claim.Msg.GetDnsTxtName(), claim.Msg.GetDnsTxtValue())
	if _, err := owner.client.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{
		DomainId: claim.Msg.GetDomain().GetId(),
	})); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	return created.Msg.GetTenantId(), domain
}

// signupDomainMember signs up addr, on the company's domain, and waits for
// the domain membership signup gives it in tenantID.
func signupDomainMember(t *testing.T, h *RedesignHarness, addr, tenantID string) domainSession {
	t.Helper()
	signup, err := h.Client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(%s): %v", addr, err)
	}
	s := domainSession{
		userID: signup.Msg.GetUser().GetId(), password: validPassword,
		access: signup.Msg.GetAccessToken(), refresh: signup.Msg.GetRefreshToken(),
	}
	if m := waitForDomainMembership(t, h, s.userID); m.TenantID != tenantID || m.Status != service.MembershipStatusActive {
		t.Fatalf("signup's domain membership = %+v, want an active one in %s", m, tenantID)
	}
	return s
}

// changeEmailAndSignIn confirms an email change to newAddr, which verifies
// it, and signs in again: the confirmation ends every session.
func changeEmailAndSignIn(t *testing.T, h *RedesignHarness, s domainSession, newAddr string) domainSession {
	t.Helper()
	ctx := context.Background()
	if _, err := h.AuthedClient(s.access).RequestEmailChange(ctx, connect.NewRequest(&identitypb.RequestEmailChangeRequest{
		NewEmail: newAddr, CurrentPassword: s.password,
	})); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	confirm, err := h.Client.ConfirmEmailChange(ctx, connect.NewRequest(&identitypb.ConfirmEmailChangeRequest{
		Token: extractMailedToken(t, h, newAddr),
	}))
	if err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}
	if !confirm.Msg.GetUser().GetEmailVerified() {
		t.Fatal("the confirmed address must be verified")
	}
	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: newAddr, Password: s.password,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin(%s): %v", newAddr, err)
	}
	s.access, s.refresh = login.Msg.GetAccessToken(), login.Msg.GetRefreshToken()
	return s
}

// domainMembership is userID's membership in tenantID.
func domainMembership(t *testing.T, h *RedesignHarness, userID, tenantID string) *service.TenantMembership {
	t.Helper()
	m, err := h.Stores.memberships.GetMembership(context.Background(), h.ProjectID, tenantID, userID)
	if err != nil || m == nil {
		t.Fatalf("GetMembership(%s, %s) = %v, %v", tenantID, userID, m, err)
	}
	return m
}

// requireNotInTenant asserts the account neither sees tenantID in
// ListMyTenants nor gets it from a refresh, which is refused as not a member
// and leaves the refresh token to rotate without a selection. It returns the
// rotated refresh token.
func requireNotInTenant(t *testing.T, h *RedesignHarness, what, access, refresh, tenantID string) string {
	t.Helper()
	ctx := context.Background()
	mine, err := h.AuthedClient(access).ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	if err != nil {
		t.Fatalf("%s: ListMyTenants: %v", what, err)
	}
	for _, ut := range mine.Msg.GetTenants() {
		if ut.GetTenantId() == tenantID {
			t.Fatalf("%s: ListMyTenants lists %s", what, tenantID)
		}
	}
	_, err = h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: refresh, TenantId: tenantID,
	}))
	requireSelectionRefused(t, what+": selecting the tenant", err, connect.CodePermissionDenied,
		identitypb.TenantSelectionRefusal_TENANT_SELECTION_REFUSAL_NOT_A_MEMBER)
	rotated, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: refresh,
	}))
	if err != nil {
		t.Fatalf("%s: the refused refresh token must still rotate: %v", what, err)
	}
	return rotated.Msg.GetRefreshToken()
}

// requireSelectionRefused asserts err is a tenant-selection refusal with
// code and reason, carrying the detail that tells a client its refresh token
// was not consumed.
func requireSelectionRefused(t *testing.T, what string, err error, code connect.Code, reason identitypb.TenantSelectionRefusal) {
	t.Helper()
	requireConnectCode(t, what, err, code)
	var cerr *connect.Error
	errors.As(err, &cerr)
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if got, ok := v.(*identitypb.TenantSelectionRefusedDetails); ok {
				if got.GetReason() != reason {
					t.Fatalf("%s: refusal reason = %v, want %v", what, got.GetReason(), reason)
				}
				return
			}
		}
	}
	t.Fatalf("%s: no TenantSelectionRefusedDetails on %v", what, err)
}

// listsTenant reports whether tenants holds tenantID with role.
func listsTenant(tenants []*identitypb.UserTenant, tenantID, role string) bool {
	for _, ut := range tenants {
		if ut.GetTenantId() == tenantID && ut.GetRole() == role {
			return true
		}
	}
	return false
}

// decodeTokenTenantClaim returns the `tenant` claim of a JWT access token
// without verifying it: the test asserts which tenant the server stamped.
func decodeTokenTenantClaim(t *testing.T, accessToken string) string {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %q", accessToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims struct {
		Tenant string `json:"tenant"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal token claims: %v", err)
	}
	return claims.Tenant
}

// waitForDomainMembership returns the domain-derived membership signup gave
// userID in the harness's default project, polling while auto-formation
// lands.
func waitForDomainMembership(t *testing.T, h *RedesignHarness, userID string) *service.TenantMembership {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ms, err := h.Stores.memberships.ListMembershipsForUser(ctx, h.ProjectID, userID)
		if err != nil {
			t.Fatalf("ListMembershipsForUser(%s): %v", userID, err)
		}
		for _, m := range ms {
			if m.Source == service.MembershipSourceDomain {
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no domain membership for %s within the deadline", userID)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitForAuditEvent returns the newest audit event of eventType naming
// userID, polling while the audit log flushes.
func waitForAuditEvent(t *testing.T, h *RedesignHarness, userID, eventType string) *service.AuditEvent {
	t.Helper()
	ctx := context.Background()
	repo := h.Stores.users.WithProject(h.ProjectID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := repo.ListAuditEventsForUser(ctx, userID, 100)
		if err != nil {
			t.Fatalf("ListAuditEventsForUser(%s): %v", userID, err)
		}
		for _, e := range events {
			if e.EventType == eventType {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s audit event for %s within the deadline", eventType, userID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
