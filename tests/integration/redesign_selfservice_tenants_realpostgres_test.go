//go:build integration && realpostgres

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
// tenants on for the default project.
func startSelfServiceHarness(t *testing.T) *RedesignHarness {
	t.Helper()
	return startRedesignHarnessWith(t, func(c *config.Config) { c.SelfServiceTenantsEnabled = true })
}

// TestRedesign_SelfServiceTenants_EndToEnd drives a self-service tenant
// through its life over the wire: a person signs up, creates a tenant and
// sees it in ListMyTenants; a refresh that selects it mints a token whose
// tenant claim is that tenant, and the token authenticates; suspending the
// tenant ends the token at its next request and refuses a new selection,
// while a plain refresh still rotates; and the creation is audited.
func TestRedesign_SelfServiceTenants_EndToEnd(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    fmt.Sprintf("ss-owner-%d@example.com", time.Now().UnixNano()),
		Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
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

	if err := h.Stores.tenants.SetTenantStatus(ctx, h.ProjectID, tenantID, service.TenantStatusSuspended); err != nil {
		t.Fatalf("SetTenantStatus(suspended): %v", err)
	}
	_, err = inTenant.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	requireConnectCode(t, "a suspended tenant's token", err, connect.CodeUnauthenticated)

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
		addr := fmt.Sprintf("%s-%d@example-corp.com", label, unique)
		resp, err := h.ClientWithHost(host, nil).PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
			Email: addr, Password: validPassword,
		}))
		if err != nil {
			t.Fatalf("PasswordSignup(%s) on %s: %v", label, host, err)
		}
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
	domain := fmt.Sprintf("squatted-%d.com", unique)

	newTenantOwner := func(addr, name string) (identityconnectgen.IdentityServiceClient, string) {
		t.Helper()
		user := signupMembershipUser(t, h, addr)
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

	squatter, squatTenant := newTenantOwner(fmt.Sprintf("squatter-%d@example-corp.com", unique), "Not The Company")
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
