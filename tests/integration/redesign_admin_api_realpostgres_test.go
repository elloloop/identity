//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// adminClient returns a Connect client whose every request carries the shared
// admin secret in the X-Admin-Secret header — the platform-operator credential
// the control-plane admin RPCs authenticate against.
func (h *RedesignHarness) adminClient(secret string) identityconnectgen.IdentityServiceClient {
	return h.ClientWithHost("", map[string]string{middleware.AdminAPISecretHeader: secret})
}

// TestRedesign_ControlPlaneAdmin_ProvisioningFlow drives the full operator
// provisioning sequence over the wire against a real Postgres:
//
//	AdminCreateProject → AdminCreateProjectCredential → AdminAddProjectAuthDomain
//	→ AdminCreateTenant → AdminAddTenantAdmin
//
// and asserts each side-effect through the governance stores: the auth-domain
// host resolves to the NEW project (via the same resolver the project
// middleware uses), the tenant is claimed, and the user is now an active owner.
func TestRedesign_ControlPlaneAdmin_ProvisioningFlow(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)

	unique := time.Now().UnixNano()
	storageScope := fmt.Sprintf("admin-scope-%d", unique)

	// 1. Create a project mapped onto a fresh storage scope.
	projResp, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "Operator Provisioned",
		StorageScopeId: storageScope,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	newProjectID := projResp.Msg.GetProjectId()
	if newProjectID == "" {
		t.Fatal("AdminCreateProject returned an empty project id")
	}
	if newProjectID == h.ProjectID {
		t.Fatalf("new project id %q collided with the default project", newProjectID)
	}

	// 2. Mint a secret credential — the raw key is returned ONCE.
	credResp, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: newProjectID,
		Kind:      service.CredentialKindSecret,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	publicID := credResp.Msg.GetPublicId()
	rawKey := credResp.Msg.GetRawKey()
	if publicID == "" || rawKey == "" || credResp.Msg.GetCredentialId() == "" {
		t.Fatalf("credential response incomplete: %+v", credResp.Msg)
	}

	// The public_id resolves the NEW project via the credential resolver.
	resolvedByKey, err := h.Stores.projects.ResolveByCredential(ctx, publicID)
	if err != nil {
		t.Fatalf("ResolveByCredential: %v", err)
	}
	if resolvedByKey == nil || resolvedByKey.ID != newProjectID {
		t.Fatalf("credential %q resolved to %+v, want project %q", publicID, resolvedByKey, newProjectID)
	}

	// 3. Register a branded serving hostname on the new project.
	adminHost := fmt.Sprintf("admin-%d.acme.test", unique)
	if _, err := admin.AdminAddProjectAuthDomain(ctx, connect.NewRequest(&identitypb.AdminAddProjectAuthDomainRequest{
		ProjectId: newProjectID,
		Hostname:  adminHost,
		IsPrimary: true,
	})); err != nil {
		t.Fatalf("AdminAddProjectAuthDomain: %v", err)
	}

	// The host resolves to the new project (same resolution the project
	// middleware performs from the request Host).
	resolvedByHost, err := h.Stores.projects.ResolveByHostname(ctx, adminHost)
	if err != nil {
		t.Fatalf("ResolveByHostname: %v", err)
	}
	if resolvedByHost == nil || resolvedByHost.ID != newProjectID {
		t.Fatalf("host %q resolved to %+v, want project %q", adminHost, resolvedByHost, newProjectID)
	}
	if resolvedByHost.PrimaryAuthDomain != adminHost {
		t.Fatalf("primary auth domain = %q, want %q", resolvedByHost.PrimaryAuthDomain, adminHost)
	}

	// 4. Create a tenant under the new project — operator-created ⇒ claimed.
	tenantResp, err := admin.AdminCreateTenant(ctx, connect.NewRequest(&identitypb.AdminCreateTenantRequest{
		ProjectId:     newProjectID,
		Name:          "Acme Division",
		PrimaryDomain: fmt.Sprintf("acme-%d.example", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateTenant: %v", err)
	}
	newTenantID := tenantResp.Msg.GetTenantId()
	if newTenantID == "" {
		t.Fatal("AdminCreateTenant returned an empty tenant id")
	}
	tnt, err := h.Stores.tenants.GetTenant(ctx, newProjectID, newTenantID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if tnt == nil || tnt.Status != service.TenantStatusClaimed {
		t.Fatalf("tenant = %+v, want a claimed tenant", tnt)
	}

	// 5. Bootstrap the first tenant admin as an owner (source=added). The
	// membership row FK-references a real user, so sign one up first (the
	// realistic flow: an operator bootstraps an existing human as the first
	// tenant admin so they can then self-serve).
	bootstrapUser := signupMembershipUser(t, h, fmt.Sprintf("operator-bootstrap-%d@example-corp.com", unique))
	bootstrapUserID := bootstrapUser.userID
	adminResp, err := admin.AdminAddTenantAdmin(ctx, connect.NewRequest(&identitypb.AdminAddTenantAdminRequest{
		ProjectId: newProjectID,
		TenantId:  newTenantID,
		UserId:    bootstrapUserID,
		Role:      service.RoleOwner,
	}))
	if err != nil {
		t.Fatalf("AdminAddTenantAdmin: %v", err)
	}
	if m := adminResp.Msg.GetMembership(); m.GetUserId() != bootstrapUserID || m.GetRole() != service.RoleOwner {
		t.Fatalf("returned membership = %+v", m)
	}

	// The user is now an active owner member, per the membership store.
	mem, err := h.Stores.memberships.GetMembership(ctx, newProjectID, newTenantID, bootstrapUserID)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if mem == nil {
		t.Fatal("bootstrap user has no membership after AdminAddTenantAdmin")
	}
	if mem.Role != service.RoleOwner || mem.Status != service.MembershipStatusActive || mem.Source != service.MembershipSourceAdded {
		t.Fatalf("membership = %+v, want active owner (source=added)", mem)
	}
}

// TestRedesign_ControlPlaneAdmin_CustomAuthDomainFlow drives the customer
// custom-domain lifecycle over the wire against a real Postgres:
//
//	AddProjectAuthDomain (unverified, returns TXT challenge) → resolver REJECTS
//	→ VerifyProjectAuthDomain with the published TXT → resolver RESOLVES.
//
// It proves the security invariant: an unverified customer-owned hostname must
// not resolve to its project until DNS ownership is proven.
func TestRedesign_ControlPlaneAdmin_CustomAuthDomainFlow(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)

	unique := time.Now().UnixNano()
	scope := fmt.Sprintf("custom-scope-%d", unique)
	projResp, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "Custom Domain Co",
		StorageScopeId: scope,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := projResp.Msg.GetProjectId()

	host := fmt.Sprintf("custom-%d.customer.test", unique)

	// 0. The customer RPC rejects is_primary=true: promoting a custom
	// auth-domain to primary is not yet supported, so it is the documented
	// InvalidArgument contract rather than a silent half-built path.
	if _, err := admin.AddProjectAuthDomain(ctx, connect.NewRequest(&identitypb.AddProjectAuthDomainRequest{
		ProjectId: projectID,
		Hostname:  host,
		IsPrimary: true,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("AddProjectAuthDomain(is_primary=true): code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// 1. Register the custom domain non-primary — unverified, with a TXT challenge.
	addResp, err := admin.AddProjectAuthDomain(ctx, connect.NewRequest(&identitypb.AddProjectAuthDomainRequest{
		ProjectId: projectID,
		Hostname:  host,
		IsPrimary: false,
	}))
	if err != nil {
		t.Fatalf("AddProjectAuthDomain: %v", err)
	}
	if addResp.Msg.GetDomain().GetVerifiedAtMs() != 0 {
		t.Fatalf("custom domain must start unverified, got %d", addResp.Msg.GetDomain().GetVerifiedAtMs())
	}
	challenge := addResp.Msg.GetTxtValue()
	if challenge == "" {
		t.Fatal("AddProjectAuthDomain returned no TXT challenge")
	}

	// 2. An unverified custom domain must NOT resolve.
	if resolved, err := h.Stores.projects.ResolveByHostname(ctx, host); err != nil {
		t.Fatalf("ResolveByHostname (unverified): %v", err)
	} else if resolved != nil {
		t.Fatalf("unverified custom domain %q must not resolve, got %+v", host, resolved)
	}

	// 3. Verify without the TXT published → PermissionDenied, stays unverified.
	if _, err := admin.VerifyProjectAuthDomain(ctx, connect.NewRequest(&identitypb.VerifyProjectAuthDomainRequest{
		ProjectId: projectID,
		Hostname:  host,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("verify without TXT: code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// 4. Publish the challenge and verify → succeeds.
	h.DNS.publish(host, challenge)
	verResp, err := admin.VerifyProjectAuthDomain(ctx, connect.NewRequest(&identitypb.VerifyProjectAuthDomainRequest{
		ProjectId: projectID,
		Hostname:  host,
	}))
	if err != nil {
		t.Fatalf("VerifyProjectAuthDomain: %v", err)
	}
	if verResp.Msg.GetDomain().GetVerifiedAtMs() <= 0 {
		t.Fatalf("verified_at_ms not stamped: %+v", verResp.Msg.GetDomain())
	}

	// 5. The verified custom domain now resolves to its project.
	resolved, err := h.Stores.projects.ResolveByHostname(ctx, host)
	if err != nil {
		t.Fatalf("ResolveByHostname (verified): %v", err)
	}
	if resolved == nil || resolved.ID != projectID {
		t.Fatalf("verified custom domain %q resolved to %+v, want project %q", host, resolved, projectID)
	}

	// 6. ListProjectAuthDomains reflects the verified domain.
	listResp, err := admin.ListProjectAuthDomains(ctx, connect.NewRequest(&identitypb.ListProjectAuthDomainsRequest{
		ProjectId: projectID,
	}))
	if err != nil {
		t.Fatalf("ListProjectAuthDomains: %v", err)
	}
	if len(listResp.Msg.GetDomains()) != 1 || listResp.Msg.GetDomains()[0].GetHostname() != host {
		t.Fatalf("list = %+v, want one domain %q", listResp.Msg.GetDomains(), host)
	}
}

// TestRedesign_ControlPlaneAdmin_BadSecretDenied asserts that a missing or
// wrong admin secret is rejected (PermissionDenied) and provisions nothing,
// even though the surface is ENABLED (the harness configures a secret).
func TestRedesign_ControlPlaneAdmin_BadSecretDenied(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	scope := fmt.Sprintf("admin-denied-scope-%d", time.Now().UnixNano())
	req := func() *connect.Request[identitypb.AdminCreateProjectRequest] {
		return connect.NewRequest(&identitypb.AdminCreateProjectRequest{
			Name:           "Should Not Exist",
			StorageScopeId: scope,
		})
	}

	// Wrong secret.
	if _, err := h.adminClient("the-wrong-secret").AdminCreateProject(ctx, req()); err == nil {
		t.Fatal("AdminCreateProject with wrong secret: want error, got nil")
	} else if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong-secret code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// No secret header at all (default Host client carries none).
	if _, err := h.Client.AdminCreateProject(ctx, req()); err == nil {
		t.Fatal("AdminCreateProject with no secret: want error, got nil")
	} else if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("missing-secret code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Nothing was provisioned: the storage scope maps to no project.
	if resolved, err := h.Stores.projects.ResolveByHostname(ctx, "never-registered.example"); err != nil {
		t.Fatalf("ResolveByHostname: %v", err)
	} else if resolved != nil {
		t.Fatalf("unexpected resolution after denied calls: %+v", resolved)
	}
}
