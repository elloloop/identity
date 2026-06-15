//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
)

// TestRedesign_DomainVerify_Success drives CreateDomain → publish the DNS
// challenge → VerifyDomain end-to-end over the Connect client. On success the
// domain flips to verified, the tenant to claimed, and the caller to owner;
// ListTenantDomains reflects it.
func TestRedesign_DomainVerify_Success(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	caller := signupOwner(t, h, "owner")
	domain := fmt.Sprintf("verify-ok-%d.com", time.Now().UnixNano())

	// CreateDomain returns the deterministic DNS-TXT challenge.
	created, err := caller.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId:           caller.tenantID,
		Domain:             domain,
		VerificationMethod: service.DomainVerificationDNSTXT,
	}))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	domainID := created.Msg.GetDomain().GetId()
	if domainID == "" || created.Msg.GetDnsTxtValue() == "" {
		t.Fatalf("CreateDomain returned empty id/challenge: %+v", created.Msg)
	}
	if created.Msg.GetDomain().GetStatus() != service.DomainStatusPending {
		t.Fatalf("new domain status = %q, want pending", created.Msg.GetDomain().GetStatus())
	}

	// Publish exactly the challenge the server handed us at the TXT name it
	// named (the domain itself), so VerifyDomain's DNS check passes.
	h.DNS.publish(created.Msg.GetDnsTxtName(), created.Msg.GetDnsTxtValue())

	verified, err := caller.client.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{
		DomainId: domainID,
	}))
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	if verified.Msg.GetDomain().GetStatus() != service.DomainStatusVerified {
		t.Fatalf("verified domain status = %q, want verified", verified.Msg.GetDomain().GetStatus())
	}

	// The tenant is now claimed.
	tenant, err := h.Stores.tenants.GetTenant(ctx, h.ProjectID, caller.tenantID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if tenant == nil || tenant.Status != service.TenantStatusClaimed {
		t.Fatalf("tenant status = %v, want claimed", tenant)
	}

	// The caller is an owner of the tenant.
	mem, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, caller.tenantID, caller.userID)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if mem == nil || mem.Role != service.RoleOwner {
		t.Fatalf("caller membership = %v, want role owner", mem)
	}

	// ListTenantDomains (over RPC) shows the verified domain.
	list, err := caller.client.ListTenantDomains(ctx, connect.NewRequest(&identitypb.ListTenantDomainsRequest{
		TenantId: caller.tenantID,
	}))
	if err != nil {
		t.Fatalf("ListTenantDomains: %v", err)
	}
	if !hasVerifiedDomain(list.Msg.GetDomains(), domain) {
		t.Fatalf("ListTenantDomains missing verified %q: %+v", domain, list.Msg.GetDomains())
	}
}

// TestRedesign_DomainVerify_Failure asserts VerifyDomain fails with
// PermissionDenied and leaves the tenant unclaimed when the DNS TXT challenge
// is absent or wrong.
func TestRedesign_DomainVerify_Failure(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	caller := signupOwner(t, h, "owner-fail")
	domain := fmt.Sprintf("verify-bad-%d.com", time.Now().UnixNano())

	created, err := caller.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId:           caller.tenantID,
		Domain:             domain,
		VerificationMethod: service.DomainVerificationDNSTXT,
	}))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	domainID := created.Msg.GetDomain().GetId()

	// Publish the WRONG TXT value (and nothing matching the challenge).
	h.DNS.publish(created.Msg.GetDnsTxtName(), "identity-domain-verify=deadbeef")

	_, err = caller.client.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{
		DomainId: domainID,
	}))
	if err == nil {
		t.Fatal("VerifyDomain with wrong TXT: want error, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("VerifyDomain failure code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// The tenant must NOT have been claimed by a failed verification.
	tenant, err := h.Stores.tenants.GetTenant(ctx, h.ProjectID, caller.tenantID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if tenant == nil || tenant.Status == service.TenantStatusClaimed {
		t.Fatalf("tenant status = %v, want NOT claimed after failed verify", tenant)
	}

	// The domain is recorded as failed, not verified.
	dom, err := h.Stores.domains.GetDomain(ctx, h.ProjectID, domainID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if dom == nil || dom.Status == service.DomainStatusVerified {
		t.Fatalf("domain status = %v, want NOT verified after failed verify", dom)
	}
}

// ownerCaller is a signed-up user plus an admin tenant they can manage
// domains on, with a Connect client that carries the user's bearer token.
type ownerCaller struct {
	client   identityconnectgen.IdentityServiceClient
	userID   string
	tenantID string
}

// signupOwner signs up a user, then seeds a fresh latent tenant with that
// user as an active OWNER so CreateDomain (which requires tenant-admin)
// succeeds. The membership seed is the realistic setup a tenant admin already
// has; everything after it is driven over RPC.
func signupOwner(t *testing.T, h *RedesignHarness, label string) ownerCaller {
	t.Helper()
	ctx := context.Background()

	email := fmt.Sprintf("%s-%d@example-corp.com", label, time.Now().UnixNano())
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("signupOwner PasswordSignup: %v", err)
	}
	userID := signup.Msg.GetUser().GetId()

	tenantID, err := h.Stores.tenants.CreateTenant(ctx, &service.Tenant{
		ProjectID:     h.ProjectID,
		Name:          label + " tenant",
		PrimaryDomain: fmt.Sprintf("%s-primary-%d.com", label, time.Now().UnixNano()),
		Status:        service.TenantStatusLatent,
	})
	if err != nil {
		t.Fatalf("signupOwner CreateTenant: %v", err)
	}
	if _, err := h.Stores.memberships.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: h.ProjectID,
		TenantID:  tenantID,
		UserID:    userID,
		Source:    service.MembershipSourceAdded,
		Role:      service.RoleOwner,
		Status:    service.MembershipStatusActive,
	}); err != nil {
		t.Fatalf("signupOwner UpsertMembership: %v", err)
	}

	return ownerCaller{
		client:   h.AuthedClient(signup.Msg.GetAccessToken()),
		userID:   userID,
		tenantID: tenantID,
	}
}

func hasVerifiedDomain(domains []*identitypb.Domain, name string) bool {
	for _, d := range domains {
		if d.GetDomain() == name && d.GetStatus() == service.DomainStatusVerified {
			return true
		}
	}
	return false
}
