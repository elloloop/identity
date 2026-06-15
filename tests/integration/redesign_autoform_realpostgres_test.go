//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestRedesign_AutoFormation_CompanyEmail asserts the full-stack auto-formation
// path: a PasswordSignup with a COMPANY email on the default project forms a
// latent tenant for that domain plus a domain-derived membership, while a
// PUBLIC email (gmail.com) forms nothing.
func TestRedesign_AutoFormation_CompanyEmail(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	// A non-reserved, non-public TLD so validateEmailFormat accepts it AND
	// IsPublicEmailDomain treats it as a company. (.test/.example are reserved;
	// gmail.com is public — both covered separately.)
	companyDomain := fmt.Sprintf("acme-%d.com", time.Now().UnixNano())
	companyEmail := "alice@" + companyDomain

	resp, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    companyEmail,
		Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(company): %v", err)
	}
	userID := resp.Msg.GetUser().GetId()
	if userID == "" {
		t.Fatal("PasswordSignup(company): empty user id")
	}

	// Auto-formation runs best-effort after the user is created; poll the
	// governance stores until it lands (or fail).
	tenant := waitForTenantByDomain(t, h, companyDomain)
	if tenant.Status != service.TenantStatusLatent {
		t.Fatalf("auto-formed tenant status = %q, want %q", tenant.Status, service.TenantStatusLatent)
	}
	if tenant.PrimaryDomain != companyDomain {
		t.Fatalf("auto-formed tenant primary_domain = %q, want %q", tenant.PrimaryDomain, companyDomain)
	}

	// The domain row exists, bound to that tenant, pending.
	dom, err := h.Stores.domains.GetDomainByName(ctx, h.ProjectID, companyDomain)
	if err != nil {
		t.Fatalf("GetDomainByName: %v", err)
	}
	if dom == nil {
		t.Fatalf("no domain row for %q after company signup", companyDomain)
	}
	if dom.TenantID != tenant.ID || dom.Status != service.DomainStatusPending {
		t.Fatalf("domain row = {tenant=%q status=%q}, want {tenant=%q status=pending}",
			dom.TenantID, dom.Status, tenant.ID)
	}

	// The signing user gets a domain-derived membership in that tenant.
	mem, err := h.Stores.memberships.GetMembership(ctx, h.ProjectID, tenant.ID, userID)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if mem == nil {
		t.Fatalf("no membership for user %q in auto-formed tenant %q", userID, tenant.ID)
	}
	if mem.Source != service.MembershipSourceDomain || mem.Status != service.MembershipStatusActive {
		t.Fatalf("membership = {source=%q status=%q}, want {source=domain status=active}",
			mem.Source, mem.Status)
	}
}

// TestRedesign_AutoFormation_PublicEmail asserts a PUBLIC email never
// auto-forms a tenant.
func TestRedesign_AutoFormation_PublicEmail(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	// gmail canonicalizes (dot-stripping); a unique +tag keeps the canonical
	// address distinct across runs while the domain stays gmail.com.
	publicEmail := fmt.Sprintf("bob+%d@gmail.com", time.Now().UnixNano())

	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    publicEmail,
		Password: validPassword,
	})); err != nil {
		t.Fatalf("PasswordSignup(public): %v", err)
	}

	// Give any (incorrect) auto-formation a chance to land, then assert none
	// did: no tenant maps gmail.com in this project.
	time.Sleep(300 * time.Millisecond)
	tenant, err := h.Stores.tenants.GetTenantByPrimaryDomain(ctx, h.ProjectID, "gmail.com")
	if err != nil {
		t.Fatalf("GetTenantByPrimaryDomain(gmail.com): %v", err)
	}
	if tenant != nil {
		t.Fatalf("public email auto-formed a tenant for gmail.com: %+v", tenant)
	}
	dom, err := h.Stores.domains.GetDomainByName(ctx, h.ProjectID, "gmail.com")
	if err != nil {
		t.Fatalf("GetDomainByName(gmail.com): %v", err)
	}
	if dom != nil {
		t.Fatalf("public email created a domain row for gmail.com: %+v", dom)
	}
}

// waitForTenantByDomain polls the tenant store until a tenant maps domain (or
// fails). Auto-formation is asynchronous to the signup response, so a poll —
// not a single read — is the honest assertion.
func waitForTenantByDomain(t *testing.T, h *RedesignHarness, domain string) *service.Tenant {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(3 * time.Second)
	for {
		tenant, err := h.Stores.tenants.GetTenantByPrimaryDomain(ctx, h.ProjectID, domain)
		if err != nil {
			t.Fatalf("GetTenantByPrimaryDomain(%q): %v", domain, err)
		}
		if tenant != nil {
			return tenant
		}
		if time.Now().After(deadline) {
			t.Fatalf("no tenant auto-formed for domain %q within deadline", domain)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
