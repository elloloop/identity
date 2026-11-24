//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

const domainJoinSignupConfig = `{"access":{"mode":"invite","admit_domain_join":true}}`

// operatorTenantWithDomain gives a tenant the store made, as an operator
// makes one (its created_by empty), a domain its owner verifies, and returns
// the owner, the domain and the domain's id.
func operatorTenantWithDomain(t *testing.T, h *RedesignHarness, label string) (ownerCaller, string, string) {
	t.Helper()
	ctx := context.Background()
	owner := signupOwner(t, h, label)
	domain := fmt.Sprintf("%s-%d.example.com", label, time.Now().UnixNano())
	claim, err := owner.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId: owner.tenantID, Domain: domain, VerificationMethod: service.DomainVerificationDNSTXT,
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
	return owner, domain, claim.Msg.GetDomain().GetId()
}

// TestRedesign_InviteOnly_DomainJoinAdmitsAndJoinsOnlyByJoinTenantByDomain
// drives access.admit_domain_join end to end against a real Postgres, on the
// branded host: an address on an operator-made tenant's verified domain gets
// no code until the owner opens the domain to joining, then signs in with an
// emailed code, which creates its account in no tenant, and joins the tenant
// with JoinTenantByDomain. A password sign-up stays refused, and an address
// on another domain gets no code and no account.
func TestRedesign_InviteOnly_DomainJoinAdmitsAndJoinsOnlyByJoinTenantByDomain(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner, domain, domainID := operatorTenantWithDomain(t, h, "domain-join-signup")
	setProjectConfig(t, h, domainJoinSignupConfig)
	newcomer := "newcomer@" + domain

	if sent := requestCode(t, h, newcomer); sent != 0 {
		t.Fatalf("an address on a domain closed to joining got %d emails, want none", sent)
	}
	requireNoAccount(t, h, newcomer)
	if _, err := owner.client.SetDomainJoin(ctx, connect.NewRequest(&identitypb.SetDomainJoinRequest{
		DomainId: domainID, AllowJoin: true,
	})); err != nil {
		t.Fatalf("SetDomainJoin: %v", err)
	}

	_, err := h.ClientWithHost(h.BrandedAuthDomain, nil).PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: newcomer, Password: validPassword,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("PasswordSignup on a joinable domain = %v, want PermissionDenied", err)
	}

	signedIn := signInWithCode(t, h, newcomer)
	userID := signedIn.GetUser().GetId()
	requireNoMemberships(t, h, userID)
	client := h.AuthedClient(signedIn.GetAccessToken())
	joinable, err := client.ListJoinableTenants(ctx, connect.NewRequest(&identitypb.ListJoinableTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListJoinableTenants: %v", err)
	}
	if got := joinable.Msg.GetTenants(); len(got) != 1 || got[0].GetTenantId() != owner.tenantID {
		t.Fatalf("joinable = %v, want %s", got, owner.tenantID)
	}
	joined, err := client.JoinTenantByDomain(ctx, connect.NewRequest(&identitypb.JoinTenantByDomainRequest{TenantId: owner.tenantID}))
	if err != nil {
		t.Fatalf("JoinTenantByDomain: %v", err)
	}
	if m := joined.Msg.GetMembership(); m.GetUserId() != userID || m.GetSource() != service.MembershipSourceDomain || m.GetStatus() != service.MembershipStatusActive {
		t.Fatalf("membership = %+v, want an active domain membership", m)
	}

	stranger := fmt.Sprintf("stranger@elsewhere-%d.example.com", time.Now().UnixNano())
	if sent := requestCode(t, h, stranger); sent != 0 {
		t.Fatalf("an address on another domain got %d emails, want none", sent)
	}
	requireNoAccount(t, h, stranger)
}

// TestRedesign_InviteOnly_SelfServiceTenantDomainAdmitsNobody: a person who
// makes a tenant, verifies a domain they own and opens it to joining does not
// let anyone on it into an invite-only project.
func TestRedesign_InviteOnly_SelfServiceTenantDomainAdmitsNobody(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) { c.SelfServiceTenantsEnabled = true })
	ctx := context.Background()
	_, domain := companyWithVerifiedDomain(t, h)
	verified, err := h.Stores.domains.GetVerifiedDomain(ctx, h.ProjectID, domain)
	if err != nil || verified == nil {
		t.Fatalf("GetVerifiedDomain(%s) = %+v, %v", domain, verified, err)
	}
	if _, _, err := h.Stores.domains.SetDomainAllowJoin(ctx, h.ProjectID, verified.ID, true); err != nil {
		t.Fatalf("SetDomainAllowJoin: %v", err)
	}
	setProjectConfig(t, h, domainJoinSignupConfig)

	friend := "friend@" + domain
	if sent := requestCode(t, h, friend); sent != 0 {
		t.Fatalf("an address on a self-service tenant's domain got %d sign-in emails, want none", sent)
	}
	requireNoAccount(t, h, friend)
}
