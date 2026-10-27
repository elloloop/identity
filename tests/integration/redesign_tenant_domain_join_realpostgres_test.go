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
	"github.com/elloloop/identity/pkg/audit"
)

// TestRedesign_TenantDomainJoin drives joining by domain over the wire
// against a real Postgres. An account made on a domain before any tenant
// verified it is in no tenant of the domain's. Once a tenant verifies the
// domain, the account still may not join until the tenant's owner turns
// joining on; then it finds the tenant and joins it as a domain member, a
// retry changes nothing, and turning joining off ends no membership. Only
// an admin turns it on or off, only a verified email on the domain joins,
// and every change and join is audited.
func TestRedesign_TenantDomainJoin(t *testing.T) {
	h := startSelfServiceHarness(t)
	ctx := context.Background()
	domain := fmt.Sprintf("join-%d.example.com", time.Now().UnixNano())

	early := signupVerifiedUser(t, h, "early@"+domain)
	unverified := signupMembershipUser(t, h, "unverified@"+domain)
	outsider := signupVerifiedUser(t, h, fmt.Sprintf("outsider@elsewhere-%d.example.com", time.Now().UnixNano()))

	founder := signupVerifiedUser(t, h, "founder@"+domain)
	created, err := founder.client.CreateTenant(ctx, connect.NewRequest(&identitypb.CreateTenantRequest{Name: "Join Co"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID := created.Msg.GetTenantId()
	claim, err := founder.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId: tenantID, Domain: domain, VerificationMethod: service.DomainVerificationDNSTXT,
	}))
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	domainID := claim.Msg.GetDomain().GetId()
	if claim.Msg.GetDomain().GetAllowJoin() {
		t.Fatal("a new domain lets its people join; want off until an admin turns it on")
	}
	h.DNS.publish(claim.Msg.GetDnsTxtName(), claim.Msg.GetDnsTxtValue())
	if _, err := founder.client.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{DomainId: domainID})); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}

	joinable := func(u membershipUser) []*identitypb.JoinableTenant {
		t.Helper()
		list, err := u.client.ListJoinableTenants(ctx, connect.NewRequest(&identitypb.ListJoinableTenantsRequest{}))
		if err != nil {
			t.Fatalf("ListJoinableTenants: %v", err)
		}
		return list.Msg.GetTenants()
	}
	join := func(u membershipUser) (*connect.Response[identitypb.JoinTenantByDomainResponse], error) {
		return u.client.JoinTenantByDomain(ctx, connect.NewRequest(&identitypb.JoinTenantByDomainRequest{TenantId: tenantID}))
	}
	setJoin := func(u membershipUser, allowJoin bool) (*connect.Response[identitypb.SetDomainJoinResponse], error) {
		return u.client.SetDomainJoin(ctx, connect.NewRequest(&identitypb.SetDomainJoinRequest{DomainId: domainID, AllowJoin: allowJoin}))
	}

	// Verifying the domain does not let the people on it join.
	if got := joinable(early); len(got) != 0 {
		t.Fatalf("joinable before joining is on = %v, want none", got)
	}
	_, err = join(early)
	requireConnectCode(t, "joining before joining is on", err, connect.CodePermissionDenied)

	_, err = setJoin(early, true)
	requireConnectCode(t, "a non-member turning joining on", err, connect.CodePermissionDenied)
	on, err := setJoin(founder, true)
	if err != nil {
		t.Fatalf("SetDomainJoin: %v", err)
	}
	if d := on.Msg.GetDomain(); !d.GetAllowJoin() || d.GetId() != domainID || d.GetStatus() != service.DomainStatusVerified {
		t.Fatalf("domain = %+v, want %s verified and allowing join", d, domainID)
	}
	if _, err := setJoin(founder, true); err != nil {
		t.Fatalf("SetDomainJoin retried: %v", err)
	}

	if got := joinable(early); len(got) != 1 || got[0].GetTenantId() != tenantID || got[0].GetName() != "Join Co" {
		t.Fatalf("joinable = %v, want %s", got, tenantID)
	}
	if got := joinable(founder); len(got) != 0 {
		t.Fatalf("the owner's joinable = %v, want none", got)
	}
	if got := joinable(outsider); len(got) != 0 {
		t.Fatalf("an outsider's joinable = %v, want none", got)
	}
	_, err = join(outsider)
	requireConnectCode(t, "joining from another domain", err, connect.CodePermissionDenied)
	_, err = join(unverified)
	requireConnectCode(t, "joining with an unverified email", err, connect.CodeFailedPrecondition)

	joined, err := join(early)
	if err != nil {
		t.Fatalf("JoinTenantByDomain: %v", err)
	}
	m := joined.Msg.GetMembership()
	if m.GetTenantId() != tenantID || m.GetUserId() != early.userID || m.GetRole() != service.RoleMember ||
		m.GetSource() != service.MembershipSourceDomain || m.GetStatus() != service.MembershipStatusActive {
		t.Fatalf("membership = %+v, want %s an active domain member", m, early.userID)
	}
	again, err := join(early)
	if err != nil {
		t.Fatalf("JoinTenantByDomain retried: %v", err)
	}
	if again.Msg.GetMembership().GetId() != m.GetId() {
		t.Fatalf("a retried join returned %+v, want %+v", again.Msg.GetMembership(), m)
	}
	if got := joinable(early); len(got) != 0 {
		t.Fatalf("joinable after joining = %v, want none", got)
	}

	// Turning joining off ends no membership.
	off, err := setJoin(founder, false)
	if err != nil {
		t.Fatalf("SetDomainJoin off: %v", err)
	}
	if off.Msg.GetDomain().GetAllowJoin() {
		t.Fatal("joining is still on")
	}
	if roles := tenantRoles(t, founder, tenantID); roles[early.userID] != service.RoleMember {
		t.Fatalf("members after joining is off = %v, want %s still a member", roles, early.userID)
	}

	sets := waitForTenantAuditCount(t, h.ProjectID, tenantID, audit.EventDomainJoinSet, 2)
	if len(sets) != 2 || sets[0]["allow_join"] != true || sets[1]["allow_join"] != false || sets[0]["domain"] != domain {
		t.Fatalf("%s events = %v, want on then off", audit.EventDomainJoinSet, sets)
	}
	joins := waitForTenantAuditCount(t, h.ProjectID, tenantID, audit.EventTenantJoinedByDomain, 1)
	if len(joins) != 1 || joins[0]["domain"] != domain {
		t.Fatalf("%s events = %v, want one", audit.EventTenantJoinedByDomain, joins)
	}
}

// waitForTenantAuditCount is waitForTenantAuditEvents, waiting for at least
// n events rather than the first.
func waitForTenantAuditCount(t *testing.T, projectID, tenantID string, eventType audit.EventType, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := waitForTenantAuditEvents(t, projectID, tenantID, eventType)
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
}
