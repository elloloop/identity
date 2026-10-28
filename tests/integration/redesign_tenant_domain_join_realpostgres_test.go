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
// against a real Postgres. An account made on a domain before a self-service
// tenant verified it is in no tenant of the domain's. Once the tenant
// verifies the domain, the account still may not join until the tenant's
// owner turns joining on; then it finds the tenant and joins it as a domain
// member, a retry changes nothing, and turning joining off ends no
// membership and still returns it to a retry. While joining is on, a member
// removed can join again. An account whose email moves onto the domain
// after signup joins too, and moving it off again ends the membership. Only
// an admin turns joining on or off, only a verified email on the domain
// joins, and every change and join is audited.
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

	// Turning joining off ends no membership, and a retry still returns it.
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
	held, err := join(early)
	if err != nil {
		t.Fatalf("JoinTenantByDomain retried with joining off: %v", err)
	}
	if held.Msg.GetMembership().GetId() != m.GetId() {
		t.Fatalf("a retry with joining off returned %+v, want %+v", held.Msg.GetMembership(), m)
	}

	// While joining is on, a member removed who is still on the domain can
	// join again.
	if _, err := setJoin(founder, true); err != nil {
		t.Fatalf("SetDomainJoin on again: %v", err)
	}
	if _, err := founder.client.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{
		TenantId: tenantID, UserId: early.userID,
	})); err != nil {
		t.Fatalf("RemoveTenantMember: %v", err)
	}
	if got := joinable(early); len(got) != 1 || got[0].GetTenantId() != tenantID {
		t.Fatalf("joinable after removal = %v, want %s", got, tenantID)
	}
	rejoined, err := join(early)
	if err != nil {
		t.Fatalf("JoinTenantByDomain after removal: %v", err)
	}
	if r := rejoined.Msg.GetMembership(); r.GetStatus() != service.MembershipStatusActive || r.GetSource() != service.MembershipSourceDomain {
		t.Fatalf("membership after rejoining = %+v, want an active domain member", r)
	}

	// An account whose email moves onto the domain after signup joins it,
	// and moving the email off the domain again ends that membership.
	mover := signupOnAnotherDomain(t, h)
	mover = changeEmailAndSignIn(t, h, mover, "mover@"+domain)
	moverUser := membershipUser{client: h.AuthedClient(mover.access), userID: mover.userID}
	if got := joinable(moverUser); len(got) != 1 || got[0].GetTenantId() != tenantID {
		t.Fatalf("joinable after moving onto the domain = %v, want %s", got, tenantID)
	}
	if _, err := join(moverUser); err != nil {
		t.Fatalf("JoinTenantByDomain after moving onto the domain: %v", err)
	}
	mine, err := moverUser.client.ListMyTenants(ctx, connect.NewRequest(&identitypb.ListMyTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListMyTenants: %v", err)
	}
	if !listsTenant(mine.Msg.GetTenants(), tenantID, service.RoleMember) {
		t.Fatalf("ListMyTenants after joining = %v, want %s as a member", mine.Msg.GetTenants(), tenantID)
	}
	mover = changeEmailAndSignIn(t, h, mover, fmt.Sprintf("mover@away-%d.example.com", time.Now().UnixNano()))
	if got := domainMembership(t, h, mover.userID, tenantID); got.Status != service.MembershipStatusInactive {
		t.Fatalf("membership after moving off the domain = %+v, want inactive", got)
	}
	requireNotInTenant(t, h, "after moving off the domain", mover.access, mover.refresh, tenantID)

	sets := waitForTenantAuditEvents(t, h.ProjectID, tenantID, audit.EventDomainJoinSet, 3)
	if len(sets) != 3 || sets[0]["allow_join"] != true || sets[1]["allow_join"] != false || sets[2]["allow_join"] != true || sets[0]["domain"] != domain {
		t.Fatalf("%s events = %v, want on, off, on", audit.EventDomainJoinSet, sets)
	}
	joins := waitForTenantAuditEvents(t, h.ProjectID, tenantID, audit.EventTenantJoinedByDomain, 3)
	if len(joins) != 3 || joins[0]["domain"] != domain {
		t.Fatalf("%s events = %v, want three: the join, the rejoin and the mover's", audit.EventTenantJoinedByDomain, joins)
	}
}

// signupOnAnotherDomain signs up an account on a fresh domain no tenant
// holds, so auto-formation joins it to no tenant of the test's domain.
func signupOnAnotherDomain(t *testing.T, h *RedesignHarness) domainSession {
	t.Helper()
	addr := fmt.Sprintf("mover@before-%d.example.com", time.Now().UnixNano())
	signup, err := h.Client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(%s): %v", addr, err)
	}
	return domainSession{
		userID: signup.Msg.GetUser().GetId(), password: validPassword,
		access: signup.Msg.GetAccessToken(), refresh: signup.Msg.GetRefreshToken(),
	}
}
