package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

func phoneHash(number string) []byte {
	h := sha256.Sum256([]byte(number))
	return h[:]
}

// TestMembershipStore_MatchTenantMemberPhones holds the match to the members
// who may act in the tenant and whose number is verified: every other
// account whose number was asked for stays out, and so does every member
// whose number was not. It runs again on a non-superuser role bound to
// another project, so the users it reads are behind row-level security.
func TestMembershipStore_MatchTenantMemberPhones(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	ms, _, projectID, tenantID, _, _ := newMembershipFixture(ctx, t, dsn)
	people, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectID})
	require.NoError(t, err)
	t.Cleanup(people.Close)

	_, err = NewDomainStore(people).CreateDomain(ctx, &service.Domain{
		ProjectID: projectID, TenantID: tenantID, Domain: "acme.example.test",
		VerificationMethod: service.DomainVerificationDNSTXT, Status: service.DomainStatusVerified,
	})
	require.NoError(t, err)
	tenants := NewTenantStore(people)
	otherTenant, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	suspendedTenant, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Status: service.TenantStatusSuspended})
	require.NoError(t, err)

	type membership struct {
		tenant, source, status string
	}
	added := func(tenant string) *membership {
		return &membership{tenant: tenant, source: service.MembershipSourceAdded, status: service.MembershipStatusActive}
	}
	cases := []struct {
		name       string
		user       service.User
		membership *membership
		notAsked   bool
		match      bool
	}{
		{name: "active member with a verified number", user: service.User{Email: "member@acme.com", PhoneVerified: true}, membership: added("tenant"), match: true},
		{name: "member whose number is unverified", user: service.User{Email: "unverified@acme.com"}, membership: added("tenant")},
		{name: "member with no number", user: service.User{Email: "nonumber@acme.com", PhoneVerified: true}, membership: added("tenant")},
		{name: "non-member with a verified number", user: service.User{Email: "outsider@acme.com", PhoneVerified: true}},
		{name: "member of another tenant only", user: service.User{Email: "elsewhere@acme.com", PhoneVerified: true}, membership: added("other")},
		{name: "member of a suspended tenant only", user: service.User{Email: "suspendedtenant@acme.com", PhoneVerified: true}, membership: added("suspended")},
		{name: "suspended membership", user: service.User{Email: "suspended@acme.com", PhoneVerified: true}, membership: &membership{tenant: "tenant", source: service.MembershipSourceAdded, status: service.MembershipStatusSuspended}},
		{name: "ended membership", user: service.User{Email: "ended@acme.com", PhoneVerified: true}, membership: &membership{tenant: "tenant", source: service.MembershipSourceAdded, status: service.MembershipStatusInactive}},
		{name: "deactivated account", user: service.User{Email: "gone@acme.com", PhoneVerified: true, Status: service.StatusDeactivated}, membership: added("tenant")},
		{name: "anonymous account", user: service.User{PhoneVerified: true, IsAnonymous: true}, membership: added("tenant")},
		{name: "domain member on a verified domain", user: service.User{Email: "domain@acme.example.test", EmailVerified: true, PhoneVerified: true}, membership: &membership{tenant: "tenant", source: service.MembershipSourceDomain, status: service.MembershipStatusActive}, match: true},
		{name: "domain member whose email is unverified", user: service.User{Email: "domainunverified@acme.example.test", PhoneVerified: true}, membership: &membership{tenant: "tenant", source: service.MembershipSourceDomain, status: service.MembershipStatusActive}},
		{name: "domain member off the domain", user: service.User{Email: "domain@elsewhere.example.test", EmailVerified: true, PhoneVerified: true}, membership: &membership{tenant: "tenant", source: service.MembershipSourceDomain, status: service.MembershipStatusActive}},
		{name: "member whose number was not asked for", user: service.User{Email: "notasked@acme.com", PhoneVerified: true}, membership: added("tenant"), notAsked: true},
	}
	tenantIDs := map[string]string{"tenant": tenantID, "other": otherTenant, "suspended": suspendedTenant}
	now := time.Now()
	var asked [][]byte
	var want []string
	for i, tc := range cases {
		u := tc.user
		if tc.name != "member with no number" {
			u.PhoneNumber = fmt.Sprintf("+1415555%02d11", i)
		}
		u.CreatedAt, u.UpdatedAt = now, now
		id, err := people.CreateUser(ctx, &u)
		require.NoError(t, err, tc.name)
		if tc.membership != nil {
			_, err = ms.UpsertMembership(ctx, &service.TenantMembership{
				ProjectID: projectID, TenantID: tenantIDs[tc.membership.tenant], UserID: id,
				Source: tc.membership.source, Role: service.RoleMember, Status: tc.membership.status,
			})
			require.NoError(t, err, tc.name)
		}
		if !tc.notAsked && u.PhoneNumber != "" {
			asked = append(asked, phoneHash(u.PhoneNumber))
		}
		if tc.match {
			want = append(want, id)
		}
		if tc.name == "active member with a verified number" {
			agent := service.User{Kind: service.UserKindAgent, OwnerUserID: id, PhoneNumber: "+14155559900", PhoneVerified: true, CreatedAt: now, UpdatedAt: now}
			agentID, err := people.CreateUser(ctx, &agent)
			require.NoError(t, err)
			_, err = ms.UpsertMembership(ctx, &service.TenantMembership{ProjectID: projectID, TenantID: tenantID, UserID: agentID})
			require.NoError(t, err)
			asked = append(asked, phoneHash(agent.PhoneNumber))
		}
	}
	asked = append(asked, phoneHash("+19995550000"))
	sort.Strings(want)

	check := func(name string, store *MembershipStore) {
		t.Helper()
		got, err := store.MatchTenantMemberPhones(ctx, projectID, tenantID, asked)
		require.NoError(t, err, name)
		require.Equal(t, want, got, "%s: only active people's verified numbers match", name)

		got, err = store.MatchTenantMemberPhones(ctx, projectID, suspendedTenant, asked)
		require.NoError(t, err, name)
		require.Empty(t, got, "%s: a suspended tenant has no member who may act in it", name)

		got, err = store.MatchTenantMemberPhones(ctx, projectID, tenantID, nil)
		require.NoError(t, err, name)
		require.Empty(t, got, name)

		_, err = store.MatchTenantMemberPhones(ctx, projectID, "no-such-tenant", asked)
		require.ErrorIs(t, err, service.ErrNotFound, name)
		_, err = store.MatchTenantMemberPhones(ctx, "control-plane", tenantID, asked)
		require.ErrorIs(t, err, service.ErrNotFound, "%s: another project's tenant is not found", name)
	}
	check("owner role", ms)
	_, err = ms.MatchTenantMemberPhones(ctx, "", tenantID, asked)
	require.ErrorIs(t, err, service.ErrInvalidArgument)

	bound, err := New(ctx, Config{DSN: provisionRLSAppRole(ctx, t, dsn), MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: "control-plane"})
	require.NoError(t, err)
	t.Cleanup(bound.Close)
	check("row-level security", NewMembershipStore(bound))
}
