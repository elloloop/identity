package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// A membership that came from an email's domain counts only while the email
// is verified and on a domain the tenant has verified (the active-tenant
// reads), and ends when the email leaves the tenant's verified domains
// (migration 0047). These tests write through the stores as the
// row-level-security app role, the role a deployment runs as.

const (
	domainSecondVerified = "acme-two.example.test"
	domainPendingClaim   = "acme-pending.example.test"
	domainNowhere        = "nowhere.example.test"
)

// domainMember gives userID a domain-derived active membership in tenantID.
func (f *governanceFixture) domainMember(ctx context.Context, t *testing.T, tenantID, userID string) {
	t.Helper()
	_, err := f.members.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.project, TenantID: tenantID, UserID: userID,
		Source: service.MembershipSourceDomain, Role: service.RoleMember, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)
}

// membershipStatus is the status of userID's membership in tenantID.
func (f *governanceFixture) membershipStatus(ctx context.Context, t *testing.T, tenantID, userID string) string {
	t.Helper()
	m, err := f.members.GetMembership(ctx, f.project, tenantID, userID)
	require.NoError(t, err)
	require.NotNil(t, m)
	return m.Status
}

func TestActiveTenantsForUser_DomainMembershipNeedsTheTenantsVerifiedDomain(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusVerified)
	f.claim(ctx, t, f.tenant, domainPendingClaim, service.DomainStatusPending)
	f.claim(ctx, t, f.otherTenant, govOtherDomain, service.DomainStatusVerified)
	f.domainMember(ctx, t, f.tenant, f.onDomain)

	for name, tc := range map[string]struct {
		emailDomain string
		counts      bool
	}{
		"verified and on the tenant's verified domain": {govDomain, true},
		"unverified":                         {"", false},
		"on a domain the tenant only claims": {domainPendingClaim, false},
		"on another tenant's domain":         {govOtherDomain, false},
		"on no tenant's domain":              {domainNowhere, false},
	} {
		list, err := f.members.ListActiveTenantsForUser(ctx, f.project, f.onDomain, tc.emailDomain)
		require.NoError(t, err, name)
		one, err := f.members.GetActiveTenantForUser(ctx, f.project, f.tenant, f.onDomain, tc.emailDomain)
		require.NoError(t, err, name)
		if !tc.counts {
			assert.Empty(t, list, name)
			assert.Nil(t, one, name)
			continue
		}
		require.Len(t, list, 1, name)
		assert.Equal(t, service.UserTenant{TenantID: f.tenant, Name: "Acme", Role: service.RoleMember, Source: service.MembershipSourceDomain}, *list[0], name)
		require.NotNil(t, one, name)
		assert.Equal(t, f.tenant, one.TenantID, name)
	}

	// Any other source counts whatever the email: the domain rule is the
	// domain membership's alone.
	got, err := f.members.GetActiveTenantForUser(ctx, f.project, f.tenant, f.member, "")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, service.MembershipSourceAdded, got.Source)
}

func TestDomainMembershipsEndWhenTheEmailLeavesTheDomain(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusVerified)
	f.claim(ctx, t, f.tenant, domainSecondVerified, service.DomainStatusVerified)
	f.claim(ctx, t, f.tenant, domainPendingClaim, service.DomainStatusPending)
	f.domainMember(ctx, t, f.tenant, f.onDomain)
	at := time.Now().UnixMilli()

	// Within the domain, a change of case included, nothing fires.
	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "renamed@"+govDomain, at))
	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "renamed@ACME.example.test", at))
	require.Equal(t, service.MembershipStatusActive, f.membershipStatus(ctx, t, f.tenant, f.onDomain))
	// Another domain the tenant has verified keeps the membership.
	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "person@"+domainSecondVerified, at))
	require.Equal(t, service.MembershipStatusActive, f.membershipStatus(ctx, t, f.tenant, f.onDomain))
	// A domain the tenant only claims does not: a confirmed email change ends it.
	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "person@"+domainPendingClaim, at))
	require.Equal(t, service.MembershipStatusInactive, f.membershipStatus(ctx, t, f.tenant, f.onDomain))

	// The SCIM and admin path (UpdateUser) ends one too, and leaves every
	// other source alone: the outsider's `added` membership in otherTenant.
	f.domainMember(ctx, t, f.tenant, f.outsider)
	require.NoError(t, f.repo.UpdateUser(ctx, f.outsider, map[string]any{"email": "outsider@" + domainNowhere, "email_verified": false}))
	require.Equal(t, service.MembershipStatusInactive, f.membershipStatus(ctx, t, f.tenant, f.outsider))
	require.Equal(t, service.MembershipStatusActive, f.membershipStatus(ctx, t, f.otherTenant, f.outsider))
	// So does a change to no email at all, as an account merge writes on the
	// account it retires.
	now := time.Now()
	retired, err := f.repo.CreateUser(ctx, &service.User{Email: "retired@" + govDomain, Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	f.domainMember(ctx, t, f.tenant, retired)
	require.NoError(t, f.repo.UpdateUser(ctx, retired, map[string]any{"email": ""}))
	require.Equal(t, service.MembershipStatusInactive, f.membershipStatus(ctx, t, f.tenant, retired))

	// Coming back to the domain does not rejoin; a grant reactivates the row.
	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "person@"+govDomain, at))
	require.Equal(t, service.MembershipStatusInactive, f.membershipStatus(ctx, t, f.tenant, f.onDomain))
	regranted, _, err := f.members.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: f.project, TenantID: f.tenant, UserID: f.onDomain, Role: service.RoleMember, Source: service.MembershipSourceInvited,
	})
	require.NoError(t, err)
	assert.Equal(t, service.MembershipStatusActive, regranted.Status)
	assert.Equal(t, service.MembershipSourceInvited, regranted.Source)
}

// TestDomainMembershipEmailMigrationRoundTrip asserts 0047 down drops the
// trigger and its function, and up puts both back.
func TestDomainMembershipEmailMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	triggerFunction := func() string {
		t.Helper()
		var fn string
		err := raw.QueryRow(ctx, `SELECT p.proname FROM pg_trigger tr JOIN pg_proc p ON p.oid=tr.tgfoid
			WHERE tr.tgname='tenant_domain_membership_email' AND tr.tgrelid=to_regclass('users')`).Scan(&fn)
		if errors.Is(err, pgx.ErrNoRows) {
			return ""
		}
		require.NoError(t, err)
		return fn
	}
	functionExists := func() bool {
		t.Helper()
		var ok bool
		require.NoError(t, raw.QueryRow(ctx, `SELECT to_regproc('end_domain_memberships_off_domain') IS NOT NULL`).Scan(&ok))
		return ok
	}
	for _, version := range []uint{47, 46, 47} {
		migrateToVersion(t, scratch, version)
		if version == 47 {
			require.Equal(t, "end_domain_memberships_off_domain", triggerFunction())
			require.True(t, functionExists())
		} else {
			require.Empty(t, triggerFunction())
			require.False(t, functionExists())
		}
	}
}
