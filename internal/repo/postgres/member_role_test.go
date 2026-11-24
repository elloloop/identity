package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// memberRoleDSN is GATEWAY_TEST_POSTGRES_DSN, or a skip without it.
func memberRoleDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping member role test")
	}
	return dsn
}

// roleChange is byID's change of userID's role, for an account on the
// tenant's verified domain that may be an admin.
func (f *joinFixture) roleChange(userID, role, byID string) service.MemberRoleChange {
	return service.MemberRoleChange{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: userID, Role: role, By: byID,
		EmailDomain: "acme.com", MayBeAdmin: true,
	}
}

func (f *joinFixture) setRole(ctx context.Context, userID, role, byID string) (*service.TenantMembership, string, error) {
	return f.ms.SetMemberRole(ctx, f.roleChange(userID, role, byID))
}

func (f *joinFixture) membershipOf(ctx context.Context, t *testing.T, userID string) *service.TenantMembership {
	t.Helper()
	m, err := f.ms.GetMembership(ctx, f.projectID, f.tenantID, userID)
	require.NoError(t, err)
	require.NotNil(t, m, userID)
	return m
}

// ownerlessAdmins makes the fixture's owner an admin, as an operator's upsert
// can, and grants a second account admin, so the tenant has two active
// admins and no owner. It returns the second admin's id.
func (f *joinFixture) ownerlessAdmins(ctx context.Context, t *testing.T) string {
	t.Helper()
	_, err := f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.other,
		Source: service.MembershipSourceCreated, Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)
	admin := f.account(ctx, t, "admin@acme.com")
	f.grant(ctx, t, admin, service.RoleAdmin)
	return admin
}

// TestMembershipStore_SetMemberRole: a role change keeps the membership's
// id and status, makes a domain member promoted an added one, and reports
// the role it replaced; setting the role held writes nothing. A suspended
// member stays suspended.
func TestMembershipStore_SetMemberRole(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	joined, _, err := f.join(ctx)
	require.NoError(t, err)

	promoted, from, err := f.setRole(ctx, f.user, service.RoleAdmin, f.other)
	require.NoError(t, err)
	assert.Equal(t, service.RoleMember, from)
	assert.Equal(t, service.RoleAdmin, promoted.Role)
	assert.Equal(t, service.MembershipSourceAdded, promoted.Source, "an admin no longer depends on the email's domain")
	assert.Equal(t, service.MembershipStatusActive, promoted.Status)
	assert.Equal(t, joined.ID, promoted.ID)
	assert.Equal(t, joined.CreatedAtMs, promoted.CreatedAtMs)
	assert.GreaterOrEqual(t, promoted.UpdatedAtMs, joined.UpdatedAtMs)
	assert.Equal(t, promoted, f.held(ctx, t))

	again, from, err := f.setRole(ctx, f.user, service.RoleAdmin, f.other)
	require.NoError(t, err)
	assert.Equal(t, service.RoleAdmin, from, "the role held is reported as the one before")
	assert.Equal(t, promoted, again, "setting the role held writes nothing")

	demoted, from, err := f.setRole(ctx, f.user, service.RoleMember, f.user)
	require.NoError(t, err, "an admin steps down while an owner governs")
	assert.Equal(t, service.RoleAdmin, from)
	assert.Equal(t, service.RoleMember, demoted.Role)
	assert.Equal(t, service.MembershipSourceAdded, demoted.Source, "a demotion keeps the source")

	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)
	suspended, from, err := f.setRole(ctx, f.user, service.RoleAdmin, f.other)
	require.NoError(t, err)
	assert.Equal(t, service.RoleMember, from)
	assert.Equal(t, service.RoleAdmin, suspended.Role)
	assert.Equal(t, service.MembershipStatusSuspended, suspended.Status, "a suspended member stays suspended")
	restored, _, err := f.restore(ctx, f.user, f.other)
	require.NoError(t, err)
	assert.Equal(t, service.RoleAdmin, restored.Role)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
}

// TestMembershipStore_SetMemberRoleRefusals: each rule refuses before
// anything is written.
func TestMembershipStore_SetMemberRoleRefusals(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	member := f.account(ctx, t, "member@acme.com")
	f.grant(ctx, t, member, service.RoleMember)
	suspendedAdmin := f.account(ctx, t, "suspended-admin@acme.com")
	f.grant(ctx, t, suspendedAdmin, service.RoleAdmin)
	_, _, err := f.suspend(ctx, suspendedAdmin)
	require.NoError(t, err)

	for name, by := range map[string]string{
		"a plain member":        member,
		"a suspended admin":     suspendedAdmin,
		"no member":             f.account(ctx, t, "stranger@acme.com"),
		"an id with no account": "no-such-user",
	} {
		_, _, err := f.setRole(ctx, member, service.RoleAdmin, by)
		require.ErrorIs(t, err, service.ErrPermissionDenied, name)
	}
	assert.Equal(t, service.RoleMember, f.membershipOf(ctx, t, member).Role)

	_, _, err = f.setRole(ctx, f.user, service.RoleAdmin, f.other)
	require.ErrorIs(t, err, service.ErrNotFound, "no membership")
	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceInvited, Role: service.RoleMember, Status: service.MembershipStatusInactive,
	})
	require.NoError(t, err)
	_, _, err = f.setRole(ctx, f.user, service.RoleAdmin, f.other)
	require.ErrorIs(t, err, service.ErrNotFound, "an ended membership")
	assert.Equal(t, service.RoleMember, f.held(ctx, t).Role)

	_, _, err = f.setRole(ctx, f.other, service.RoleAdmin, f.other)
	require.ErrorIs(t, err, service.ErrMemberIsOwner)
	assert.Equal(t, service.RoleOwner, f.membershipOf(ctx, t, f.other).Role)

	refused := f.roleChange(member, service.RoleAdmin, f.other)
	refused.MayBeAdmin = false
	_, _, err = f.ms.SetMemberRole(ctx, refused)
	require.ErrorIs(t, err, service.ErrIneligibleTenantAdmin)
	assert.Equal(t, service.RoleMember, f.membershipOf(ctx, t, member).Role)
	f.grant(ctx, t, member, service.RoleAdmin)
	kept, from, err := f.ms.SetMemberRole(ctx, refused)
	require.NoError(t, err, "an admin who could not be made one now is left as they are")
	assert.Equal(t, service.RoleAdmin, from)
	assert.Equal(t, service.RoleAdmin, kept.Role)
	refused.Role = service.RoleMember
	demoted, _, err := f.ms.SetMemberRole(ctx, refused)
	require.NoError(t, err, "and may be made a member")
	assert.Equal(t, service.RoleMember, demoted.Role)

	for name, change := range map[string]service.MemberRoleChange{
		"no project": {TenantID: f.tenantID, UserID: member, Role: service.RoleAdmin, By: f.other},
		"no tenant":  {ProjectID: f.projectID, UserID: member, Role: service.RoleAdmin, By: f.other},
		"no user":    {ProjectID: f.projectID, TenantID: f.tenantID, Role: service.RoleAdmin, By: f.other},
		"no caller":  {ProjectID: f.projectID, TenantID: f.tenantID, UserID: member, Role: service.RoleAdmin},
		"owner":      {ProjectID: f.projectID, TenantID: f.tenantID, UserID: member, Role: service.RoleOwner, By: f.other},
		"no role":    {ProjectID: f.projectID, TenantID: f.tenantID, UserID: member, By: f.other},
	} {
		_, _, err := f.ms.SetMemberRole(ctx, change)
		require.ErrorIs(t, err, service.ErrInvalidArgument, name)
	}
	assert.Equal(t, service.RoleMember, f.membershipOf(ctx, t, member).Role)
}

// TestMembershipStore_SetMemberRoleJudgesADomainMemberByTheDomain: a member
// only through their email's domain is one only while the tenant verifies
// the domain the email is on; a member from another source is one wherever
// the email is.
func TestMembershipStore_SetMemberRoleJudgesADomainMemberByTheDomain(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	_, _, err := f.join(ctx)
	require.NoError(t, err)
	invited := f.account(ctx, t, "invited@acme.com")
	f.grant(ctx, t, invited, service.RoleMember)

	for name, emailDomain := range map[string]string{
		"an email on another domain": "elsewhere.example",
		"an unverified email":        "",
	} {
		change := f.roleChange(f.user, service.RoleAdmin, f.other)
		change.EmailDomain = emailDomain
		_, _, err := f.ms.SetMemberRole(ctx, change)
		require.ErrorIs(t, err, service.ErrNotFound, name)
		change.Role = service.RoleMember
		_, _, err = f.ms.SetMemberRole(ctx, change)
		require.ErrorIs(t, err, service.ErrNotFound, "%s, setting the role held", name)
	}

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	_, err = raw.Exec(ctx, `DELETE FROM domains WHERE project_id = $1 AND id = $2`, f.projectID, f.domainID)
	require.NoError(t, err)
	_, _, err = f.setRole(ctx, f.user, service.RoleAdmin, f.other)
	require.ErrorIs(t, err, service.ErrNotFound, "a domain the tenant no longer verifies")
	m := f.held(ctx, t)
	assert.Equal(t, service.RoleMember, m.Role)
	assert.Equal(t, service.MembershipSourceDomain, m.Source)

	promoted, _, err := f.setRole(ctx, invited, service.RoleAdmin, f.other)
	require.NoError(t, err)
	assert.Equal(t, service.MembershipSourceInvited, promoted.Source)
}

// TestMembershipStore_SetMemberRoleKeepsAGovernor: an admin steps down while
// another active owner or admin is left, and the last one cannot.
func TestMembershipStore_SetMemberRoleKeepsAGovernor(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	admin := f.ownerlessAdmins(ctx, t)

	_, _, err := f.setRole(ctx, admin, service.RoleMember, admin)
	require.NoError(t, err, "the other admin is left")
	_, _, err = f.setRole(ctx, f.other, service.RoleMember, f.other)
	require.ErrorIs(t, err, service.ErrLastTenantGovernor)
	assert.Equal(t, service.RoleAdmin, f.membershipOf(ctx, t, f.other).Role)
}

// TestMembershipStore_SetMemberRoleWaitsOnTheOtherAdmins: a step-down holds
// every active admin's membership, not only the owners', and counts who is
// left once it has them. Here the other admin's own step-down is under way
// when it starts; it waits for it, and is then refused as the last one.
func TestMembershipStore_SetMemberRoleWaitsOnTheOtherAdmins(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	admin := f.ownerlessAdmins(ctx, t)

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	other, err := raw.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = other.Rollback(ctx) }()
	_, err = other.Exec(ctx, `UPDATE tenant_memberships SET role = 'member'
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, f.projectID, f.tenantID, f.other)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, _, err := f.setRole(ctx, admin, service.RoleMember, admin)
		done <- err
	}()
	waitOnLock(ctx, t, dsn, "%FROM tenant_memberships%FOR UPDATE%", "the step-down waits on the other admin's membership")
	require.NoError(t, other.Commit(ctx))

	require.ErrorIs(t, <-done, service.ErrLastTenantGovernor, "it sees the other admin gone")
	assert.Equal(t, service.RoleAdmin, f.membershipOf(ctx, t, admin).Role)
}

// TestMembershipStore_SetMemberRoleChecksTheCallerWhereItWrites: the
// caller's membership is read once it is held, so a suspension of the caller
// that commits while the change waits is seen, and nothing is written.
func TestMembershipStore_SetMemberRoleChecksTheCallerWhereItWrites(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	admin := f.account(ctx, t, "admin@acme.com")
	f.grant(ctx, t, admin, service.RoleAdmin)
	member := f.account(ctx, t, "member@acme.com")
	f.grant(ctx, t, member, service.RoleMember)

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	suspend, err := raw.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = suspend.Rollback(ctx) }()
	_, err = suspend.Exec(ctx, `UPDATE tenant_memberships SET status = 'suspended'
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, f.projectID, f.tenantID, admin)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, _, err := f.setRole(ctx, member, service.RoleAdmin, admin)
		done <- err
	}()
	waitOnLock(ctx, t, dsn, "%FROM tenant_memberships%FOR UPDATE%", "the change waits on the caller's membership")
	require.NoError(t, suspend.Commit(ctx))

	require.ErrorIs(t, <-done, service.ErrPermissionDenied)
	assert.Equal(t, service.RoleMember, f.membershipOf(ctx, t, member).Role)
}

// TestMembershipStore_ConcurrentRoleChanges: two admins of a tenant with no
// owner stepping down at once leave exactly one admin, and of many identical
// promotions at once one alone reports the change.
func TestMembershipStore_ConcurrentRoleChanges(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	admin := f.ownerlessAdmins(ctx, t)
	stepDown := func(userID string) func() error {
		return func() error { _, _, err := f.setRole(ctx, userID, service.RoleMember, userID); return err }
	}
	admins := func() int {
		t.Helper()
		members, err := f.ms.ListMembershipsForTenant(ctx, f.projectID, f.tenantID)
		require.NoError(t, err)
		n := 0
		for _, m := range members {
			if (m.Role == service.RoleAdmin || m.Role == service.RoleOwner) && m.Status == service.MembershipStatusActive {
				n++
			}
		}
		return n
	}

	const rounds = 20
	for round := range rounds {
		f.grant(ctx, t, f.other, service.RoleAdmin)
		f.grant(ctx, t, admin, service.RoleAdmin)
		require.Equal(t, 2, admins(), "round %d", round)
		err1, err2 := runTogether(stepDown(f.other), stepDown(admin))
		require.True(t, (err1 == nil) != (err2 == nil), "round %d: exactly one admin steps down (%v, %v)", round, err1, err2)
		for _, err := range []error{err1, err2} {
			if err != nil {
				require.ErrorIs(t, err, service.ErrLastTenantGovernor, "round %d", round)
			}
		}
		require.Equal(t, 1, admins(), "round %d", round)
	}

	f.grant(ctx, t, admin, service.RoleAdmin)
	member := f.account(ctx, t, "member@acme.com")
	f.grant(ctx, t, member, service.RoleMember)
	const racers = 8
	froms := make(chan string, racers)
	errs := make(chan error, racers)
	for range racers {
		go func() {
			_, from, err := f.setRole(ctx, member, service.RoleAdmin, admin)
			froms <- from
			errs <- err
		}()
	}
	changed := 0
	for range racers {
		require.NoError(t, <-errs)
		if <-froms == service.RoleMember {
			changed++
		}
	}
	require.Equal(t, 1, changed, "of concurrent promotions one alone reports the change")
	assert.Equal(t, service.RoleAdmin, f.membershipOf(ctx, t, member).Role)
}
