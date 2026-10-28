package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// suspensionDSN is GATEWAY_TEST_POSTGRES_DSN, or a skip without it.
func suspensionDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping member suspension test")
	}
	return dsn
}

// runTogether runs a and b at once and returns their errors.
func runTogether(a, b func() error) (errA, errB error) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; errA = a() }()
	go func() { defer wg.Done(); <-start; errB = b() }()
	close(start)
	wg.Wait()
	return errA, errB
}

func (f *joinFixture) suspend(ctx context.Context, userID string) (*service.TenantMembership, bool, error) {
	return f.ms.SuspendMembership(ctx, f.projectID, f.tenantID, userID)
}

func (f *joinFixture) restore(ctx context.Context, userID, emailDomain string) (*service.TenantMembership, bool, error) {
	return f.ms.RestoreMembership(ctx, f.projectID, f.tenantID, userID, emailDomain)
}

// TestMembershipStore_SuspendAndRestore: a suspension keeps the membership,
// its role and source, takes the tenant out of the active-tenant reads and
// refuses the ways back in that would lift it; a restore lifts it, and an
// operator's upsert does too. Asking for the status a membership has
// changes nothing.
func TestMembershipStore_SuspendAndRestore(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	joined, _, err := f.join(ctx)
	require.NoError(t, err)

	suspended, changed, err := f.suspend(ctx, f.user)
	require.NoError(t, err)
	require.True(t, changed)
	assert.Equal(t, joined.ID, suspended.ID)
	assert.Equal(t, service.MembershipStatusSuspended, suspended.Status)
	assert.Equal(t, service.RoleMember, suspended.Role)
	assert.Equal(t, service.MembershipSourceDomain, suspended.Source)
	assert.Equal(t, suspended, f.held(ctx, t))
	again, changed, err := f.suspend(ctx, f.user)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, suspended, again)

	active, err := f.ms.GetActiveTenantForUser(ctx, f.projectID, f.tenantID, f.user, "acme.com")
	require.NoError(t, err)
	assert.Nil(t, active, "a suspended member may not act in the tenant")
	list, err := f.ms.ListActiveTenantsForUser(ctx, f.projectID, f.user, "acme.com")
	require.NoError(t, err)
	assert.Empty(t, list)

	_, _, err = f.join(ctx)
	require.ErrorIs(t, err, service.ErrMemberSuspended)
	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceInvited, Role: service.RoleAdmin,
	})
	require.ErrorIs(t, err, service.ErrMemberSuspended)
	assert.Equal(t, suspended, f.held(ctx, t), "neither a join nor a grant wrote")

	restored, changed, err := f.restore(ctx, f.user, "acme.com")
	require.NoError(t, err)
	require.True(t, changed)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
	assert.Equal(t, service.RoleMember, restored.Role)
	assert.Equal(t, service.MembershipSourceDomain, restored.Source)
	active, err = f.ms.GetActiveTenantForUser(ctx, f.projectID, f.tenantID, f.user, "acme.com")
	require.NoError(t, err)
	assert.NotNil(t, active)
	again, changed, err = f.restore(ctx, f.user, "acme.com")
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, restored, again)

	// A domain membership whose email is off the tenant's verified domains
	// comes back ended; one from another source comes back active.
	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)
	ended, changed, err := f.restore(ctx, f.user, "elsewhere.example")
	require.NoError(t, err)
	require.True(t, changed)
	assert.Equal(t, service.MembershipStatusInactive, ended.Status)
	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceInvited, Role: service.RoleMember,
	})
	require.NoError(t, err)
	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)
	back, _, err := f.restore(ctx, f.user, "elsewhere.example")
	require.NoError(t, err)
	assert.Equal(t, service.MembershipStatusActive, back.Status)

	// An operator's upsert lifts a suspension.
	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)
	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceAdded, Role: service.RoleAdmin, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)
	assert.Equal(t, service.MembershipStatusActive, f.held(ctx, t).Status)
}

// TestMembershipStore_SuspendAndRestoreRefusals: only an active member can
// be suspended and only a suspended or active one restored; anything else
// is ErrNotFound and writes nothing.
func TestMembershipStore_SuspendAndRestoreRefusals(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)

	_, _, err := f.suspend(ctx, f.user)
	require.ErrorIs(t, err, service.ErrNotFound, "no membership")
	_, _, err = f.restore(ctx, f.user, "acme.com")
	require.ErrorIs(t, err, service.ErrNotFound, "no membership")

	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceInvited, Role: service.RoleMember, Status: service.MembershipStatusInactive,
	})
	require.NoError(t, err)
	_, _, err = f.suspend(ctx, f.user)
	require.ErrorIs(t, err, service.ErrNotFound, "an ended membership")
	_, _, err = f.restore(ctx, f.user, "acme.com")
	require.ErrorIs(t, err, service.ErrNotFound, "an ended membership")
	assert.Equal(t, service.MembershipStatusInactive, f.held(ctx, t).Status)

	for _, args := range [][3]string{{"", f.tenantID, f.user}, {f.projectID, "", f.user}, {f.projectID, f.tenantID, ""}} {
		_, _, err = f.ms.SuspendMembership(ctx, args[0], args[1], args[2])
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", args)
		_, _, err = f.ms.RestoreMembership(ctx, args[0], args[1], args[2], "acme.com")
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", args)
	}
}

// TestMembershipStore_SuspensionKeepsAnOwner: the last active owner cannot
// be suspended, and a suspended owner does not count as one, so the active
// owner left can be neither suspended nor removed.
func TestMembershipStore_SuspensionKeepsAnOwner(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)

	_, _, err := f.suspend(ctx, f.other)
	require.ErrorIs(t, err, service.ErrLastOwner)
	assert.Contains(t, err.Error(), "cannot suspend the last owner")
	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceAdded, Role: service.RoleOwner, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)

	_, changed, err := f.suspend(ctx, f.other)
	require.NoError(t, err)
	require.True(t, changed)
	_, _, err = f.suspend(ctx, f.user)
	require.ErrorIs(t, err, service.ErrLastOwner)
	require.ErrorIs(t, removeErr(ctx, f.ms, f.projectID, f.tenantID, f.user), service.ErrLastOwner)
	_, _, err = f.restore(ctx, f.other, "")
	require.NoError(t, err)
	require.NoError(t, removeErr(ctx, f.ms, f.projectID, f.tenantID, f.user))
}

// TestMembershipStore_ConcurrentSuspensionsKeepAnOwner: two co-owners
// suspended at once, or one suspended while the other is removed, leave
// exactly one active owner.
func TestMembershipStore_ConcurrentSuspensionsKeepAnOwner(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	owners := func() []string {
		t.Helper()
		members, err := f.ms.ListMembershipsForTenant(ctx, f.projectID, f.tenantID)
		require.NoError(t, err)
		var out []string
		for _, m := range members {
			if m.Role == service.RoleOwner && m.Status == service.MembershipStatusActive {
				out = append(out, m.UserID)
			}
		}
		return out
	}
	coOwners := func() {
		t.Helper()
		for _, userID := range []string{f.user, f.other} {
			_, err := f.ms.UpsertMembership(ctx, &service.TenantMembership{
				ProjectID: f.projectID, TenantID: f.tenantID, UserID: userID,
				Source: service.MembershipSourceAdded, Role: service.RoleOwner, Status: service.MembershipStatusActive,
			})
			require.NoError(t, err)
		}
	}
	suspend := func(userID string) func() error {
		return func() error { _, _, err := f.suspend(ctx, userID); return err }
	}

	const rounds = 20
	for round := range rounds {
		coOwners()
		err1, err2 := runTogether(suspend(f.user), suspend(f.other))
		require.True(t, (err1 == nil) != (err2 == nil), "round %d: exactly one co-owner is suspended (%v, %v)", round, err1, err2)
		for _, err := range []error{err1, err2} {
			if err != nil {
				require.ErrorIs(t, err, service.ErrLastOwner, "round %d", round)
			}
		}
		require.Len(t, owners(), 1, "round %d", round)
	}
	for round := range rounds {
		coOwners()
		suspendErr, removalErr := runTogether(suspend(f.user), func() error {
			return removeErr(ctx, f.ms, f.projectID, f.tenantID, f.other)
		})
		require.True(t, (suspendErr == nil) != (removalErr == nil), "round %d: exactly one change lands (%v, %v)", round, suspendErr, removalErr)
		for _, err := range []error{suspendErr, removalErr} {
			if err != nil {
				require.ErrorIs(t, err, service.ErrLastOwner, "round %d", round)
			}
		}
		require.Len(t, owners(), 1, "round %d", round)
	}
}

// TestDomainMembershipSuspensionSurvivesTheEmailLeaving: migration 0053's
// trigger leaves a suspended domain membership alone when the email leaves
// the domain, so coming back to the domain cannot shed the suspension, and
// it still ends an active one.
func TestDomainMembershipSuspensionSurvivesTheEmailLeaving(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusVerified)
	f.domainMember(ctx, t, f.tenant, f.onDomain)
	f.domainMember(ctx, t, f.tenant, f.outsider)
	_, _, err := f.members.SuspendMembership(ctx, f.project, f.tenant, f.onDomain)
	require.NoError(t, err)
	at := time.Now().UnixMilli()

	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "person@"+domainNowhere, at))
	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.outsider, "outsider@"+domainNowhere, at))
	assert.Equal(t, service.MembershipStatusSuspended, f.membershipStatus(ctx, t, f.tenant, f.onDomain))
	assert.Equal(t, service.MembershipStatusInactive, f.membershipStatus(ctx, t, f.tenant, f.outsider), "an active one still ends")

	require.NoError(t, f.repo.UpdateUserEmail(ctx, f.onDomain, "person@"+govDomain, at))
	assert.Equal(t, service.MembershipStatusSuspended, f.membershipStatus(ctx, t, f.tenant, f.onDomain))
	restored, _, err := f.members.RestoreMembership(ctx, f.project, f.tenant, f.onDomain, govDomain)
	require.NoError(t, err)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
}

// TestSuspendTenantMembersMigrationRoundTrip: 0053 admits 'suspended' and
// keeps the trigger off suspended rows; its down migration ends every
// suspended membership, so the narrower check holds again, and the trigger
// is 0047's once more. 52 → 53 → 52 → 53.
func TestSuspendTenantMembersMigrationRoundTrip(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	migrateToVersion(t, scratch, 52)
	const project = "proj-suspend"
	_, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id', $1, false)`, project)
	require.NoError(t, err)
	for _, q := range []string{
		`INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('proj-suspend', 'scope-suspend', 1, 1)`,
		`INSERT INTO tenants (id, project_id, status, created_at_ms, updated_at_ms) VALUES ('t', 'proj-suspend', 'claimed', 1, 1)`,
		`INSERT INTO domains (id, project_id, tenant_id, domain, verification_method, status, created_at_ms, updated_at_ms)
			VALUES ('d', 'proj-suspend', 't', 'acme.example', 'dns_txt', 'verified', 1, 1)`,
		`INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms) VALUES ('held', 'proj-suspend', 'held@acme.example', 1, 1)`,
		`INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms) VALUES ('free', 'proj-suspend', 'free@acme.example', 1, 1)`,
	} {
		_, err = raw.Exec(ctx, q)
		require.NoError(t, err, q)
	}
	insertSuspended := func() error {
		_, err := raw.Exec(ctx, `INSERT INTO tenant_memberships (id, project_id, tenant_id, user_id, source, role, status, created_at_ms, updated_at_ms)
			VALUES ('m-held', 'proj-suspend', 't', 'held', 'domain', 'member', 'suspended', 1, 1)
			ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET status = 'suspended'`)
		return err
	}
	status := func(userID string) string {
		t.Helper()
		var s string
		require.NoError(t, raw.QueryRow(ctx, `SELECT status FROM tenant_memberships WHERE user_id = $1`, userID).Scan(&s))
		return s
	}
	moveEmail := func(userID, email string) {
		t.Helper()
		_, err := raw.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, userID, email)
		require.NoError(t, err)
	}
	statusCheck := func() string {
		t.Helper()
		var def string
		require.NoError(t, raw.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid = 'tenant_memberships'::regclass AND conname = 'tenant_memberships_status_check'`).Scan(&def))
		return def
	}

	err = insertSuspended()
	require.Error(t, err, "52 refuses a suspended membership")

	for _, version := range []uint{53, 52, 53} {
		migrateToVersion(t, scratch, version)
		assert.Equal(t, version == 53, strings.Contains(statusCheck(), "suspended"), "version %d", version)
		if version == 52 {
			assert.Equal(t, service.MembershipStatusInactive, status("held"), "the down migration ends a suspension")
			require.Error(t, insertSuspended())
			continue
		}
		require.NoError(t, insertSuspended())
		_, err = raw.Exec(ctx, `INSERT INTO tenant_memberships (id, project_id, tenant_id, user_id, source, role, status, created_at_ms, updated_at_ms)
			VALUES ('m-free', 'proj-suspend', 't', 'free', 'domain', 'member', 'active', 1, 1)
			ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET status = 'active'`)
		require.NoError(t, err)
		moveEmail("held", "held@elsewhere.example")
		moveEmail("free", "free@elsewhere.example")
		assert.Equal(t, service.MembershipStatusSuspended, status("held"), "version %d: the trigger leaves a suspension", version)
		assert.Equal(t, service.MembershipStatusInactive, status("free"), "version %d: and ends an active one", version)
		moveEmail("held", "held@acme.example")
		moveEmail("free", "free@acme.example")
	}

	// Back at 52 the trigger is 0047's: it ends the domain membership the
	// down migration ended, and an active one, whatever.
	migrateToVersion(t, scratch, 52)
	_, err = raw.Exec(ctx, `UPDATE tenant_memberships SET status = 'active'`)
	require.NoError(t, err)
	moveEmail("held", "held@elsewhere.example")
	assert.Equal(t, service.MembershipStatusInactive, status("held"))
}
