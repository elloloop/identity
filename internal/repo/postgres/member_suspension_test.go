package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/emailaddr"
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

// restore lifts userID's suspension as the owner or admin byID.
func (f *joinFixture) restore(ctx context.Context, userID, byID string) (*service.TenantMembership, bool, error) {
	return f.ms.RestoreMembership(ctx, f.projectID, f.tenantID, userID, service.RestoredByMember(byID))
}

// restoreAsOperator lifts userID's suspension as an operator.
func (f *joinFixture) restoreAsOperator(ctx context.Context, userID string) (*service.TenantMembership, bool, error) {
	return f.ms.RestoreMembership(ctx, f.projectID, f.tenantID, userID, service.RestoredByOperator())
}

// moveEmail changes userID's email, as an account change would.
func (f *joinFixture) moveEmail(ctx context.Context, t *testing.T, userID, email string) {
	t.Helper()
	require.NoError(t, f.accounts.UpdateUserEmail(ctx, userID, email, time.Now().UnixMilli()))
}

// account creates an account of the fixture's project with email, and
// returns its id.
func (f *joinFixture) account(ctx context.Context, t *testing.T, email string) string {
	t.Helper()
	return f.accountWithID(ctx, t, "", email)
}

// accountWithID creates an account of the fixture's project with email and
// id, for a test that needs ids in a known order, or a generated id when id
// is empty, and returns its id.
func (f *joinFixture) accountWithID(ctx context.Context, t *testing.T, id, email string) string {
	t.Helper()
	now := time.Now()
	id, err := f.accounts.CreateUser(ctx, &service.User{ID: id, Email: email, Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	return id
}

// upgradeSQL returns the one fenced sql block of docs/UPGRADE.md that
// starts with prefix, so a test runs the statement the guide gives rather
// than a copy of it.
func upgradeSQL(t *testing.T, prefix string) string {
	t.Helper()
	guide, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "UPGRADE.md"))
	require.NoError(t, err)
	var found []string
	for _, block := range strings.Split(string(guide), "```sql\n")[1:] {
		if body, _, closed := strings.Cut(block, "```"); closed && strings.HasPrefix(body, prefix) {
			found = append(found, body)
		}
	}
	require.Len(t, found, 1, "docs/UPGRADE.md holds one sql block starting %q", prefix)
	return found[0]
}

// waitOnLock waits until exactly one session of the test database is
// waiting on a lock in a statement matching the LIKE pattern like.
func waitOnLock(ctx context.Context, t *testing.T, dsn, like, msg string) {
	t.Helper()
	watch, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = watch.Close(ctx) }()
	require.Eventually(t, func() bool {
		var waiting int
		err := watch.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND query LIKE $1`, like).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 20*time.Millisecond, msg)
}

// grant gives userID an invited membership with role.
func (f *joinFixture) grant(ctx context.Context, t *testing.T, userID, role string) {
	t.Helper()
	_, _, err := f.ms.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: userID,
		Source: service.MembershipSourceInvited, Role: role,
	})
	require.NoError(t, err)
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

	restored, changed, err := f.restore(ctx, f.user, f.other)
	require.NoError(t, err)
	require.True(t, changed)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
	assert.Equal(t, service.RoleMember, restored.Role)
	assert.Equal(t, service.MembershipSourceDomain, restored.Source)
	active, err = f.ms.GetActiveTenantForUser(ctx, f.projectID, f.tenantID, f.user, "acme.com")
	require.NoError(t, err)
	assert.NotNil(t, active)
	again, changed, err = f.restore(ctx, f.user, f.other)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, restored, again)

	// A domain membership whose email left the tenant's verified domains
	// while it was suspended comes back ended; one from another source
	// comes back active.
	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)
	f.moveEmail(ctx, t, f.user, "u1@elsewhere.example")
	ended, changed, err := f.restore(ctx, f.user, f.other)
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
	back, _, err := f.restoreAsOperator(ctx, f.user)
	require.NoError(t, err)
	assert.Equal(t, service.MembershipStatusActive, back.Status, "an operator's restore")

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
	_, _, err = f.restore(ctx, f.user, f.other)
	require.ErrorIs(t, err, service.ErrNotFound, "no membership")

	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceInvited, Role: service.RoleMember, Status: service.MembershipStatusInactive,
	})
	require.NoError(t, err)
	_, _, err = f.suspend(ctx, f.user)
	require.ErrorIs(t, err, service.ErrNotFound, "an ended membership")
	_, _, err = f.restore(ctx, f.user, f.other)
	require.ErrorIs(t, err, service.ErrNotFound, "an ended membership")
	assert.Equal(t, service.MembershipStatusInactive, f.held(ctx, t).Status)

	for _, args := range [][3]string{{"", f.tenantID, f.user}, {f.projectID, "", f.user}, {f.projectID, f.tenantID, ""}} {
		_, _, err = f.ms.SuspendMembership(ctx, args[0], args[1], args[2])
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", args)
		_, _, err = f.ms.RestoreMembership(ctx, args[0], args[1], args[2], service.RestoredByMember(f.other))
		require.ErrorIs(t, err, service.ErrInvalidArgument, "%v", args)
	}
}

// TestMembershipStore_RestoreChecksTheRestorer: a restore is written only
// while the one restoring holds an active owner or admin membership, read
// where the restore is: a suspended admin, a plain member, someone with no
// membership and the suspended member themselves are refused, as is a
// restore that names no restorer (the zero Restorer), and the suspension
// stands.
func TestMembershipStore_RestoreChecksTheRestorer(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	_, _, err := f.join(ctx)
	require.NoError(t, err)
	admin := f.account(ctx, t, "admin@acme.com")
	member := f.account(ctx, t, "member@acme.com")
	f.grant(ctx, t, admin, service.RoleAdmin)
	f.grant(ctx, t, member, service.RoleMember)
	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)
	_, _, err = f.suspend(ctx, admin)
	require.NoError(t, err)

	for name, by := range map[string]string{
		"a suspended admin":     admin,
		"a plain member":        member,
		"no member":             f.account(ctx, t, "stranger@acme.com"),
		"the suspended member":  f.user,
		"an id with no account": "no-such-user",
	} {
		_, _, err := f.restore(ctx, f.user, by)
		require.ErrorIs(t, err, service.ErrPermissionDenied, name)
		assert.Equal(t, service.MembershipStatusSuspended, f.held(ctx, t).Status, name)
	}
	// The zero Restorer names the empty user id. A row for that id, an
	// active owner of the tenant, would let it restore if the store judged
	// it as a member; it refuses it before reading anything.
	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	nobody := []string{
		`INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms) VALUES ('', $1, 'nobody@acme.com', 1, 1)`,
		`INSERT INTO tenant_memberships (id, project_id, tenant_id, user_id, source, role, status, created_at_ms, updated_at_ms)
			VALUES ('m-nobody', $1, $2, '', 'added', 'owner', 'active', 1, 1)`,
	}
	_, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id', $1, false)`, f.projectID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, nobody[0], f.projectID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, nobody[1], f.projectID, f.tenantID)
	require.NoError(t, err)
	_, _, err = f.ms.RestoreMembership(ctx, f.projectID, f.tenantID, f.user, service.Restorer{})
	require.ErrorIs(t, err, service.ErrPermissionDenied, "a restore that names no restorer fails closed")
	assert.Equal(t, service.MembershipStatusSuspended, f.held(ctx, t).Status)
	_, err = raw.Exec(ctx, `DELETE FROM tenant_memberships WHERE project_id = $1 AND id = 'm-nobody'`, f.projectID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `DELETE FROM users WHERE project_id = $1 AND id = ''`, f.projectID)
	require.NoError(t, err)
	_, _, err = f.restore(ctx, admin, admin)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "a suspended admin restoring themselves")

	restored, changed, err := f.restore(ctx, admin, f.other)
	require.NoError(t, err)
	require.True(t, changed)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
	restored, changed, err = f.restore(ctx, f.user, admin)
	require.NoError(t, err, "a restored admin restores")
	require.True(t, changed)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
}

// TestMembershipStore_RestoreJudgesTheEmailWhereItWrites: a restore reads
// the account's email in its own transaction and holds the account's row,
// so an email change it waits for is the one it judges: a domain member
// whose email left the domain before the restore committed comes back
// ended, not active.
func TestMembershipStore_RestoreJudgesTheEmailWhereItWrites(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	_, _, err := f.join(ctx)
	require.NoError(t, err)
	_, _, err = f.suspend(ctx, f.user)
	require.NoError(t, err)

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	move, err := raw.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = move.Rollback(ctx) }()
	_, err = move.Exec(ctx, `SELECT set_config($1, $2, true)`, rlsGUC, f.projectID)
	require.NoError(t, err)
	_, err = move.Exec(ctx, `UPDATE users SET email = 'u1@elsewhere.example' WHERE project_id = $1 AND id = $2`, f.projectID, f.user)
	require.NoError(t, err)

	type result struct {
		m   *service.TenantMembership
		err error
	}
	done := make(chan result, 1)
	go func() {
		m, _, err := f.restore(ctx, f.user, f.other)
		done <- result{m, err}
	}()
	waitOnLock(ctx, t, dsn, "%FROM users%FOR SHARE%", "the restore waits on the account's row")

	require.NoError(t, move.Commit(ctx))

	got := <-done
	require.NoError(t, got.err)
	assert.Equal(t, service.MembershipStatusInactive, got.m.Status, "the email the restore waited for is the one it judged")
}

// TestMembershipStore_RestoreQueuesWithAnAccountDeletion: a restore takes
// the target's account row before any membership row, the order an account
// deletion takes them in (its users row, then by cascade its memberships),
// so the two queue rather than deadlock. Here the restore holds the
// target's membership while it waits on an owner's, the deletion of the
// target starts behind it, and both finish once the owner's row is free.
func TestMembershipStore_RestoreQueuesWithAnAccountDeletion(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	// lockOwnersAnd takes memberships in user_id order, so these ids put the
	// target's before the owner's the test holds.
	target := f.accountWithID(ctx, t, "restore-a-target", "target@acme.com")
	owner := f.accountWithID(ctx, t, "restore-z-owner", "owner@acme.com")
	f.grant(ctx, t, target, service.RoleMember)
	f.grant(ctx, t, owner, service.RoleOwner)
	_, _, err := f.suspend(ctx, target)
	require.NoError(t, err)

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	hold, err := raw.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = hold.Rollback(ctx) }()
	_, err = hold.Exec(ctx, `SELECT 1 FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3
		FOR UPDATE`, f.projectID, f.tenantID, owner)
	require.NoError(t, err)

	restored := make(chan error, 1)
	go func() {
		_, _, err := f.restore(ctx, target, f.other)
		restored <- err
	}()
	waitOnLock(ctx, t, dsn, "%FROM tenant_memberships%FOR UPDATE%", "the restore waits on the owner's membership")
	deleted := make(chan error, 1)
	go func() { deleted <- f.accounts.DeleteUser(ctx, target) }()
	waitOnLock(ctx, t, dsn, "DELETE FROM users%", "the deletion waits behind the restore")

	require.NoError(t, hold.Rollback(ctx))
	require.NoError(t, <-restored, "the restore finishes")
	require.NoError(t, <-deleted, "the deletion finishes after it")
	m, err := f.ms.GetMembership(ctx, f.projectID, f.tenantID, target)
	require.NoError(t, err)
	assert.Nil(t, m, "the deletion took the restored membership with the account")
}

// TestMembershipStore_RestoreLocksOnlyASuspendedMembersAccount: a restore
// takes its target's account row only when the target is a suspended
// member. Naming any other account writes nothing, so it must not hold up
// writes to that account either.
func TestMembershipStore_RestoreLocksOnlyASuspendedMembersAccount(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	stranger := f.account(ctx, t, "stranger@acme.com")
	member := f.account(ctx, t, "member@acme.com")
	f.grant(ctx, t, member, service.RoleMember)

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	hold, err := raw.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = hold.Rollback(ctx) }()
	_, err = hold.Exec(ctx, `SELECT set_config($1, $2, true)`, rlsGUC, f.projectID)
	require.NoError(t, err)
	var locked int
	require.NoError(t, hold.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT 1 FROM users WHERE project_id = $1 AND id = ANY($2) FOR UPDATE) l`,
		f.projectID, []string{stranger, member}).Scan(&locked))
	require.Equal(t, 2, locked, "both accounts' rows are held")

	quick, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	_, _, err = f.ms.RestoreMembership(quick, f.projectID, f.tenantID, stranger, service.RestoredByMember(f.other))
	require.ErrorIs(t, err, service.ErrNotFound, "naming a non-member waits on nothing")
	m, changed, err := f.ms.RestoreMembership(quick, f.projectID, f.tenantID, member, service.RestoredByMember(f.other))
	require.NoError(t, err, "naming an active member waits on nothing")
	assert.False(t, changed)
	assert.Equal(t, service.MembershipStatusActive, m.Status)
}

// TestMembershipStore_TransferAndSuspension: ownership passes only from an
// active owner to an active member, so a suspended member can neither
// receive it nor, as a suspended owner, hand it on.
func TestMembershipStore_TransferAndSuspension(t *testing.T) {
	dsn := suspensionDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	f.grant(ctx, t, f.user, service.RoleMember)
	_, _, err := f.suspend(ctx, f.user)
	require.NoError(t, err)
	_, _, err = f.ms.TransferOwnership(ctx, f.projectID, f.tenantID, f.other, f.user)
	require.ErrorIs(t, err, service.ErrNotFound, "to a suspended member")

	co := f.account(ctx, t, "co@acme.com")
	f.grant(ctx, t, co, service.RoleOwner)
	_, _, err = f.suspend(ctx, f.other)
	require.NoError(t, err)
	_, _, err = f.restore(ctx, f.user, co)
	require.NoError(t, err)
	_, _, err = f.ms.TransferOwnership(ctx, f.projectID, f.tenantID, f.other, f.user)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "by a suspended owner")
	assert.Equal(t, service.RoleMember, f.held(ctx, t).Role)
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
	_, _, err = f.restore(ctx, f.other, f.user)
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
	// A suspension of the member a transfer makes the owner: whichever lands
	// first, the other is refused, and one active owner is left.
	transfer := func() error {
		_, _, err := f.ms.TransferOwnership(ctx, f.projectID, f.tenantID, f.other, f.user)
		return err
	}
	for round := range rounds {
		_, err := f.ms.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
			Source: service.MembershipSourceAdded, Role: service.RoleMember, Status: service.MembershipStatusActive,
		})
		require.NoError(t, err)
		_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.other,
			Source: service.MembershipSourceAdded, Role: service.RoleOwner, Status: service.MembershipStatusActive,
		})
		require.NoError(t, err)
		suspendErr, transferErr := runTogether(suspend(f.user), transfer)
		require.True(t, (suspendErr == nil) != (transferErr == nil), "round %d: exactly one change lands (%v, %v)", round, suspendErr, transferErr)
		if suspendErr != nil {
			require.ErrorIs(t, suspendErr, service.ErrLastOwner, "round %d: the new owner is the last one", round)
		} else {
			require.ErrorIs(t, transferErr, service.ErrNotFound, "round %d: a suspended member takes nothing", round)
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

	// The restore reads the email under row-level security, through a
	// store bound to another project, as the control plane's is: it binds
	// its transaction to the membership's project, so it finds the email
	// back on the domain.
	elsewhere, err := New(ctx, Config{DSN: roleDSN, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: "control-plane"})
	require.NoError(t, err)
	t.Cleanup(elsewhere.Close)
	restored, _, err := NewMembershipStore(elsewhere).RestoreMembership(ctx, f.project, f.tenant, f.onDomain, service.RestoredByOperator())
	require.NoError(t, err)
	assert.Equal(t, service.MembershipStatusActive, restored.Status)
}

// TestSuspendTenantMembersMigrationRoundTrip: 0053 admits 'suspended' and
// keeps the trigger off suspended rows. Its down migration refuses to run
// while a membership is suspended, changing nothing; once none is, it
// narrows the check again and the trigger is 0047's once more.
// 52 → 53 → 52 → 53 → 52.
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
		if version == 52 {
			err := withMigrator(t, scratch, func(m *migrate.Migrate) error { return m.Migrate(52) })
			require.ErrorContains(t, err, "tenant memberships suspended: 1;")
			require.NoError(t, withMigrator(t, scratch, func(m *migrate.Migrate) error {
				v, dirty, err := m.Version()
				require.NoError(t, err)
				assert.Equal(t, uint(52), v, "a refused down migration records 52")
				assert.True(t, dirty, "and records it dirty")
				return m.Force(53)
			}))
			assert.True(t, strings.Contains(statusCheck(), "suspended"), "the refused down migration changed nothing")
			assert.Equal(t, service.MembershipStatusSuspended, status("held"))
			decideSuspensionsInSQL(ctx, t, raw)
		}
		migrateToVersion(t, scratch, version)
		assert.Equal(t, version == 53, strings.Contains(statusCheck(), "suspended"), "version %d", version)
		if version == 52 {
			assert.Contains(t, statusCheck(), "NOT VALID", "the narrower check skips the scan the down migration's own check made")
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

	// Back at 52, once no one is suspended, the trigger is 0047's: it ends
	// every active domain membership whose email leaves the domain.
	_, err = raw.Exec(ctx, `UPDATE tenant_memberships SET status = 'active'`)
	require.NoError(t, err)
	migrateToVersion(t, scratch, 52)
	moveEmail("held", "held@elsewhere.example")
	assert.Equal(t, service.MembershipStatusInactive, status("held"))
}

// decideSuspensionsInSQL runs, at version 53 with "held" suspended in
// tenant t, what docs/UPGRADE.md tells an operator to run before migrating
// down while suspensions stand. Each block is one transaction whose SET
// LOCAL row_security = off ends with it.
//
// The listing names, for the operator to decide by hand, the suspended
// members whose email is not all ASCII (one with no email has no mailbox,
// and is left out), and the pending invitations to an address that is not
// all ASCII in the tenants they are suspended from. A role that row-level
// security binds cannot run the statement at all. Run as the guide says,
// it removes every suspended member, recording each removal, revokes each
// removed person's pending invitations whose address canonicalizes, as
// acceptance does, to their canonical mailbox in the tenant they were
// removed from, leaves every other invitation as it was, and lists what it
// changed. The accounts' emails are stored as typed, as accounts made
// before the service canonicalized them are, so the statement
// canonicalizes the member's side too.
func decideSuspensionsInSQL(ctx context.Context, t *testing.T, raw *pgx.Conn) {
	t.Helper()
	exec := func(q string) {
		t.Helper()
		_, err := raw.Exec(ctx, q)
		require.NoError(t, err, q)
	}
	exec(`INSERT INTO tenants (id, project_id, status, created_at_ms, updated_at_ms) VALUES
		('t2', 'proj-suspend', 'claimed', 1, 1),
		('t3', 'proj-suspend', 'claimed', 1, 1)`)
	exec(`INSERT INTO users (id, project_id, email, created_at_ms, updated_at_ms) VALUES
		('tagged', 'proj-suspend', 'Tagged+Work@acme.example', 1, 1),
		('dotted', 'proj-suspend', 'Dot.Ted@googlemail.com.', 1, 1),
		('intl', 'proj-suspend', 'intl@bücher.example', 1, 1),
		('nomail', 'proj-suspend', '', 1, 1),
		('present', 'proj-suspend', 'present@acme.example', 1, 1)`)
	exec(`INSERT INTO tenant_memberships (id, project_id, tenant_id, user_id, source, role, status, created_at_ms, updated_at_ms) VALUES
		('m-tagged', 'proj-suspend', 't', 'tagged', 'invited', 'member', 'suspended', 1, 1),
		('m-dotted', 'proj-suspend', 't', 'dotted', 'invited', 'member', 'suspended', 1, 1),
		('m-intl', 'proj-suspend', 't', 'intl', 'invited', 'member', 'suspended', 1, 1),
		('m-free-t2', 'proj-suspend', 't2', 'free', 'invited', 'member', 'suspended', 1, 1),
		('m-nomail-t2', 'proj-suspend', 't2', 'nomail', 'added', 'member', 'suspended', 1, 1),
		('m-present-t3', 'proj-suspend', 't3', 'present', 'invited', 'member', 'active', 1, 1)`)
	// free was removed from t2 once before being invited back; the
	// statement records the new removal over the old one.
	exec(`INSERT INTO tenant_member_removals (project_id, tenant_id, user_id, removed_at_ms) VALUES ('proj-suspend', 't2', 'free', 1)`)
	exec(`INSERT INTO tenant_invitations (id, project_id, tenant_id, token_hash, email, role, status, expires_at_ms, created_at_ms) VALUES
		('inv-held', 'proj-suspend', 't', 'hash-held', 'held@acme.example', 'admin', 'pending', 9999999999999, 1),
		('inv-held-t2', 'proj-suspend', 't2', 'hash-held-t2', 'held@acme.example', 'member', 'pending', 9999999999999, 1),
		('inv-held-accepted', 'proj-suspend', 't', 'hash-held-accepted', 'held@acme.example', 'member', 'accepted', 9999999999999, 1),
		('inv-free', 'proj-suspend', 't', 'hash-free', 'free@acme.example', 'member', 'pending', 9999999999999, 1),
		('inv-tagged', 'proj-suspend', 't', 'hash-tagged', 'tagged@acme.example', 'member', 'pending', 9999999999999, 1),
		('inv-dotted', 'proj-suspend', 't', 'hash-dotted', 'dotted@gmail.com', 'member', 'pending', 9999999999999, 1),
		('inv-intl', 'proj-suspend', 't', 'hash-intl', 'intl@xn--bcher-kva.example', 'member', 'pending', 9999999999999, 1),
		('inv-umlaut', 'proj-suspend', 't', 'hash-umlaut', 'jürgen@acme.example', 'member', 'pending', 9999999999999, 1),
		('inv-umlaut-accepted', 'proj-suspend', 't', 'hash-umlaut-accepted', 'jürgen@acme.example', 'member', 'accepted', 9999999999999, 1),
		('inv-umlaut-t3', 'proj-suspend', 't3', 'hash-umlaut-t3', 'jürgen@acme.example', 'member', 'pending', 9999999999999, 1)`)
	// An invitation is stored canonicalized once, so one typed with two
	// trailing dots keeps one, and one typed with a space other than ASCII's
	// before its dot keeps the space; acceptance canonicalizes it again and
	// admits the person.
	storedOnce := func(typed, account string) string {
		t.Helper()
		stored, usable := emailaddr.Mailbox(typed)
		require.True(t, usable, typed)
		require.True(t, emailaddr.SameMailbox(stored, account), "%q admits %q", stored, account)
		return stored
	}
	_, err := raw.Exec(ctx, `INSERT INTO tenant_invitations (id, project_id, tenant_id, token_hash, email, role, status, expires_at_ms, created_at_ms) VALUES
		('inv-held-fqdn', 'proj-suspend', 't', 'hash-held-fqdn', $1, 'member', 'pending', 9999999999999, 1),
		('inv-dotted-fqdn', 'proj-suspend', 't', 'hash-dotted-fqdn', $2, 'member', 'pending', 9999999999999, 1),
		('inv-held-nbsp', 'proj-suspend', 't', 'hash-held-nbsp', $3, 'member', 'pending', 9999999999999, 1),
		('inv-held-vt', 'proj-suspend', 't', 'hash-held-vt', $4, 'member', 'pending', 9999999999999, 1)`,
		storedOnce("held@acme.example..", "held@acme.example"),
		storedOnce("Dot.Ted@GoogleMail.com..", "Dot.Ted@googlemail.com."),
		storedOnce("held@acme.example .", "held@acme.example"),
		storedOnce("held@acme.example\v.", "held@acme.example"))
	require.NoError(t, err)
	invitations := func() map[string]string {
		t.Helper()
		rows, err := raw.Query(ctx, `SELECT id, status FROM tenant_invitations`)
		require.NoError(t, err)
		out := map[string]string{}
		var id, status string
		_, err = pgx.ForEachRow(rows, []any{&id, &status}, func() error {
			out[id] = status
			return nil
		})
		require.NoError(t, err)
		return out
	}
	suspended := func() int {
		t.Helper()
		var n int
		require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM tenant_memberships WHERE status = 'suspended'`).Scan(&n))
		return n
	}
	rowSecurity := func() string {
		t.Helper()
		var setting string
		require.NoError(t, raw.QueryRow(ctx, `SHOW row_security`).Scan(&setting))
		return setting
	}
	// block returns the statements of the guide's sql block that starts
	// with the opening and then first, one per element, as psql sends them.
	const opening = "BEGIN;\nSET LOCAL row_security = off;\n"
	block := func(first string) []string {
		t.Helper()
		body := upgradeSQL(t, opening+first)
		require.True(t, strings.HasSuffix(body, ";\nCOMMIT;\n"), "the block starting %q commits", first)
		return strings.Split(strings.TrimSuffix(body, ";\n"), ";\n")
	}
	// column returns column i of every row q returns, joined with "/" to the
	// columns before it from from.
	column := func(q string, from, i int) []string {
		t.Helper()
		rows, err := raw.Query(ctx, q)
		require.NoError(t, err, q)
		var out []string
		for rows.Next() {
			values, err := rows.Values()
			require.NoError(t, err)
			parts := make([]string, 0, i-from+1)
			for _, v := range values[from : i+1] {
				parts = append(parts, fmt.Sprint(v))
			}
			out = append(out, strings.Join(parts, "/"))
		}
		require.NoError(t, rows.Err())
		return out
	}
	before, stillSuspended := invitations(), suspended()

	removal := block("WITH removed AS (")
	require.Len(t, removal, 4, "BEGIN, SET LOCAL, the statement, COMMIT")
	role := fmt.Sprintf("rollback_rls_bound_%d", time.Now().UnixNano())
	exec(`CREATE ROLE ` + role + ` NOLOGIN NOSUPERUSER NOBYPASSRLS`)
	defer func() {
		// ROLLBACK first: a failure inside an open transaction would make
		// every later statement fail, and leave the role in the cluster.
		for _, q := range []string{`ROLLBACK`, `RESET ROLE`, `DROP OWNED BY ` + role, `DROP ROLE ` + role} {
			if _, err := raw.Exec(ctx, q); err != nil {
				t.Logf("%s: %v", q, err)
			}
		}
	}()
	exec(`GRANT USAGE ON SCHEMA public TO ` + role)
	exec(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + role)
	exec(`SET ROLE ` + role)
	// Sent as one string, as psql -c sends it, the block stops at the
	// statement and never reaches its COMMIT.
	_, err = raw.Exec(ctx, strings.Join(removal, ";\n")+";\n")
	require.ErrorContains(t, err, "row-level security", "a role row-level security binds cannot run the statement")
	assert.Equal(t, byte('E'), raw.PgConn().TxStatus(), "the refusal leaves its transaction failed, so nothing commits")
	exec(`ROLLBACK`)
	exec(`RESET ROLE`)
	assert.Equal(t, stillSuspended, suspended(), "and the refused statement removed no one")
	assert.Equal(t, before, invitations(), "and revoked nothing")

	// Each block runs as psql runs a file, one statement at a time, so its
	// rows can be read inside its transaction.
	listing := block("SELECT m.")
	require.Len(t, listing, 5, "BEGIN, SET LOCAL, the two lists, COMMIT")
	exec(listing[0])
	exec(listing[1])
	members := column(listing[2], 2, 2)
	invited := column(listing[3], 2, 2)
	exec(listing[4])
	assert.Equal(t, "on", rowSecurity(), "the listing's setting ends with its transaction")
	assert.Equal(t, []string{"intl"}, members, "the listing names the suspended member whose email is not all ASCII, and not one with none")
	assert.ElementsMatch(t, []string{"inv-held-nbsp", "inv-held-vt", "inv-umlaut"}, invited,
		"and the pending invitations not all ASCII in the tenants members are suspended from")

	exec(removal[0])
	exec(removal[1])
	changes := column(removal[2], 0, 3)
	exec(removal[3])
	assert.Equal(t, byte('I'), raw.PgConn().TxStatus(), "the statement's transaction committed")
	assert.Equal(t, "on", rowSecurity(), "and its setting ended with it")
	assert.Equal(t, []string{
		"removed/proj-suspend/t/dotted",
		"removed/proj-suspend/t/held",
		"removed/proj-suspend/t/intl",
		"removed/proj-suspend/t/tagged",
		"removed/proj-suspend/t2/free",
		"removed/proj-suspend/t2/nomail",
		"revoked/proj-suspend/t/inv-dotted",
		"revoked/proj-suspend/t/inv-dotted-fqdn",
		"revoked/proj-suspend/t/inv-held",
		"revoked/proj-suspend/t/inv-held-fqdn",
		"revoked/proj-suspend/t/inv-tagged",
	}, changes, "the statement lists each member it removed and each invitation it revoked")
	assert.Zero(t, suspended(), "every suspended member is removed")
	rows, err := raw.Query(ctx, `SELECT tenant_id || '/' || user_id FROM tenant_member_removals ORDER BY 1`)
	require.NoError(t, err)
	removals, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	assert.Equal(t, []string{"t/dotted", "t/held", "t/intl", "t/tagged", "t2/free", "t2/nomail"}, removals, "each removal is recorded in its tenant")
	var removedAt int64
	require.NoError(t, raw.QueryRow(ctx, `SELECT removed_at_ms FROM tenant_member_removals WHERE tenant_id = 't2' AND user_id = 'free'`).Scan(&removedAt))
	assert.Greater(t, removedAt, int64(1), "a removal recorded before is recorded again")
	assert.Equal(t, map[string]string{
		"inv-held":            "revoked",
		"inv-held-fqdn":       "revoked",
		"inv-tagged":          "revoked",
		"inv-dotted":          "revoked",
		"inv-dotted-fqdn":     "revoked",
		"inv-held-t2":         "pending",
		"inv-held-accepted":   "accepted",
		"inv-free":            "pending",
		"inv-intl":            "pending",
		"inv-held-nbsp":       "pending",
		"inv-held-vt":         "pending",
		"inv-umlaut":          "pending",
		"inv-umlaut-accepted": "accepted",
		"inv-umlaut-t3":       "pending",
	}, invitations(), "the pending invitations to the canonical mailbox in the tenant each was removed from are revoked, and nothing else")
}
