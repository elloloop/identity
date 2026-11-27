package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// managedHelpFixture is the join fixture's tenant, owned by other, with a
// managed account it holds as an active member.
type managedHelpFixture struct {
	*joinFixture
	managed string
}

func newManagedHelpFixture(ctx context.Context, t *testing.T) *managedHelpFixture {
	t.Helper()
	f := &managedHelpFixture{joinFixture: newJoinFixture(ctx, t, memberRoleDSN(t))}
	f.managed = f.managedAccount(ctx, t, "ann@acme.com", service.MembershipStatusActive)
	return f
}

// managedAccount creates a managed account of the tenant at address and, for
// a status other than "", gives it a membership with that status.
func (f *managedHelpFixture) managedAccount(ctx context.Context, t *testing.T, address, status string) string {
	t.Helper()
	now := time.Now()
	id, err := f.accounts.CreateUser(ctx, &service.User{
		Email: address, Status: service.StatusActive, ManagedByTenantID: f.tenantID,
		SetUpAtMs: now.UnixMilli(), SetupEpoch: 1, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	if status != "" {
		_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: f.projectID, TenantID: f.tenantID, UserID: id,
			Source: service.MembershipSourceInvited, Role: service.RoleMember, Status: status,
		})
		require.NoError(t, err)
	}
	return id
}

func (f *managedHelpFixture) request(address, source string, now time.Time) service.ManagedHelpRequest {
	return service.ManagedHelpRequest{
		ProjectID: f.projectID, Address: address, SourceKey: source, NowMs: now.UnixMilli(),
		SinceMs: now.Add(-24 * time.Hour).UnixMilli(), MaxPerTenant: 3, MaxPerTenantSource: 2,
	}
}

// TestMembershipStore_RecordManagedHelp_TellsTheTenantOncePerAccount: the
// first request about a managed account is recorded and names the tenant's
// active owners and admins, not the account; another within the window is a
// duplicate, and one after it notifies again.
func TestMembershipStore_RecordManagedHelp_TellsTheTenantOncePerAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newManagedHelpFixture(ctx, t)
	admin := f.account(ctx, t, "admin@acme.com")
	f.grant(ctx, t, admin, service.RoleAdmin)
	suspendedAdmin := f.account(ctx, t, "away@acme.com")
	f.grant(ctx, t, suspendedAdmin, service.RoleAdmin)
	_, _, err := f.ms.SuspendMembership(ctx, f.projectID, f.tenantID, suspendedAdmin)
	require.NoError(t, err)
	now := time.Now()

	rec, err := f.ms.RecordManagedHelp(ctx, f.request("ANN@acme.com", "src-1", now))
	require.NoError(t, err)
	assert.Equal(t, service.ManagedHelpNotify, rec.Outcome)
	assert.Equal(t, f.managed, rec.Account.ID)
	assert.Equal(t, f.tenantID, rec.TenantID)
	var recipients []string
	for _, u := range rec.Recipients {
		recipients = append(recipients, u.ID)
	}
	assert.ElementsMatch(t, []string{f.other, admin}, recipients, "the active owner and admin, not the suspended admin")

	again, err := f.ms.RecordManagedHelp(ctx, f.request("ann@acme.com", "src-2", now.Add(time.Hour)))
	require.NoError(t, err)
	assert.Equal(t, service.ManagedHelpDuplicate, again.Outcome)
	assert.Empty(t, again.Recipients)

	later, err := f.ms.RecordManagedHelp(ctx, f.request("ann@acme.com", "src-1", now.Add(25*time.Hour)))
	require.NoError(t, err)
	assert.Equal(t, service.ManagedHelpNotify, later.Outcome, "a day later the tenant is told again")
}

// TestMembershipStore_RecordManagedHelp_Caps: past the source's cap one
// source's requests about other accounts are refused while another source's
// still notify, until the tenant's cap refuses everyone.
func TestMembershipStore_RecordManagedHelp_Caps(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newManagedHelpFixture(ctx, t)
	for _, addr := range []string{"bo@acme.com", "cy@acme.com", "di@acme.com"} {
		f.managedAccount(ctx, t, addr, service.MembershipStatusActive)
	}
	now := time.Now()
	outcome := func(addr, source string) string {
		t.Helper()
		rec, err := f.ms.RecordManagedHelp(ctx, f.request(addr, source, now))
		require.NoError(t, err)
		return rec.Outcome
	}

	assert.Equal(t, service.ManagedHelpNotify, outcome("ann@acme.com", "src-1"))
	assert.Equal(t, service.ManagedHelpNotify, outcome("bo@acme.com", "src-1"))
	assert.Equal(t, service.ManagedHelpSourceLimited, outcome("cy@acme.com", "src-1"))
	assert.Equal(t, service.ManagedHelpNotify, outcome("cy@acme.com", "src-2"))
	assert.Equal(t, service.ManagedHelpTenantLimited, outcome("di@acme.com", "src-3"))
}

// TestMembershipStore_RecordManagedHelp_OnlyActiveOrSuspendedManagedAccounts:
// a personal account, an address no account holds, and a managed account
// with no membership, or one that has left, are ErrNotFound; a suspended
// one's tenant is told.
func TestMembershipStore_RecordManagedHelp_OnlyActiveOrSuspendedManagedAccounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newManagedHelpFixture(ctx, t)
	f.managedAccount(ctx, t, "new@acme.com", "")
	f.managedAccount(ctx, t, "gone@acme.com", service.MembershipStatusInactive)
	f.managedAccount(ctx, t, "held@acme.com", service.MembershipStatusSuspended)
	now := time.Now()

	for _, addr := range []string{"u1@acme.com", "nobody@acme.com", "new@acme.com", "gone@acme.com"} {
		_, err := f.ms.RecordManagedHelp(ctx, f.request(addr, "src", now))
		require.ErrorIs(t, err, service.ErrNotFound, addr)
	}
	rec, err := f.ms.RecordManagedHelp(ctx, f.request("held@acme.com", "src", now))
	require.NoError(t, err)
	assert.Equal(t, service.ManagedHelpNotify, rec.Outcome)

	_, err = f.ms.RecordManagedHelp(ctx, service.ManagedHelpRequest{ProjectID: f.projectID, Address: "ann@acme.com"})
	require.ErrorIs(t, err, service.ErrInvalidArgument, "the caps are required")
}

// TestMembershipStore_RecordManagedHelp_ConcurrentRequestsKeepTheCap: requests
// about different accounts racing for a tenant with room for one notice
// notify exactly once.
func TestMembershipStore_RecordManagedHelp_ConcurrentRequestsKeepTheCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newManagedHelpFixture(ctx, t)
	const racers = 6
	addrs := make([]string, racers)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("racer%d@acme.com", i)
		f.managedAccount(ctx, t, addrs[i], service.MembershipStatusActive)
	}
	now := time.Now()
	var wg sync.WaitGroup
	outcomes := make([]string, racers)
	errs := make([]error, racers)
	for i, addr := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := f.request(addr, fmt.Sprintf("src-%d", i), now)
			req.MaxPerTenant = 1
			rec, err := f.ms.RecordManagedHelp(ctx, req)
			if err != nil {
				errs[i] = err
				return
			}
			outcomes[i] = rec.Outcome
		}()
	}
	wg.Wait()
	require.NoError(t, errors.Join(errs...))
	notified := 0
	for _, o := range outcomes {
		if o == service.ManagedHelpNotify {
			notified++
		} else {
			assert.Equal(t, service.ManagedHelpTenantLimited, o)
		}
	}
	assert.Equal(t, 1, notified)
}

// TestMembershipStore_RecordManagedHelp_NoRecipientsRecordsNothing: a tenant
// with no active owner or admin to tell gets no notice and records nothing,
// so neither the account's day nor a cap is used up; once it has one, the
// next request tells it.
func TestMembershipStore_RecordManagedHelp_NoRecipientsRecordsNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newManagedHelpFixture(ctx, t)
	setOwner := func(status string) {
		t.Helper()
		_, err := f.ms.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.other,
			Source: service.MembershipSourceCreated, Role: service.RoleOwner, Status: status,
		})
		require.NoError(t, err)
	}
	setOwner(service.MembershipStatusSuspended)
	now := time.Now()
	for range 2 {
		rec, err := f.ms.RecordManagedHelp(ctx, f.request("ann@acme.com", "src-1", now))
		require.NoError(t, err)
		assert.Equal(t, service.ManagedHelpNoRecipients, rec.Outcome)
		assert.Empty(t, rec.Recipients)
	}
	var recorded int
	require.NoError(t, f.ms.pool.QueryRow(ctx, `SELECT count(*) FROM managed_help_notices WHERE project_id = $1`, f.projectID).Scan(&recorded))
	assert.Zero(t, recorded)

	setOwner(service.MembershipStatusActive)
	rec, err := f.ms.RecordManagedHelp(ctx, f.request("ann@acme.com", "src-1", now))
	require.NoError(t, err)
	assert.Equal(t, service.ManagedHelpNotify, rec.Outcome)
}
