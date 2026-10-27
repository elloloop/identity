package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// removeErr is RemoveMembership's error alone, for the checks that do not
// look at the membership it removed.
func removeErr(ctx context.Context, ms *MembershipStore, projectID, tenantID, userID string) error {
	_, err := ms.RemoveMembership(ctx, projectID, tenantID, userID)
	return err
}

// joinFixture is a claimed tenant with a verified domain that lets its
// people join, and a user on it.
type joinFixture struct {
	ms                                  *MembershipStore
	tenants                             *TenantStore
	domains                             *DomainStore
	projectID, tenantID, domainID, user string
	// other is a second user, the tenant's owner.
	other string
}

func newJoinFixture(ctx context.Context, t *testing.T, dsn string) *joinFixture {
	t.Helper()
	require.NoError(t, truncateAll(ctx, dsn))
	ms, _, projectID, tenantID, user1, user2 := newMembershipFixture(ctx, t, dsn)
	_, tenants, domains := newTenantDomainStores(ctx, t, dsn)
	domainID, err := domains.CreateDomain(ctx, &service.Domain{
		ProjectID: projectID, TenantID: tenantID, Domain: "acme.com",
		VerificationMethod: service.DomainVerificationDNSTXT, Status: service.DomainStatusPending,
	})
	require.NoError(t, err)
	require.NoError(t, domains.SetDomainStatus(ctx, projectID, domainID, service.DomainStatusVerified, time.Now().UnixMilli()))
	_, _, err = domains.SetDomainAllowJoin(ctx, projectID, domainID, true)
	require.NoError(t, err)
	_, _, err = ms.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: user2,
		Source: service.MembershipSourceCreated, Role: service.RoleOwner,
	})
	require.NoError(t, err)
	return &joinFixture{ms: ms, tenants: tenants, domains: domains, projectID: projectID, tenantID: tenantID, domainID: domainID, user: user1, other: user2}
}

func (f *joinFixture) join(ctx context.Context) (*service.TenantMembership, bool, error) {
	return f.ms.JoinByDomain(ctx, f.projectID, f.tenantID, f.user, f.domainID)
}

func (f *joinFixture) removed(ctx context.Context, t *testing.T) bool {
	t.Helper()
	removed, err := f.ms.IsRemoved(ctx, f.projectID, f.tenantID, f.user)
	require.NoError(t, err)
	return removed
}

func (f *joinFixture) held(ctx context.Context, t *testing.T) *service.TenantMembership {
	t.Helper()
	m, err := f.ms.GetMembership(ctx, f.projectID, f.tenantID, f.user)
	require.NoError(t, err)
	return m
}

// TestMembershipStore_RemovalIsRecordedAndRefusesAJoin: a removal is
// recorded with the membership it removed; while it stands a join by domain
// is ErrRemovedFromTenant and writes nothing, and so is a grant with the
// domain's source; a grant or upsert from any other source lets the person
// back in and deletes the record.
func TestMembershipStore_RemovalIsRecordedAndRefusesAJoin(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping removal record test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)

	joined, changed, err := f.join(ctx)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, service.MembershipSourceDomain, joined.Source)
	require.False(t, f.removed(ctx, t))

	removed, err := f.ms.RemoveMembership(ctx, f.projectID, f.tenantID, f.user)
	require.NoError(t, err)
	require.NotNil(t, removed)
	require.Equal(t, joined.ID, removed.ID, "the membership as it stood when removed")
	require.Equal(t, service.MembershipSourceDomain, removed.Source)
	require.Nil(t, f.held(ctx, t))
	require.True(t, f.removed(ctx, t))

	_, _, err = f.join(ctx)
	require.ErrorIs(t, err, service.ErrRemovedFromTenant)
	require.Nil(t, f.held(ctx, t), "a refused join writes nothing")

	// A grant with the domain's own source is no decision about the person.
	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceDomain, Role: service.RoleMember,
	})
	require.NoError(t, err)
	require.True(t, f.removed(ctx, t), "a domain grant leaves the removal standing")
	require.NoError(t, removeErr(ctx, f.ms, f.projectID, f.tenantID, f.user))

	// An accepted invitation lets them back in.
	invited, changed, err := f.ms.GrantMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceInvited, Role: service.RoleMember,
	})
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, service.MembershipSourceInvited, invited.Source)
	require.False(t, f.removed(ctx, t), "an invitation deletes the removal")
	held, changed, err := f.join(ctx)
	require.NoError(t, err)
	require.False(t, changed, "a member already holds the membership a join would make")
	require.Equal(t, invited.ID, held.ID)

	// An operator's upsert does too.
	require.NoError(t, removeErr(ctx, f.ms, f.projectID, f.tenantID, f.user))
	require.True(t, f.removed(ctx, t))
	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceAdded, Role: service.RoleAdmin,
	})
	require.NoError(t, err)
	require.False(t, f.removed(ctx, t), "an added membership deletes the removal")

	// Removing nobody records nothing.
	gone, err := f.ms.RemoveMembership(ctx, f.projectID, f.tenantID, "no-such-user")
	require.NoError(t, err)
	require.Nil(t, gone)
	removedNobody, err := f.ms.IsRemoved(ctx, f.projectID, f.tenantID, "no-such-user")
	require.NoError(t, err)
	require.False(t, removedNobody)

	// The last owner is still refused, and nothing is recorded.
	require.ErrorIs(t, removeErr(ctx, f.ms, f.projectID, f.tenantID, f.other), service.ErrLastOwner)
	removedOwner, err := f.ms.IsRemoved(ctx, f.projectID, f.tenantID, f.other)
	require.NoError(t, err)
	require.False(t, removedOwner)

	removedBlank, err := f.ms.IsRemoved(ctx, "", f.tenantID, f.user)
	require.NoError(t, err)
	require.False(t, removedBlank)
}

// TestMembershipStore_JoinByDomainNeedsAnOpenDoor: the join writes only
// while the domain is verified on the tenant and lets people join, and the
// tenant is claimed (a verified domain stops being one only by being
// removed, which an unknown id stands for). It reactivates an ended domain
// membership and leaves a membership held another way as it is.
func TestMembershipStore_JoinByDomainNeedsAnOpenDoor(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping join-by-domain store test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	refused := func(why string) {
		t.Helper()
		m, changed, err := f.join(ctx)
		require.NoError(t, err, why)
		require.Nil(t, m, why)
		require.False(t, changed, why)
		require.Nil(t, f.held(ctx, t), why)
	}

	_, _, err := f.domains.SetDomainAllowJoin(ctx, f.projectID, f.domainID, false)
	require.NoError(t, err)
	refused("joining is off")
	_, _, err = f.domains.SetDomainAllowJoin(ctx, f.projectID, f.domainID, true)
	require.NoError(t, err)

	moved, err := f.tenants.SetTenantStatus(ctx, f.projectID, f.tenantID, service.TenantStatusClaimed, service.TenantStatusSuspended)
	require.NoError(t, err)
	require.True(t, moved)
	refused("the tenant is suspended")
	moved, err = f.tenants.SetTenantStatus(ctx, f.projectID, f.tenantID, service.TenantStatusSuspended, service.TenantStatusClaimed)
	require.NoError(t, err)
	require.True(t, moved)

	otherTenant, err := f.tenants.CreateTenant(ctx, &service.Tenant{ProjectID: f.projectID, Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	m, _, err := f.ms.JoinByDomain(ctx, f.projectID, otherTenant, f.user, f.domainID)
	require.NoError(t, err)
	require.Nil(t, m, "the domain is another tenant's")
	m, _, err = f.ms.JoinByDomain(ctx, f.projectID, f.tenantID, f.user, "dom-unknown")
	require.NoError(t, err)
	require.Nil(t, m, "an unknown domain")
	_, _, err = f.ms.JoinByDomain(ctx, f.projectID, f.tenantID, f.user, "")
	require.ErrorIs(t, err, service.ErrInvalidArgument)

	pending, err := f.domains.CreateDomain(ctx, &service.Domain{
		ProjectID: f.projectID, TenantID: f.tenantID, Domain: "pending.example",
		VerificationMethod: service.DomainVerificationDNSTXT, Status: service.DomainStatusPending,
	})
	require.NoError(t, err)
	_, _, err = f.domains.SetDomainAllowJoin(ctx, f.projectID, pending, true)
	require.NoError(t, err)
	m, _, err = f.ms.JoinByDomain(ctx, f.projectID, f.tenantID, f.user, pending)
	require.NoError(t, err)
	require.Nil(t, m, "a domain the tenant has not verified")

	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
		Source: service.MembershipSourceDomain, Role: service.RoleMember, Status: service.MembershipStatusInactive,
	})
	require.NoError(t, err)
	joined, changed, err := f.join(ctx)
	require.NoError(t, err)
	require.True(t, changed, "an ended domain membership is made active again")
	require.Equal(t, service.MembershipStatusActive, joined.Status)

	held, changed, err := f.ms.JoinByDomain(ctx, f.projectID, f.tenantID, f.other, f.domainID)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, service.RoleOwner, held.Role, "a membership held another way is left as it is")
	require.Equal(t, service.MembershipSourceCreated, held.Source)
}

// TestMembershipStore_RemovalRacingAJoin: a removal racing a join by domain
// leaves the person outside the tenant with the removal standing, whichever
// goes first. A join that waited on the membership the removal deleted must
// not insert it again: the membership lock orders the two.
func TestMembershipStore_RemovalRacingAJoin(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping removal race test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)

	const rounds = 20
	for round := range rounds {
		// Each round starts from a domain member with no removal.
		_, _, err := f.ms.GrantMembership(ctx, &service.TenantMembership{
			ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
			Source: service.MembershipSourceInvited, Role: service.RoleMember,
		})
		require.NoError(t, err)
		require.NoError(t, removeErr(ctx, f.ms, f.projectID, f.tenantID, f.user))
		_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: f.projectID, TenantID: f.tenantID, UserID: f.user,
			Source: service.MembershipSourceAdded, Role: service.RoleMember,
		})
		require.NoError(t, err)
		require.False(t, f.removed(ctx, t))

		var wg sync.WaitGroup
		var joinErr, removeErrOut error
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _, _, joinErr = f.join(ctx) }()
		go func() {
			defer wg.Done()
			<-start
			removeErrOut = removeErr(ctx, f.ms, f.projectID, f.tenantID, f.user)
		}()
		close(start)
		wg.Wait()

		require.NoError(t, removeErrOut, "round %d", round)
		if joinErr != nil {
			require.ErrorIs(t, joinErr, service.ErrRemovedFromTenant, "round %d", round)
		}
		require.Nil(t, f.held(ctx, t), "round %d: the person is not a member", round)
		require.True(t, f.removed(ctx, t), "round %d: the removal stands", round)
	}
}

// TestTenantMemberRemovalsMigrationRoundTrip: 0051 adds the removal table
// and its user index, and its down migration drops them; 50 → 51 → 50 → 51.
func TestTenantMemberRemovalsMigrationRoundTrip(t *testing.T) {
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

	exists := func(relation string) bool {
		t.Helper()
		var name string
		err := raw.QueryRow(ctx, `SELECT coalesce(to_regclass($1)::text, '')`, relation).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return false
		}
		require.NoError(t, err)
		return name != ""
	}

	for _, version := range []uint{50, 51, 50, 51} {
		migrateToVersion(t, scratch, version)
		require.Equal(t, version == 51, exists("tenant_member_removals"), "version %d", version)
		require.Equal(t, version == 51, exists("tenant_member_removals_user_idx"), "version %d", version)
	}
}
