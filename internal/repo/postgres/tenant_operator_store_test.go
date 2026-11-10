package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestMembershipStore_AddMember: an operator's addition makes a new active
// member, keeps any active membership as it is, renews an ended one as a
// member, and refuses a suspended membership or a removal, leaving either
// in place.
func TestMembershipStore_AddMember(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping AddMember test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	ms, _, projectID, tenantID, user1, user2 := newMembershipFixture(ctx, t, dsn)
	_, tenants, _ := newTenantDomainStores(ctx, t, dsn)
	newTenant := func() string {
		t.Helper()
		id, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Status: service.TenantStatusClaimed})
		require.NoError(t, err)
		return id
	}
	seed := func(tenant, user, source, role, status string) {
		t.Helper()
		_, err := ms.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: projectID, TenantID: tenant, UserID: user, Source: source, Role: role, Status: status,
		})
		require.NoError(t, err)
	}

	added, changed, err := ms.AddMember(ctx, projectID, tenantID, user1)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, service.RoleMember, added.Role)
	require.Equal(t, service.MembershipSourceAdded, added.Source)
	require.Equal(t, service.MembershipStatusActive, added.Status)
	again, changed, err := ms.AddMember(ctx, projectID, tenantID, user1)
	require.NoError(t, err)
	require.False(t, changed, "a retry writes nothing")
	require.Equal(t, added.ID, again.ID)

	owned := newTenant()
	seed(owned, user1, service.MembershipSourceCreated, service.RoleOwner, service.MembershipStatusActive)
	seed(owned, user2, service.MembershipSourceDomain, service.RoleAdmin, service.MembershipStatusActive)
	for user, want := range map[string]struct{ role, source string }{
		user1: {service.RoleOwner, service.MembershipSourceCreated},
		user2: {service.RoleAdmin, service.MembershipSourceDomain},
	} {
		kept, changed, err := ms.AddMember(ctx, projectID, owned, user)
		require.NoError(t, err)
		require.False(t, changed)
		require.Equal(t, want.role, kept.Role, "an active membership keeps its role")
		require.Equal(t, want.source, kept.Source, "and its source")
	}

	ended := newTenant()
	seed(ended, user1, service.MembershipSourceDomain, service.RoleAdmin, service.MembershipStatusInactive)
	renewed, changed, err := ms.AddMember(ctx, projectID, ended, user1)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, service.RoleMember, renewed.Role, "an ended membership comes back as a member")
	require.Equal(t, service.MembershipSourceAdded, renewed.Source)
	require.Equal(t, service.MembershipStatusActive, renewed.Status)

	shut := newTenant()
	seed(shut, user1, service.MembershipSourceInvited, service.RoleMember, service.MembershipStatusSuspended)
	seed(shut, user2, service.MembershipSourceInvited, service.RoleMember, service.MembershipStatusActive)
	require.NoError(t, removeErr(ctx, ms, projectID, shut, user2))
	_, _, err = ms.AddMember(ctx, projectID, shut, user1)
	require.ErrorIs(t, err, service.ErrMemberSuspended)
	suspended, err := ms.GetMembership(ctx, projectID, shut, user1)
	require.NoError(t, err)
	require.Equal(t, service.MembershipStatusSuspended, suspended.Status)
	_, _, err = ms.AddMember(ctx, projectID, shut, user2)
	require.ErrorIs(t, err, service.ErrRemovedFromTenant)
	removed, err := ms.IsRemoved(ctx, projectID, shut, user2)
	require.NoError(t, err)
	require.True(t, removed, "the removal stands")
	gone, err := ms.GetMembership(ctx, projectID, shut, user2)
	require.NoError(t, err)
	require.Nil(t, gone)

	_, _, err = ms.AddMember(ctx, projectID, tenantID, "")
	require.ErrorIs(t, err, service.ErrInvalidArgument)
}

// TestTenantStore_CreatorCredentialKind: a tenant keeps what authorized its
// creation, empty by default, and the column takes no other value.
func TestTenantStore_CreatorCredentialKind(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping tenant creator kind test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	projects, tenants, _ := newTenantDomainStores(ctx, t, dsn)
	projectID, err := projects.createProject(ctx, &Project{StorageScopeID: "scope-creator", Name: "Creator"})
	require.NoError(t, err)

	for _, kind := range []string{service.CredentialKindTenantOperator, service.CreatorAdminSecret, ""} {
		id, err := tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Status: service.TenantStatusClaimed, CreatorCredentialKind: kind})
		require.NoError(t, err, kind)
		got, err := tenants.GetTenant(ctx, projectID, id)
		require.NoError(t, err, kind)
		require.Equal(t, kind, got.CreatorCredentialKind)
	}
	_, err = tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Status: service.TenantStatusClaimed, CreatorCredentialKind: "secret"})
	require.Error(t, err, "the CHECK refuses another kind")
}

// TestTenantCreatorCredentialKindMigrationRoundTrip: 0057 adds the column
// and its CHECK, and its down migration drops them.
func TestTenantCreatorCredentialKindMigrationRoundTrip(t *testing.T) {
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

	hasColumn := func() bool {
		t.Helper()
		var n int
		require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'tenants' AND column_name = 'creator_credential_kind'`).Scan(&n))
		return n == 1
	}
	for _, version := range []uint{56, 57, 56, 57} {
		migrateToVersion(t, scratch, version)
		require.Equal(t, version == 57, hasColumn(), "version %d", version)
	}
}
