package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// selfServiceFixture is a migrated Postgres with two projects and two users
// (the membership FK targets), plus the tenant and membership stores.
type selfServiceFixture struct {
	tenants      *TenantStore
	members      *MembershipStore
	projA, projB string
	user1, user2 string
}

func newSelfServiceFixture(ctx context.Context, t *testing.T, dsn string) *selfServiceFixture {
	t.Helper()
	require.NoError(t, truncateAll(ctx, dsn))
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    10,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	seedProject(ctx, t, repo, "control-plane")

	projects := NewProjectStore(repo, true, nil)
	f := &selfServiceFixture{tenants: NewTenantStore(repo), members: NewMembershipStore(repo)}
	f.projA, err = projects.createProject(ctx, &Project{StorageScopeID: "scope-ss-a", Name: "A"})
	require.NoError(t, err)
	f.projB, err = projects.createProject(ctx, &Project{StorageScopeID: "scope-ss-b", Name: "B"})
	require.NoError(t, err)

	now := time.Now()
	f.user1, err = repo.CreateUser(ctx, &service.User{Email: "owner1@example.com", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	f.user2, err = repo.CreateUser(ctx, &service.User{Email: "owner2@example.com", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	return f
}

func (f *selfServiceFixture) owned(projectID, ownerID, name string, max int) service.OwnedTenantRequest {
	return service.OwnedTenantRequest{ProjectID: projectID, Name: name, OwnerID: ownerID, MaxPerWindow: max}
}

// TestSelfServiceTenants_Postgres runs the self-service tenant store
// behaviour against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN,
// skipping when unset.
func TestSelfServiceTenants_Postgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping self-service tenant store test")
	}
	runSelfServiceTenants(t, dsn)
}

// runSelfServiceTenants asserts owned-tenant creation (one transaction, the
// per-owner limit and window, serialised concurrent creations) and the
// active-tenant reads behind ListMyTenants and tenant selection.
func runSelfServiceTenants(t *testing.T, dsn string) {
	t.Helper()
	t.Run("CreateOwnedTenant", func(t *testing.T) { runCreateOwnedTenant(t, dsn) })
	t.Run("CreateOwnedTenantConcurrent", func(t *testing.T) { runCreateOwnedTenantConcurrent(t, dsn) })
	t.Run("ActiveTenantsForUser", func(t *testing.T) { runActiveTenantsForUser(t, dsn) })
}

func runCreateOwnedTenant(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newSelfServiceFixture(ctx, t, dsn)

	tenant, membership, err := f.tenants.CreateOwnedTenant(ctx, f.owned(f.projA, f.user1, "Acme", 2))
	require.NoError(t, err)
	assert.Equal(t, service.TenantStatusClaimed, tenant.Status)
	assert.Equal(t, f.user1, tenant.CreatedBy)
	assert.Equal(t, service.RoleOwner, membership.Role)
	assert.Equal(t, service.MembershipSourceCreated, membership.Source)
	assert.Equal(t, service.MembershipStatusActive, membership.Status)

	// Both rows are durable and created_by round-trips.
	got, err := f.tenants.GetTenant(ctx, f.projA, tenant.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Acme", got.Name)
	assert.Equal(t, f.user1, got.CreatedBy)
	assert.Equal(t, service.TenantStatusClaimed, got.Status)
	m, err := f.members.GetMembership(ctx, f.projA, tenant.ID, f.user1)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, service.RoleOwner, m.Role)
	assert.Equal(t, service.MembershipSourceCreated, m.Source)

	// An operator-created tenant has no creator.
	plainID, err := f.tenants.CreateTenant(ctx, &service.Tenant{ProjectID: f.projA, Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	plain, err := f.tenants.GetTenant(ctx, f.projA, plainID)
	require.NoError(t, err)
	assert.Empty(t, plain.CreatedBy)

	// The limit counts the owner's tenants in the project.
	_, _, err = f.tenants.CreateOwnedTenant(ctx, f.owned(f.projA, f.user1, "Acme Two", 2))
	require.NoError(t, err)
	_, _, err = f.tenants.CreateOwnedTenant(ctx, f.owned(f.projA, f.user1, "Acme Three", 2))
	assert.ErrorIs(t, err, service.ErrTenantCreationLimited)

	// Another owner and another project each have their own count.
	_, _, err = f.tenants.CreateOwnedTenant(ctx, f.owned(f.projA, f.user2, "Beta", 2))
	require.NoError(t, err)
	_, _, err = f.tenants.CreateOwnedTenant(ctx, f.owned(f.projB, f.user1, "Gamma", 2))
	require.NoError(t, err)

	// Tenants created before the window do not count.
	req := f.owned(f.projA, f.user1, "Acme Later", 2)
	req.WindowStartMs = time.Now().Add(time.Hour).UnixMilli()
	_, _, err = f.tenants.CreateOwnedTenant(ctx, req)
	require.NoError(t, err)

	// A refused creation wrote nothing.
	all, err := f.tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: f.projA, Limit: 100})
	require.NoError(t, err)
	var mine int
	for _, tn := range all {
		if tn.CreatedBy == f.user1 {
			mine++
		}
	}
	assert.Equal(t, 3, mine)

	for name, bad := range map[string]service.OwnedTenantRequest{
		"no project":   f.owned("", f.user1, "X", 1),
		"no owner":     f.owned(f.projA, "", "X", 1),
		"no limit":     f.owned(f.projA, f.user1, "X", 0),
		"unknown user": f.owned(f.projA, "user-missing", "X", 5),
	} {
		_, _, err := f.tenants.CreateOwnedTenant(ctx, bad)
		assert.Error(t, err, name)
		if name != "unknown user" {
			assert.ErrorIs(t, err, service.ErrInvalidArgument, name)
		}
	}
	// The unknown owner's tenant was rolled back with its membership.
	after, err := f.tenants.ListTenants(ctx, service.TenantListQuery{ProjectID: f.projA, Limit: 100})
	require.NoError(t, err)
	assert.Len(t, after, len(all))
}

// Concurrent creations by one owner are serialised: with a limit of one,
// exactly one succeeds.
func runCreateOwnedTenantConcurrent(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newSelfServiceFixture(ctx, t, dsn)

	const n = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		ok      int
		limited int
		other   []error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := f.tenants.CreateOwnedTenant(ctx, f.owned(f.projA, f.user1, "Race", 1))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, service.ErrTenantCreationLimited):
				limited++
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(t, other)
	assert.Equal(t, 1, ok)
	assert.Equal(t, n-1, limited)
}

func runActiveTenantsForUser(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newSelfServiceFixture(ctx, t, dsn)

	tenant := func(projectID, name, status string) string {
		id, err := f.tenants.CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Name: name, Status: status})
		require.NoError(t, err)
		return id
	}
	member := func(projectID, tenantID, userID, role, status string) {
		_, err := f.members.UpsertMembership(ctx, &service.TenantMembership{
			ProjectID: projectID, TenantID: tenantID, UserID: userID,
			Source: service.MembershipSourceAdded, Role: role, Status: status,
		})
		require.NoError(t, err)
	}

	zeta := tenant(f.projA, "Zeta", service.TenantStatusClaimed)
	alpha := tenant(f.projA, "Alpha", service.TenantStatusClaimed)
	suspended := tenant(f.projA, "Suspended", service.TenantStatusSuspended)
	latent := tenant(f.projA, "Latent", service.TenantStatusLatent)
	inactive := tenant(f.projA, "Inactive member", service.TenantStatusClaimed)
	elsewhere := tenant(f.projB, "Elsewhere", service.TenantStatusClaimed)

	member(f.projA, zeta, f.user1, service.RoleMember, service.MembershipStatusActive)
	member(f.projA, alpha, f.user1, service.RoleAdmin, service.MembershipStatusActive)
	member(f.projA, suspended, f.user1, service.RoleOwner, service.MembershipStatusActive)
	member(f.projA, latent, f.user1, service.RoleOwner, service.MembershipStatusActive)
	member(f.projA, inactive, f.user1, service.RoleMember, service.MembershipStatusInactive)
	member(f.projB, elsewhere, f.user1, service.RoleMember, service.MembershipStatusActive)
	member(f.projA, alpha, f.user2, service.RoleMember, service.MembershipStatusActive)

	got, err := f.members.ListActiveTenantsForUser(ctx, f.projA, f.user1, "")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, service.UserTenant{TenantID: alpha, Name: "Alpha", Role: service.RoleAdmin, Source: service.MembershipSourceAdded}, *got[0])
	assert.Equal(t, service.UserTenant{TenantID: zeta, Name: "Zeta", Role: service.RoleMember, Source: service.MembershipSourceAdded}, *got[1])

	other, err := f.members.ListActiveTenantsForUser(ctx, f.projB, f.user1, "")
	require.NoError(t, err)
	require.Len(t, other, 1)
	assert.Equal(t, elsewhere, other[0].TenantID)

	none, err := f.members.ListActiveTenantsForUser(ctx, f.projB, f.user2, "")
	require.NoError(t, err)
	assert.Empty(t, none)

	one, err := f.members.GetActiveTenantForUser(ctx, f.projA, alpha, f.user1, "")
	require.NoError(t, err)
	require.NotNil(t, one)
	assert.Equal(t, service.RoleAdmin, one.Role)
	assert.Equal(t, service.MembershipSourceAdded, one.Source)

	for name, tc := range map[string]struct{ project, tenant, user string }{
		"suspended tenant":         {f.projA, suspended, f.user1},
		"latent tenant":            {f.projA, latent, f.user1},
		"inactive membership":      {f.projA, inactive, f.user1},
		"another project's tenant": {f.projA, elsewhere, f.user1},
		"not a member":             {f.projA, zeta, f.user2},
		"unknown tenant":           {f.projA, "tenant-missing", f.user1},
	} {
		got, err := f.members.GetActiveTenantForUser(ctx, tc.project, tc.tenant, tc.user, "")
		require.NoError(t, err, name)
		assert.Nil(t, got, name)
	}

	// Suspending a tenant removes it from the list.
	suspendTenant(ctx, t, f.tenants, f.projA, zeta)
	got, err = f.members.ListActiveTenantsForUser(ctx, f.projA, f.user1, "")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, alpha, got[0].TenantID)
}
