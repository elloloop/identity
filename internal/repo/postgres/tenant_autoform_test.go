package postgres

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// newAutoFormFixture migrates a Postgres at dsn, seeds a project, and
// returns the auto-form store plus the tenant/domain/membership stores (for
// verification) and a helper that creates a fresh user. The repository is
// closed on cleanup.
func newAutoFormFixture(ctx context.Context, t *testing.T, dsn string) (
	af *AutoFormStore, ts *TenantStore, ds *DomainStore, ms *MembershipStore,
	projectID string, newUser func(t *testing.T) string,
) {
	t.Helper()
	repo, err := New(ctx, Config{
		DSN: dsn, MaxConns: 8, ConnTimeout: 5 * time.Second,
		AutoMigrate: true, ProjectID: "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)

	// Users created below carry project_id="control-plane" (the repo binding);
	// seed that project so the project_id FK (migration 0015) is satisfied.
	seedProject(ctx, t, repo, "control-plane")

	projectID, err = NewProjectStore(repo).createProject(ctx, &Project{StorageScopeID: "scope-af", Name: "AF"})
	require.NoError(t, err)

	var n int
	newUser = func(t *testing.T) string {
		t.Helper()
		n++
		now := time.Now()
		id, err := repo.CreateUser(ctx, &service.User{
			Email: fmt.Sprintf("u%d@acme.com", n), Status: "active", CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return id
	}
	return NewAutoFormStore(repo), NewTenantStore(repo), NewDomainStore(repo), NewMembershipStore(repo), projectID, newUser
}

// TestAutoFormStore_Smoke exercises tenant auto-formation against a live
// Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN (CI's coverage job),
// skipping when unset.
func TestAutoFormStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping auto-form smoke test")
	}
	runAutoFormSmoke(t, dsn)
}

func runAutoFormSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	af, ts, ds, ms, projectID, newUser := newAutoFormFixture(ctx, t, dsn)

	user1 := newUser(t)

	// First signer forms a latent tenant + domain + derived membership.
	tenantID, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", user1)
	require.NoError(t, err)
	require.NotEmpty(t, tenantID)

	ten, err := ts.GetTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.NotNil(t, ten)
	require.Equal(t, service.TenantStatusLatent, ten.Status, "auto-formed tenant is latent until verified")
	require.Equal(t, "acme.com", ten.PrimaryDomain)

	dom, err := ds.GetDomainByName(ctx, projectID, "acme.com")
	require.NoError(t, err)
	require.NotNil(t, dom)
	require.Equal(t, tenantID, dom.TenantID)
	require.Equal(t, service.DomainStatusPending, dom.Status)
	require.Equal(t, service.DomainVerificationEmail, dom.VerificationMethod)

	mem, err := ms.GetMembership(ctx, projectID, tenantID, user1)
	require.NoError(t, err)
	require.NotNil(t, mem)
	require.Equal(t, service.MembershipSourceDomain, mem.Source)
	require.Equal(t, service.MembershipStatusActive, mem.Status)

	// A second signer on the SAME domain (different case) joins the SAME
	// tenant — no second tenant, no second domain.
	user2 := newUser(t)
	tenantID2, err := af.EnsureTenantForDomain(ctx, projectID, "ACME.COM", user2)
	require.NoError(t, err)
	require.Equal(t, tenantID, tenantID2, "same email domain → same tenant")

	tenants, err := ts.ListTenants(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, tenants, 1, "no duplicate tenant for the same domain")
	forTenant, err := ms.ListMembershipsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Len(t, forTenant, 2, "both signers are members")

	// Idempotent: re-running for an existing (domain, user) is a no-op.
	again, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", user1)
	require.NoError(t, err)
	require.Equal(t, tenantID, again)
	forTenant, err = ms.ListMembershipsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Len(t, forTenant, 2, "re-running does not duplicate a membership")

	// Validation.
	_, err = af.EnsureTenantForDomain(ctx, "", "x.com", user1)
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = af.EnsureTenantForDomain(ctx, projectID, "", user1)
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = af.EnsureTenantForDomain(ctx, projectID, "x.com", "")
	require.ErrorIs(t, err, service.ErrInvalidArgument)

	// ── concurrent race: many signers on a fresh domain converge ────
	const racers = 8
	users := make([]string, racers)
	for i := range users {
		users[i] = newUser(t)
	}
	results := make([]string, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = af.EnsureTenantForDomain(ctx, projectID, "race.com", users[i])
		}(i)
	}
	wg.Wait()

	winner := ""
	for i := range racers {
		require.NoError(t, errs[i], "racer %d", i)
		require.NotEmpty(t, results[i], "racer %d", i)
		if winner == "" {
			winner = results[i]
		}
		require.Equal(t, winner, results[i], "racer %d formed a different tenant — convergence failed", i)
	}

	// Exactly one tenant and one domain exist for race.com (no orphans from
	// rolled-back losers), and every racer is a member.
	raceDom, err := ds.GetDomainByName(ctx, projectID, "race.com")
	require.NoError(t, err)
	require.NotNil(t, raceDom)
	require.Equal(t, winner, raceDom.TenantID)
	raceMembers, err := ms.ListMembershipsForTenant(ctx, projectID, winner)
	require.NoError(t, err)
	require.Len(t, raceMembers, racers, "every concurrent signer is a member of the one tenant")

	// Two tenants total now (acme.com + race.com) — losers left no orphan.
	tenants, err = ts.ListTenants(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, tenants, 2, "a lost race must not leave an orphan tenant")
}
