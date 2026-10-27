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

	projectID, err = NewProjectStore(repo, true, nil).createProject(ctx, &Project{StorageScopeID: "scope-af", Name: "AF"})
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
	runAutoFormIgnoresUnprovenClaims(t, dsn)
	runAutoFormKeepsProvenance(t, dsn)
	runAutoFormSkipsASuspendedLatentTenant(t, dsn)
	runAutoFormSkipsASuspendedVerifiedTenant(t, dsn)
	runAutoFormSkipsARemovedMember(t, dsn)
}

// runAutoFormSkipsARemovedMember: auto-formation does not bring back a
// person removed from the domain's tenant, as a join by domain would not,
// and still adds everyone else on the domain.
func runAutoFormSkipsARemovedMember(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	af, _, _, ms, projectID, newUser := newAutoFormFixture(ctx, t, dsn)

	removed, kept := newUser(t), newUser(t)
	tenantID, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", removed)
	require.NoError(t, err)
	require.NoError(t, removeErr(ctx, ms, projectID, tenantID, removed))

	again, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", removed)
	require.NoError(t, err)
	require.Equal(t, tenantID, again)
	m, err := ms.GetMembership(ctx, projectID, tenantID, removed)
	require.NoError(t, err)
	require.Nil(t, m, "a removed person is not added back")

	_, err = af.EnsureTenantForDomain(ctx, projectID, "acme.com", kept)
	require.NoError(t, err)
	m, err = ms.GetMembership(ctx, projectID, tenantID, kept)
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, service.MembershipSourceDomain, m.Source)
}

// runAutoFormKeepsProvenance: signing in on a tenant's domain never relabels
// a membership the user created or was invited to as the domain's.
func runAutoFormKeepsProvenance(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	af, ts, ds, ms, projectID, newUser := newAutoFormFixture(ctx, t, dsn)

	creator := newUser(t)
	tenant, _, err := ts.CreateOwnedTenant(ctx, service.OwnedTenantRequest{
		ProjectID: projectID, OwnerID: creator, Name: "Acme", MaxPerWindow: 10,
	})
	require.NoError(t, err)
	domainID, err := ds.CreateDomain(ctx, &service.Domain{ProjectID: projectID, TenantID: tenant.ID, Domain: "acme.com"})
	require.NoError(t, err)
	require.NoError(t, ds.SetDomainStatus(ctx, projectID, domainID, service.DomainStatusVerified, 0))
	invitee := newUser(t)
	_, err = ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenant.ID, UserID: invitee,
		Source: service.MembershipSourceInvited, Role: service.RoleMember, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)

	for userID, source := range map[string]string{creator: service.MembershipSourceCreated, invitee: service.MembershipSourceInvited} {
		joined, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", userID)
		require.NoError(t, err)
		require.Equal(t, tenant.ID, joined)
		mem, err := ms.GetMembership(ctx, projectID, tenant.ID, userID)
		require.NoError(t, err)
		require.Equal(t, source, mem.Source, "the domain never relabels a membership with a stronger source")
	}
}

// runAutoFormSkipsASuspendedLatentTenant: a suspended auto-formed tenant takes
// no more signups; the domain's next one forms a new latent tenant.
func runAutoFormSkipsASuspendedLatentTenant(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	af, ts, _, ms, projectID, newUser := newAutoFormFixture(ctx, t, dsn)

	suspended, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", newUser(t))
	require.NoError(t, err)
	suspendTenant(ctx, t, ts, projectID, suspended)

	next := newUser(t)
	formed, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", next)
	require.NoError(t, err)
	require.NotEqual(t, suspended, formed)
	ten, err := ts.GetTenant(ctx, projectID, formed)
	require.NoError(t, err)
	require.Equal(t, service.TenantStatusLatent, ten.Status)
	mem, err := ms.GetMembership(ctx, projectID, suspended, next)
	require.NoError(t, err)
	require.Nil(t, mem, "nobody joins a suspended tenant through its domain")
}

// runAutoFormSkipsASuspendedVerifiedTenant: a suspended tenant takes no more
// signups through the domain it verified; the domain's next one forms a new
// latent tenant, and once the tenant is reinstated signups join it again.
func runAutoFormSkipsASuspendedVerifiedTenant(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	af, ts, ds, ms, projectID, newUser := newAutoFormFixture(ctx, t, dsn)

	tenant, _, err := ts.CreateOwnedTenant(ctx, service.OwnedTenantRequest{
		ProjectID: projectID, OwnerID: newUser(t), Name: "Acme", MaxPerWindow: 10,
	})
	require.NoError(t, err)
	domainID, err := ds.CreateDomain(ctx, &service.Domain{ProjectID: projectID, TenantID: tenant.ID, Domain: "acme.com"})
	require.NoError(t, err)
	require.NoError(t, ds.SetDomainStatus(ctx, projectID, domainID, service.DomainStatusVerified, 0))
	joined, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", newUser(t))
	require.NoError(t, err)
	require.Equal(t, tenant.ID, joined, "a claimed tenant takes its verified domain's signups")

	suspendTenant(ctx, t, ts, projectID, tenant.ID)
	next := newUser(t)
	formed, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", next)
	require.NoError(t, err)
	require.NotEqual(t, tenant.ID, formed)
	ten, err := ts.GetTenant(ctx, projectID, formed)
	require.NoError(t, err)
	require.Equal(t, service.TenantStatusLatent, ten.Status)
	mem, err := ms.GetMembership(ctx, projectID, tenant.ID, next)
	require.NoError(t, err)
	require.Nil(t, mem, "nobody joins a suspended tenant through the domain it verified")

	_, err = ts.pool.Exec(ctx, `UPDATE tenants SET status = 'claimed' WHERE project_id = $1 AND id = $2`, projectID, tenant.ID)
	require.NoError(t, err)
	rejoined, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", newUser(t))
	require.NoError(t, err)
	require.Equal(t, tenant.ID, rejoined, "a reinstated tenant takes its domain's signups again")
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

	doms, err := ds.ListDomainsByTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Len(t, doms, 1)
	dom := doms[0]
	require.Equal(t, "acme.com", dom.Domain)
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

	tenants, err := ts.ListTenants(ctx, service.TenantListQuery{ProjectID: projectID, Limit: 100})
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
			results[i], errs[i] = af.EnsureTenantForDomain(ctx, projectID, "race.example.test", users[i])
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

	// Exactly one tenant and one domain exist for race.example.test (no orphans from
	// rolled-back losers), and every racer is a member.
	raceDoms, err := ds.ListDomainsByTenant(ctx, projectID, winner)
	require.NoError(t, err)
	require.Len(t, raceDoms, 1, "one domain row for race.example.test")
	require.Equal(t, "race.example.test", raceDoms[0].Domain)
	raceMembers, err := ms.ListMembershipsForTenant(ctx, projectID, winner)
	require.NoError(t, err)
	require.Len(t, raceMembers, racers, "every concurrent signer is a member of the one tenant")

	// Two tenants total now (acme.com + race.example.test) — losers left no orphan.
	tenants, err = ts.ListTenants(ctx, service.TenantListQuery{ProjectID: projectID, Limit: 100})
	require.NoError(t, err)
	require.Len(t, tenants, 2, "a lost race must not leave an orphan tenant")
}

// runAutoFormIgnoresUnprovenClaims asserts that registering a domain one
// has not proven captures none of its signups: a self-service tenant's
// pending dns_txt or email claim is passed over for the domain's own latent
// tenant, and once a tenant verifies the domain, its later signups join
// that tenant.
func runAutoFormIgnoresUnprovenClaims(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	af, ts, ds, ms, projectID, newUser := newAutoFormFixture(ctx, t, dsn)

	owned := func(owner, name string) string {
		t.Helper()
		tenant, _, err := ts.CreateOwnedTenant(ctx, service.OwnedTenantRequest{
			ProjectID: projectID, OwnerID: owner, Name: name, MaxPerWindow: 10,
		})
		require.NoError(t, err)
		return tenant.ID
	}
	// One self-service tenant claims the domain by DNS, another by email;
	// neither has proven it.
	squatter := owned(newUser(t), "Squatter")
	_, err := ds.CreateDomain(ctx, &service.Domain{ProjectID: projectID, TenantID: squatter, Domain: "acme.com"})
	require.NoError(t, err)
	_, err = ds.CreateDomain(ctx, &service.Domain{
		ProjectID: projectID, TenantID: squatter, Domain: "acme.com", VerificationMethod: service.DomainVerificationEmail,
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "a tenant holds a domain once, whatever the method")
	emailSquatter := owned(newUser(t), "Email squatter")
	_, err = ds.CreateDomain(ctx, &service.Domain{
		ProjectID: projectID, TenantID: emailSquatter, Domain: "acme.com", VerificationMethod: service.DomainVerificationEmail,
	})
	require.NoError(t, err)

	first := newUser(t)
	latent, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", first)
	require.NoError(t, err)
	require.NotContains(t, []string{squatter, emailSquatter}, latent, "a pending claim captures no signup")
	ten, err := ts.GetTenant(ctx, projectID, latent)
	require.NoError(t, err)
	require.Equal(t, service.TenantStatusLatent, ten.Status)
	squatterMember, err := ms.GetMembership(ctx, projectID, squatter, first)
	require.NoError(t, err)
	require.Nil(t, squatterMember)

	again, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", newUser(t))
	require.NoError(t, err)
	require.Equal(t, latent, again, "later signups join the domain's one latent tenant")

	owner := owned(newUser(t), "Owner")
	ownerDomain, err := ds.CreateDomain(ctx, &service.Domain{ProjectID: projectID, TenantID: owner, Domain: "acme.com"})
	require.NoError(t, err)
	require.NoError(t, ds.SetDomainStatus(ctx, projectID, ownerDomain, service.DomainStatusVerified, 0))

	late := newUser(t)
	joined, err := af.EnsureTenantForDomain(ctx, projectID, "acme.com", late)
	require.NoError(t, err)
	require.Equal(t, owner, joined, "once verified, the domain's signups join the verifying tenant")
	mem, err := ms.GetMembership(ctx, projectID, owner, late)
	require.NoError(t, err)
	require.NotNil(t, mem)
	require.Equal(t, service.MembershipSourceDomain, mem.Source)
}
