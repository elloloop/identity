package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// newProjectStore migrates a Postgres at dsn and returns a control-plane
// ProjectStore backed by it. The owning *pgRepository is closed on cleanup,
// releasing the shared pool. Shared by the env-driven smoke test and the
// testcontainers-driven container test (see project_store_dockertest_test.go).
func newProjectStore(ctx context.Context, t *testing.T, dsn string) *ProjectStore {
	t.Helper()
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		// The control plane is platform-global; TenantID only satisfies
		// the data-plane *pgRepository's config validation and is unused
		// by the ProjectStore.
		ProjectID: "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	return NewProjectStore(repo)
}

// TestProjectStore_Smoke runs the control-plane store round-trip against a
// live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN. CI's coverage job
// sets that env var (so this is where project_store.go earns its coverage);
// it skips when unset so the default unit-test job passes without a backend.
// The testcontainers-driven TestProjectStore_Container (dockerpostgres tag)
// runs the same body locally without a pre-provisioned database.
func TestProjectStore_EnsureAuthDomain_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping EnsureAuthDomain smoke test")
	}
	runEnsureAuthDomainSmoke(t, dsn)
}

// runEnsureAuthDomainSmoke asserts the idempotent, boot-time auth-domain
// seed: first call creates a verified primary domain; re-seeding is a no-op;
// the host resolves to its project; and seeding the same host for a
// different project is rejected.
func runEnsureAuthDomainSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	projA, err := store.createProject(ctx, &Project{StorageScopeID: "scope-ead-a", Name: "A"})
	require.NoError(t, err)
	projB, err := store.createProject(ctx, &Project{StorageScopeID: "scope-ead-b", Name: "B"})
	require.NoError(t, err)

	// Seed a verified primary auth-domain.
	require.NoError(t, store.EnsureAuthDomain(ctx, projA, "auth.appa.test", true, 12345))
	resolved, err := store.GetProjectByAuthHostname(ctx, "auth.appa.test")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, projA, resolved.ID)

	// Idempotent: re-seeding the same host for the same project is a no-op.
	require.NoError(t, store.EnsureAuthDomain(ctx, projA, "AUTH.APPA.TEST", true, 99999))
	domains, err := store.ListProjectAuthDomains(ctx, projA)
	require.NoError(t, err)
	require.Len(t, domains, 1, "re-seeding must not duplicate the domain")
	require.True(t, domains[0].IsPrimary)
	require.Equal(t, int64(12345), domains[0].VerifiedAtMs, "re-seed does not overwrite the first seed")

	// A second, non-primary host for the same project.
	require.NoError(t, store.EnsureAuthDomain(ctx, projA, "login.appa.test", false, 12345))
	domains, err = store.ListProjectAuthDomains(ctx, projA)
	require.NoError(t, err)
	require.Len(t, domains, 2)

	// Seeding the same host for a DIFFERENT project is rejected.
	err = store.EnsureAuthDomain(ctx, projB, "auth.appa.test", true, 12345)
	require.Error(t, err, "a host owned by another project must not be re-seeded")

	// Argument validation.
	require.ErrorIs(t, store.EnsureAuthDomain(ctx, "", "h.test", false, 0), service.ErrInvalidArgument)
	require.ErrorIs(t, store.EnsureAuthDomain(ctx, projA, "", false, 0), service.ErrInvalidArgument)
}

func TestProjectStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping ProjectStore smoke test")
	}
	runProjectStoreSmoke(t, dsn)
}

// TestProjectStore_EnsureDefaultProject_Smoke runs the default-project
// bootstrap against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN
// (CI's coverage job), skipping when unset. The dockerpostgres container test
// runs the same body locally.
func TestProjectStore_EnsureDefaultProject_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping EnsureDefaultProject smoke test")
	}
	runEnsureDefaultProjectSmoke(t, dsn)
}

// runEnsureDefaultProjectSmoke asserts EnsureDefaultProject is idempotent,
// resolves an occupied storage scope to the existing project (even under a
// different id), and validates its arguments.
func runEnsureDefaultProjectSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	// First call creates the default project mapped onto the storage scope.
	p1, err := store.EnsureDefaultProject(ctx, "default", "local", "Default Project")
	require.NoError(t, err)
	require.NotNil(t, p1)
	require.Equal(t, "default", p1.ID)
	require.Equal(t, "local", p1.StorageScopeID)
	require.Equal(t, projectStatusActive, p1.Status)

	// Idempotent: a second identical call returns the same row, not a duplicate.
	p2, err := store.EnsureDefaultProject(ctx, "default", "local", "Default Project")
	require.NoError(t, err)
	require.Equal(t, p1.ID, p2.ID)

	// A different id but the same storage scope resolves the existing project
	// (storage_scope_id is globally unique) rather than failing or duplicating.
	p3, err := store.EnsureDefaultProject(ctx, "other-id", "local", "Other")
	require.NoError(t, err)
	require.Equal(t, p1.ID, p3.ID)

	// Idempotent again after the existing project is found by id (not scope).
	p4, err := store.EnsureDefaultProject(ctx, "default", "other-scope", "Default Project")
	require.NoError(t, err)
	require.Equal(t, p1.ID, p4.ID)
	require.Equal(t, "local", p4.StorageScopeID, "the id lookup wins; the scope arg does not rebind")

	// Validation guards.
	_, err = store.EnsureDefaultProject(ctx, "", "local", "")
	require.ErrorIs(t, err, service.ErrInvalidArgument, "empty project id")
	_, err = store.EnsureDefaultProject(ctx, "default", "", "")
	require.ErrorIs(t, err, service.ErrInvalidArgument, "empty storage scope")

	// A dead context surfaces the lookup error rather than swallowing it.
	dead, cancelDead := context.WithCancel(ctx)
	cancelDead()
	_, err = store.EnsureDefaultProject(dead, "default", "local", "")
	require.Error(t, err, "a cancelled context must surface the lookup error")

	// Concurrent boot: many instances calling at once on a clean scope must
	// converge on a single row — exactly one wins the insert, the rest resolve
	// the ErrAlreadyExists race by re-reading. None errors; all agree.
	require.NoError(t, truncateAll(ctx, dsn))
	const racers = 8
	var wg sync.WaitGroup
	got := make([]*Project, racers)
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = store.EnsureDefaultProject(ctx, "default", "race-scope", "Default Project")
		}(i)
	}
	wg.Wait()
	for i := range racers {
		require.NoError(t, errs[i], "racer %d", i)
		require.NotNil(t, got[i], "racer %d", i)
		require.Equal(t, "default", got[i].ID, "racer %d resolved a different project", i)
	}
	// Exactly one project row exists for the contended scope.
	winner, err := store.GetProjectByStorageScope(ctx, "race-scope")
	require.NoError(t, err)
	require.NotNil(t, winner)
	require.Equal(t, "default", winner.ID)
}

// TestProjectResolver_Smoke runs the service.ProjectResolver round-trip
// against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN (CI's
// coverage job), skipping when unset. The dockerpostgres container test
// runs the same body locally.
func TestProjectResolver_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping ProjectResolver smoke test")
	}
	runProjectResolverSmoke(t, dsn)
}

// runProjectResolverSmoke asserts credential- and hostname-based project
// resolution, including the miss cases the middleware relies on: unknown
// key/host, revoked credential, and suspended project all resolve to
// (nil, nil) rather than an error.
func runProjectResolverSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	// Active project with an active credential, a serving hostname, and a
	// per-project CORS allow-list in its config_json.
	projID, err := store.createProject(ctx, &Project{
		StorageScopeID: "scope-live", Name: "Live",
		ConfigJSON: `{"cors":{"allowed_origins":["https://app.live.test","http://localhost:5173"]}}`,
	})
	require.NoError(t, err)
	credID, err := store.createProjectCredential(ctx, &ProjectCredential{
		ProjectID: projID, Kind: "publishable", PublicID: "pk_live",
	})
	require.NoError(t, err)
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: projID, Hostname: "auth.live.test", IsPrimary: true, VerifiedAtMs: 1,
	})
	require.NoError(t, err)

	// ── credential resolution ───────────────────────────────────────
	got, err := store.ResolveByCredential(ctx, "pk_live")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, projID, got.ID)
	require.Equal(t, "scope-live", got.StorageScopeID)
	require.Equal(t, "auth.live.test", got.PrimaryAuthDomain, "resolver loads the primary auth-domain for branded links")
	require.Equal(t,
		[]string{"https://app.live.test", "http://localhost:5173"},
		got.CORSAllowedOrigins,
		"resolver parses+validates the per-project CORS allow-list from config_json",
	)

	// Unknown / blank key → clean miss.
	miss, err := store.ResolveByCredential(ctx, "pk_unknown")
	require.NoError(t, err)
	require.Nil(t, miss)
	miss, err = store.ResolveByCredential(ctx, "")
	require.NoError(t, err)
	require.Nil(t, miss)

	// Revoked credential → miss (a revoked key must not resolve).
	require.NoError(t, store.RevokeProjectCredential(ctx, credID, 0))
	miss, err = store.ResolveByCredential(ctx, "pk_live")
	require.NoError(t, err)
	require.Nil(t, miss, "a revoked credential must not resolve a project")

	// ── hostname resolution (case-insensitive) ──────────────────────
	got, err = store.ResolveByHostname(ctx, "AUTH.LIVE.TEST")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, projID, got.ID)

	// An UNVERIFIED custom domain (verified_at_ms = 0) must NOT resolve, even
	// though the row exists and is owned by the active project.
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: projID, Hostname: "pending.live.test",
	})
	require.NoError(t, err)
	miss, err = store.ResolveByHostname(ctx, "pending.live.test")
	require.NoError(t, err)
	require.Nil(t, miss, "an unverified custom domain must not resolve")
	noProj, err := store.GetProjectByAuthHostname(ctx, "pending.live.test")
	require.NoError(t, err)
	require.Nil(t, noProj, "GetProjectByAuthHostname must filter on verified")

	// Verifying the pending domain flips it to resolving.
	require.NoError(t, store.SetProjectAuthDomainVerified(ctx, projID, "PENDING.LIVE.TEST", 4242))
	got, err = store.ResolveByHostname(ctx, "pending.live.test")
	require.NoError(t, err)
	require.NotNil(t, got, "a verified custom domain resolves")
	require.Equal(t, projID, got.ID)

	// Unknown / blank host → clean miss.
	miss, err = store.ResolveByHostname(ctx, "nope.test")
	require.NoError(t, err)
	require.Nil(t, miss)
	miss, err = store.ResolveByHostname(ctx, "")
	require.NoError(t, err)
	require.Nil(t, miss)

	// ── suspended project → miss on both paths ──────────────────────
	suspID, err := store.createProject(ctx, &Project{
		StorageScopeID: "scope-susp", Name: "Suspended", Status: "suspended",
	})
	require.NoError(t, err)
	_, err = store.createProjectCredential(ctx, &ProjectCredential{
		ProjectID: suspID, Kind: "publishable", PublicID: "pk_susp",
	})
	require.NoError(t, err)
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: suspID, Hostname: "auth.susp.test", IsPrimary: true, VerifiedAtMs: 1,
	})
	require.NoError(t, err)

	miss, err = store.ResolveByCredential(ctx, "pk_susp")
	require.NoError(t, err)
	require.Nil(t, miss, "a suspended project must not resolve by credential")
	miss, err = store.ResolveByHostname(ctx, "auth.susp.test")
	require.NoError(t, err)
	require.Nil(t, miss, "a suspended project must not resolve by hostname")
}

// runProjectStoreSmoke is the shared driver-specific body: it wipes the
// control-plane tables, builds the store, and asserts every round-trip plus
// every control-plane uniqueness rule from migration 0013. truncateAll runs
// migrations first, so a bare (un-migrated) DSN is fine.
func runProjectStoreSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	// ── project round-trip ──────────────────────────────────────────
	projID, err := store.createProject(ctx, &Project{
		StorageScopeID: "scope-a",
		Name:           "Acme",
		ConfigJSON:     `{"login_methods":["email_otp"]}`,
	})
	require.NoError(t, err)
	require.NotEmpty(t, projID)

	byID, err := store.GetProjectByID(ctx, projID)
	require.NoError(t, err)
	require.NotNil(t, byID)
	require.Equal(t, projID, byID.ID)
	require.Equal(t, "scope-a", byID.StorageScopeID)
	require.Equal(t, "Acme", byID.Name)
	require.Equal(t, "active", byID.Status, "status defaults to active")
	require.JSONEq(t, `{"login_methods":["email_otp"]}`, byID.ConfigJSON)
	require.NotZero(t, byID.CreatedAtMs)
	require.Equal(t, byID.CreatedAtMs, byID.UpdatedAtMs)

	byScope, err := store.GetProjectByStorageScope(ctx, "scope-a")
	require.NoError(t, err)
	require.NotNil(t, byScope)
	require.Equal(t, projID, byScope.ID)

	// Misses resolve to (nil, nil), never an error.
	miss, err := store.GetProjectByID(ctx, "no-such-project")
	require.NoError(t, err)
	require.Nil(t, miss)
	miss, err = store.GetProjectByStorageScope(ctx, "no-such-scope")
	require.NoError(t, err)
	require.Nil(t, miss)

	// Default config_json is "{}" when omitted.
	bareID, err := store.createProject(ctx, &Project{StorageScopeID: "scope-bare"})
	require.NoError(t, err)
	bare, err := store.GetProjectByID(ctx, bareID)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, bare.ConfigJSON)

	// ── credential round-trip ───────────────────────────────────────
	credID, err := store.createProjectCredential(ctx, &ProjectCredential{
		ProjectID: projID,
		Kind:      "publishable",
		PublicID:  "pk_live_abc",
	})
	require.NoError(t, err)
	require.NotEmpty(t, credID)

	cred, err := store.GetProjectCredentialByPublicID(ctx, "pk_live_abc")
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.Equal(t, credID, cred.ID)
	require.Equal(t, projID, cred.ProjectID)
	require.Equal(t, "publishable", cred.Kind)
	require.Equal(t, "active", cred.Status, "status defaults to active")
	require.Zero(t, cred.RevokedAtMs)

	credMiss, err := store.GetProjectCredentialByPublicID(ctx, "pk_nope")
	require.NoError(t, err)
	require.Nil(t, credMiss)

	// Revoke flips status + stamps revoked_at_ms, and is idempotent.
	require.NoError(t, store.RevokeProjectCredential(ctx, credID, 0))
	cred, err = store.GetProjectCredentialByPublicID(ctx, "pk_live_abc")
	require.NoError(t, err)
	require.Equal(t, "revoked", cred.Status)
	require.NotZero(t, cred.RevokedAtMs)
	firstRevoked := cred.RevokedAtMs
	require.NoError(t, store.RevokeProjectCredential(ctx, credID, 0),
		"re-revoking is a no-op, not an error")
	cred, err = store.GetProjectCredentialByPublicID(ctx, "pk_live_abc")
	require.NoError(t, err)
	require.Equal(t, firstRevoked, cred.RevokedAtMs, "second revoke does not move the timestamp")
	// Revoking an unknown credential is a no-op.
	require.NoError(t, store.RevokeProjectCredential(ctx, "no-such-cred", 0))

	// ── auth-domain round-trip ──────────────────────────────────────
	// Seeded verified (verified_at_ms > 0) so it resolves; the verified
	// filter is exercised separately in runProjectResolverSmoke.
	primaryID, err := store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID:    projID,
		Hostname:     "auth.acme.test",
		IsPrimary:    true,
		VerifiedAtMs: 1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, primaryID)

	secondaryID, err := store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID:    projID,
		Hostname:     "login.acme.test",
		VerifiedAtMs: 1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, secondaryID)

	// Case-insensitive Host → project resolution (verified domains only).
	resolved, err := store.GetProjectByAuthHostname(ctx, "AUTH.ACME.TEST")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, projID, resolved.ID)

	hostMiss, err := store.GetProjectByAuthHostname(ctx, "unknown.test")
	require.NoError(t, err)
	require.Nil(t, hostMiss)

	// Listing is primary-first.
	domains, err := store.ListProjectAuthDomains(ctx, projID)
	require.NoError(t, err)
	require.Len(t, domains, 2)
	require.Equal(t, primaryID, domains[0].ID)
	require.True(t, domains[0].IsPrimary)
	require.Equal(t, secondaryID, domains[1].ID)
	require.False(t, domains[1].IsPrimary)

	// Unknown project lists empty.
	none, err := store.ListProjectAuthDomains(ctx, "no-such-project")
	require.NoError(t, err)
	require.Empty(t, none)

	// ── uniqueness rules (migration 0013) ───────────────────────────

	// Duplicate storage_scope_id → ErrAlreadyExists (projects_storage_scope_uidx).
	_, err = store.createProject(ctx, &Project{StorageScopeID: "scope-a", Name: "Dup"})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "duplicate storage_scope_id must conflict")

	// Duplicate credential public_id → ErrAlreadyExists
	// (project_credentials_public_id_uidx), even across projects.
	_, err = store.createProjectCredential(ctx, &ProjectCredential{
		ProjectID: bareID,
		Kind:      "secret",
		PublicID:  "pk_live_abc",
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "duplicate public_id must conflict")

	// Duplicate hostname (case-insensitive) → ErrAlreadyExists
	// (project_auth_domains_hostname_uidx).
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: bareID,
		Hostname:  "AUTH.acme.TEST",
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "duplicate hostname must conflict")

	// Second is_primary for the same project → ErrAlreadyExists
	// (project_auth_domains_primary_uidx, partial unique WHERE is_primary).
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: projID,
		Hostname:  "second-primary.acme.test",
		IsPrimary: true,
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "a second primary auth-domain must conflict")

	// A primary IS allowed for a DIFFERENT project (the partial unique is
	// per-project, not global).
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: bareID,
		Hostname:  "auth.bare.test",
		IsPrimary: true,
	})
	require.NoError(t, err, "a primary auth-domain is allowed once per project")

	// ── argument validation (no container round-trip needed, but kept
	// here so the store's guards are covered alongside the live path) ──
	_, err = store.createProject(ctx, &Project{})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = store.createProjectCredential(ctx, &ProjectCredential{ProjectID: projID, Kind: "secret"})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = store.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{ProjectID: projID})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	require.Error(t, store.RevokeProjectCredential(ctx, "", 0),
		"revoke with a blank credential id is an argument error")
}
