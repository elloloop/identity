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

// TestControlPlaneAdminStore_Smoke exercises the service.ControlPlaneProjectStore
// adapter (project_admin.go) against a live Postgres pointed to by
// GATEWAY_TEST_POSTGRES_DSN: it provisions a project, mints a credential, and
// ensures an auth domain through the SERVICE-typed API the admin RPCs use, then
// asserts the rows round-trip and the public_id / hostname resolve to the
// project. Skips without a backend; the dockerpostgres variant runs the same
// body in a throwaway container.
func TestControlPlaneAdminStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping control-plane admin store smoke test")
	}
	runControlPlaneAdminSmoke(t, dsn)
}

func runControlPlaneAdminSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	// CreateProject through the service-typed adapter writes the id back.
	proj := &service.AdminProject{StorageScopeID: "scope-admin", Name: "Admin Co"}
	projID, err := store.CreateProject(ctx, proj)
	require.NoError(t, err)
	require.NotEmpty(t, projID)
	require.Equal(t, projID, proj.ID, "CreateProject writes the assigned id back")

	got, err := store.GetProjectByID(ctx, projID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "scope-admin", got.StorageScopeID)
	require.Equal(t, "Admin Co", got.Name)

	// CreateProjectCredential through the adapter stores only the secret hash;
	// the public_id resolves the project via the resolver.
	cred := &service.AdminProjectCredential{
		ProjectID:  projID,
		Kind:       service.CredentialKindSecret,
		PublicID:   "sk_admin_smoke",
		SecretHash: "deadbeef-hash",
	}
	credID, err := store.CreateProjectCredential(ctx, cred)
	require.NoError(t, err)
	require.NotEmpty(t, credID)
	require.Equal(t, credID, cred.ID)

	storedCred, err := store.GetProjectCredentialByPublicID(ctx, "sk_admin_smoke")
	require.NoError(t, err)
	require.NotNil(t, storedCred)
	require.Equal(t, projID, storedCred.ProjectID)
	require.Equal(t, "deadbeef-hash", storedCred.SecretHash)

	resolvedByKey, err := store.ResolveByCredential(ctx, "sk_admin_smoke")
	require.NoError(t, err)
	require.NotNil(t, resolvedByKey)
	require.Equal(t, projID, resolvedByKey.ID)

	// EnsureAuthDomain through the adapter (same method the admin service
	// calls) makes the host resolve to the project.
	verifiedAt := time.Now().UnixMilli()
	require.NoError(t, store.EnsureAuthDomain(ctx, projID, "admin.acme.test", true, verifiedAt))

	resolvedByHost, err := store.ResolveByHostname(ctx, "ADMIN.ACME.TEST")
	require.NoError(t, err)
	require.NotNil(t, resolvedByHost)
	require.Equal(t, projID, resolvedByHost.ID)
	require.Equal(t, "admin.acme.test", resolvedByHost.PrimaryAuthDomain)

	// Error paths propagate through the service-typed adapter: a duplicate
	// storage scope and a duplicate credential public_id both conflict.
	_, err = store.CreateProject(ctx, &service.AdminProject{StorageScopeID: "scope-admin", Name: "Dup"})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "duplicate storage_scope_id must conflict")

	_, err = store.CreateProjectCredential(ctx, &service.AdminProjectCredential{
		ProjectID: projID,
		Kind:      service.CredentialKindSecret,
		PublicID:  "sk_admin_smoke",
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists, "duplicate public_id must conflict")
}

// TestCustomAuthDomainStore_Smoke exercises the customer custom-domain store
// methods (the service.ControlPlaneProjectStore CreateAuthDomain / GetAuthDomain
// / ListAuthDomains / SetAuthDomainVerified the AddProjectAuthDomain /
// VerifyProjectAuthDomain RPCs use) against a live Postgres. Skips without a
// backend; the dockerpostgres variant runs the same body in a container.
func TestCustomAuthDomainStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping custom auth-domain store smoke test")
	}
	runCustomAuthDomainSmoke(t, dsn)
}

func runCustomAuthDomainSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	proj := &service.AdminProject{StorageScopeID: "scope-custom", Name: "Custom Co"}
	projID, err := store.CreateProject(ctx, proj)
	require.NoError(t, err)

	// Register an UNVERIFIED custom domain.
	require.NoError(t, store.CreateAuthDomain(ctx, projID, "auth.custom.test", true))

	got, err := store.GetAuthDomain(ctx, projID, "AUTH.CUSTOM.TEST")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "auth.custom.test", got.Hostname)
	require.True(t, got.IsPrimary)
	require.Zero(t, got.VerifiedAtMs, "a customer domain starts unverified")

	// An unverified domain does NOT resolve.
	miss, err := store.ResolveByHostname(ctx, "auth.custom.test")
	require.NoError(t, err)
	require.Nil(t, miss, "an unverified custom domain must not resolve")

	// Re-creating the same hostname conflicts (global hostname uniqueness).
	require.ErrorIs(t, store.CreateAuthDomain(ctx, projID, "AUTH.custom.TEST", false), service.ErrAlreadyExists)

	// A hostname owned by a different project conflicts too.
	other, err := store.CreateProject(ctx, &service.AdminProject{StorageScopeID: "scope-custom-2", Name: "Other"})
	require.NoError(t, err)
	require.ErrorIs(t, store.CreateAuthDomain(ctx, other, "auth.custom.test", false), service.ErrAlreadyExists)

	// Verifying a hostname the project does not own is ErrNotFound.
	require.ErrorIs(t, store.SetAuthDomainVerified(ctx, projID, "never.added.test", 5), service.ErrNotFound)
	// verified_at_ms must be positive.
	require.ErrorIs(t, store.SetAuthDomainVerified(ctx, projID, "auth.custom.test", 0), service.ErrInvalidArgument)

	// Verify the domain → it now resolves.
	require.NoError(t, store.SetAuthDomainVerified(ctx, projID, "auth.custom.test", 9999))
	got, err = store.GetAuthDomain(ctx, projID, "auth.custom.test")
	require.NoError(t, err)
	require.Equal(t, int64(9999), got.VerifiedAtMs)

	resolved, err := store.ResolveByHostname(ctx, "AUTH.CUSTOM.TEST")
	require.NoError(t, err)
	require.NotNil(t, resolved, "a verified custom domain resolves")
	require.Equal(t, projID, resolved.ID)

	// Listing returns the domain; primary-first ordering.
	require.NoError(t, store.CreateAuthDomain(ctx, projID, "second.custom.test", false))
	list, err := store.ListAuthDomains(ctx, projID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.True(t, list[0].IsPrimary, "primary domain lists first")

	// GetAuthDomain misses on an unknown project/host.
	none, err := store.GetAuthDomain(ctx, projID, "nope.test")
	require.NoError(t, err)
	require.Nil(t, none)
	none, err = store.GetAuthDomain(ctx, "no-such-project", "auth.custom.test")
	require.NoError(t, err)
	require.Nil(t, none, "GetAuthDomain is scoped to the owning project")
}

// TestSetPrimaryAuthDomainStore_Smoke exercises the atomic demote+promote
// SetPrimaryAuthDomain path against a live Postgres. Skips without a backend;
// the dockerpostgres variant runs the same body in a container.
func TestSetPrimaryAuthDomainStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping set-primary auth-domain store smoke test")
	}
	runSetPrimaryAuthDomainSmoke(t, dsn)
}

func runSetPrimaryAuthDomainSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newProjectStore(ctx, t, dsn)

	proj := &service.AdminProject{StorageScopeID: "scope-primary", Name: "Primary Co"}
	projID, err := store.CreateProject(ctx, proj)
	require.NoError(t, err)

	// Seed a verified primary, then add a second domain non-primary and verify.
	require.NoError(t, store.EnsureAuthDomain(ctx, projID, "old.primary.test", true, 1000))
	require.NoError(t, store.CreateAuthDomain(ctx, projID, "new.primary.test", false))

	// Promoting an UNVERIFIED domain is rejected (and leaves the primary intact).
	_, err = store.SetPrimaryProjectAuthDomain(ctx, projID, "new.primary.test")
	require.ErrorIs(t, err, service.ErrAuthDomainNotVerified)
	old, err := store.GetAuthDomain(ctx, projID, "old.primary.test")
	require.NoError(t, err)
	require.True(t, old.IsPrimary, "a rejected promotion must not demote the existing primary")

	// Promoting a hostname the project does not own is ErrNotFound.
	_, err = store.SetPrimaryProjectAuthDomain(ctx, projID, "never.added.test")
	require.ErrorIs(t, err, service.ErrNotFound)

	// Verify the new domain, then promote it: atomic demote+promote.
	require.NoError(t, store.SetAuthDomainVerified(ctx, projID, "new.primary.test", 2000))
	promoted, err := store.SetPrimaryProjectAuthDomain(ctx, projID, "new.primary.test")
	require.NoError(t, err)
	require.True(t, promoted.IsPrimary)
	require.Equal(t, "new.primary.test", promoted.Hostname)

	old, err = store.GetAuthDomain(ctx, projID, "old.primary.test")
	require.NoError(t, err)
	require.False(t, old.IsPrimary, "the old primary must be demoted")

	// The resolver's primary now reflects the newly-promoted host.
	resolved, err := store.ResolveByHostname(ctx, "new.primary.test")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, "new.primary.test", resolved.PrimaryAuthDomain)

	// Re-promoting the already-primary host is a no-op that succeeds.
	again, err := store.SetPrimaryProjectAuthDomain(ctx, projID, "new.primary.test")
	require.NoError(t, err)
	require.True(t, again.IsPrimary)

	// Concurrent promotions never violate the partial-unique primary index:
	// they serialize on the project's row locks and converge on one primary.
	require.NoError(t, store.CreateAuthDomain(ctx, projID, "c1.primary.test", false))
	require.NoError(t, store.SetAuthDomainVerified(ctx, projID, "c1.primary.test", 3000))
	require.NoError(t, store.CreateAuthDomain(ctx, projID, "c2.primary.test", false))
	require.NoError(t, store.SetAuthDomainVerified(ctx, projID, "c2.primary.test", 3001))

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, host := range []string{"c1.primary.test", "c2.primary.test"} {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			_, errs[i] = store.SetPrimaryProjectAuthDomain(ctx, projID, host)
		}(i, host)
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	list, err := store.ListAuthDomains(ctx, projID)
	require.NoError(t, err)
	primaries := 0
	for _, d := range list {
		if d.IsPrimary {
			primaries++
		}
	}
	require.Equal(t, 1, primaries, "exactly one primary survives concurrent promotions")
}
