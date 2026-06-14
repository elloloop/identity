package postgres

import (
	"context"
	"os"
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
