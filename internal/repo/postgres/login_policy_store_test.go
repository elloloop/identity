package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// newLoginPolicyFixture migrates a Postgres at dsn, seeds a project + a
// tenant (the login_policies FK targets), and returns the policy store plus
// the seeded project/tenant ids. The owning repository is closed on cleanup.
func newLoginPolicyFixture(ctx context.Context, t *testing.T, dsn string) (store *LoginPolicyStore, projectID, tenantID string) {
	t.Helper()
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)

	projectID, err = NewProjectStore(repo).createProject(ctx, &Project{StorageScopeID: "scope-lp", Name: "LP"})
	require.NoError(t, err)

	// Seed the tenant the login_policies FK targets via the tenant store.
	tenantID, err = NewTenantStore(repo).CreateTenant(ctx, &service.Tenant{
		ProjectID: projectID, Status: service.TenantStatusClaimed,
	})
	require.NoError(t, err)

	return NewLoginPolicyStore(repo), projectID, tenantID
}

// TestLoginPolicyStore_Smoke runs the login-policy upsert/get round-trip
// against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN (CI's
// coverage job), skipping when unset. The dockerpostgres container test
// runs the same body locally.
func TestLoginPolicyStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping login-policy store smoke test")
	}
	runLoginPolicySmoke(t, dsn)
}

// runLoginPolicySmoke asserts the one-policy-per-tenant upsert semantics:
// first call inserts, second call (same tenant) updates in place keeping
// the row id and created_at_ms, and a missing policy reads as (nil, nil).
func runLoginPolicySmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store, projectID, tenantID := newLoginPolicyFixture(ctx, t, dsn)

	// Miss before any policy is set.
	none, err := store.GetLoginPolicy(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Nil(t, none)

	// Insert.
	id1, err := store.UpsertLoginPolicy(ctx, &service.LoginPolicy{
		ProjectID:      projectID,
		TenantID:       tenantID,
		AllowedMethods: service.LoginMethodSSO,
		SSORequired:    true,
		Require2FA:     true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, id1)

	got, err := store.GetLoginPolicy(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, id1, got.ID)
	require.Equal(t, service.LoginMethodSSO, got.AllowedMethods)
	require.True(t, got.SSORequired)
	require.True(t, got.Require2FA)
	require.JSONEq(t, `{}`, got.SSOConnectionJSON, "empty sso connection defaults to {}")
	require.NotZero(t, got.CreatedAtMs)
	createdAt := got.CreatedAtMs

	// Upsert the same tenant → update in place, same id + created_at_ms.
	id2, err := store.UpsertLoginPolicy(ctx, &service.LoginPolicy{
		ProjectID:         projectID,
		TenantID:          tenantID,
		AllowedMethods:    service.LoginMethodEmailOTP + "," + service.LoginMethodPassword,
		SSORequired:       false,
		SSOConnectionJSON: `{"idp":"okta"}`,
		Require2FA:        false,
	})
	require.NoError(t, err)
	require.Equal(t, id1, id2, "upsert on the same (project, tenant) keeps the row id")

	got, err = store.GetLoginPolicy(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Equal(t, service.LoginMethodEmailOTP+","+service.LoginMethodPassword, got.AllowedMethods)
	require.False(t, got.SSORequired)
	require.JSONEq(t, `{"idp":"okta"}`, got.SSOConnectionJSON)
	require.Equal(t, createdAt, got.CreatedAtMs, "created_at_ms is preserved across upsert")
	require.GreaterOrEqual(t, got.UpdatedAtMs, createdAt)

	// Validation + miss.
	_, err = store.UpsertLoginPolicy(ctx, &service.LoginPolicy{ProjectID: projectID})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	missing, err := store.GetLoginPolicy(ctx, projectID, "no-such-tenant")
	require.NoError(t, err)
	require.Nil(t, missing)
}
