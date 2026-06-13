//go:build dockerpostgres

// Build-tag–gated container test for the control-plane ProjectStore.
//
// Gated behind `dockerpostgres` (like repo_dockertest_test.go) so the
// default `go test ./...` does not require Docker. The shared assertion
// body lives in project_store_test.go (untagged) so CI's coverage job —
// which runs the untagged TestProjectStore_Smoke against a live
// GATEWAY_TEST_POSTGRES_DSN — exercises project_store.go too. Run locally
// with:
//
//	go test -tags=dockerpostgres -run Container -timeout=600s ./internal/repo/postgres/...

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startPostgresContainer spins up a fresh postgres:16.13-alpine3.23 and
// returns its sslmode=disable DSN. The container is terminated on test
// cleanup. Shared by the control-plane container tests.
func startPostgresContainer(ctx context.Context, t *testing.T) string {
	t.Helper()
	pg, err := tcpg.Run(
		ctx,
		"postgres:16.13-alpine3.23",
		tcpg.WithDatabase("identity"),
		tcpg.WithUsername("identity"),
		tcpg.WithPassword("identity"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	// Terminate on a fresh context: the test ctx may already be cancelled
	// or timed-out by the time cleanup runs.
	t.Cleanup(func() { //nolint:contextcheck // cleanup must not reuse the test ctx.
		_ = pg.Terminate(context.Background())
	})
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn
}

// TestProjectStore_Container runs the shared control-plane store body
// (project_store_test.go) against a throwaway Postgres container, so the
// store is exercised end-to-end locally without a pre-provisioned database.
func TestProjectStore_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)
	runProjectStoreSmoke(t, dsn)
}

// TestProjectStore_EnsureDefaultProject_Container runs the default-project
// bootstrap body against a throwaway Postgres container.
func TestProjectStore_EnsureDefaultProject_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)
	runEnsureDefaultProjectSmoke(t, dsn)
}

// TestProjectResolver_Container runs the project-resolution body against a
// throwaway Postgres container.
func TestProjectResolver_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)
	runProjectResolverSmoke(t, dsn)
}

// TestTenantDomainStore_Container runs the tenant + domain store body
// against a throwaway Postgres container.
func TestTenantDomainStore_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)
	runTenantDomainSmoke(t, dsn)
}

// TestLoginPolicyStore_Container runs the login-policy store body against a
// throwaway Postgres container.
func TestLoginPolicyStore_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)
	runLoginPolicySmoke(t, dsn)
}
