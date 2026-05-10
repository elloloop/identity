//go:build dockerpostgres

// Build-tag–gated container test for the Postgres repository.
//
// We gate this behind `dockerpostgres` so the default `go test ./...`
// invocation (which runs in CI on a host without Docker, and in fast
// developer feedback loops) does not attempt to spin up a container.
//
// Run locally with:
//
//	go test -tags=dockerpostgres -timeout=300s ./internal/repo/postgres/...
//
// CI's `realpostgres` job runs the equivalent flow against a docker
// compose-managed Postgres; see tests/integration/repo_realpostgres_test.go.

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

// TestPostgres_Container runs the smoke test against a freshly-spawned
// postgres:16.13-alpine3.23 container. testcontainers handles container
// lifecycle and port mapping; the test is fully hermetic.
func TestPostgres_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

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
	t.Cleanup(func() {
		_ = pg.Terminate(context.Background())
	})

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	runRepositorySmoke(t, dsn, "tc-tenant")
}
