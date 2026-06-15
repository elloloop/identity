//go:build dockerpostgres

// Build-tag–gated container twin of TestPostgres_AuditScopedToRequestProject_Smoke.
//
// Run locally with:
//
//	go test -tags=dockerpostgres -run TestPostgres_AuditScopedToRequestProject_Container -timeout=300s ./internal/repo/postgres/...
//
// The hermetic container path and the env-DSN smoke path share one body
// (runAuditProjectScopeSmoke) so the assertions cannot drift apart.

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

func TestPostgres_AuditScopedToRequestProject_Container(t *testing.T) {
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

	runAuditProjectScopeSmoke(t, dsn)
}
