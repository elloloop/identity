//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/elloloop/identity/internal/repo"
)

// Postgres testcontainer fixture constants, pinned to match the rest of the
// repo's container tests (tests/browsere2e, the CI postgres service).
const (
	postgresImage  = "postgres:16.13-alpine3.23"
	postgresDB     = "identity"
	postgresUser   = "identity"
	postgresPasswd = "identity"
)

// TestMain boots a single shared postgres testcontainer for the postgres
// backend, migrates its schema once up front, runs the suite, then tears it
// down. For the memory backend it is a no-op so the smoke run needs no Docker.
//
// A container-per-test would not scale: the suite has 55+ top-level tests, most
// t.Parallel(), so dozens of postgres instances would start at once and exhaust
// the runner. Instead one container is shared and each test owns an isolated
// project partition (unique DefaultProjectID via WithProject), which is how the
// postgres driver scopes data-plane storage.
func TestMain(m *testing.M) {
	if e2eBackend() != backendPostgres {
		os.Exit(m.Run())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := tcpg.Run(
		ctx,
		postgresImage,
		tcpg.WithDatabase(postgresDB),
		tcpg.WithUsername(postgresUser),
		tcpg.WithPassword(postgresPasswd),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: start postgres container: %v\n", err)
		os.Exit(1)
	}
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pg.Terminate(context.Background())
		fmt.Fprintf(os.Stderr, "e2e: postgres connection string: %v\n", err)
		os.Exit(1)
	}
	sharedPostgresDSN = dsn

	// Migrate the schema once, up front, against the shared container so the
	// parallel per-test builders connect to an already-migrated DB and never
	// race the DDL.
	migrator, err := repo.Build(ctx, repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    2,
		PostgresAutoMigrate: true,
		ProjectID:           "e2e-migrate",
	}, zap.NewNop())
	if err != nil {
		_ = pg.Terminate(context.Background())
		fmt.Fprintf(os.Stderr, "e2e: postgres auto-migrate: %v\n", err)
		os.Exit(1)
	}
	if closer, ok := migrator.Repository.(interface{ Close() }); ok {
		closer.Close()
	}

	code := m.Run()
	_ = pg.Terminate(context.Background())
	os.Exit(code)
}
