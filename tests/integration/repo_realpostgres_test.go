//go:build realpostgres

// Real-Postgres seed test. Drives the postgres repository against a
// live Postgres server (started by docker compose locally or by the
// GitHub Actions service container in CI).
//
// Gated behind the `realpostgres` build tag so it doesn't run during
// the default unit test job.
//
// If GATEWAY_POSTGRES_DSN is unset the test skips so a developer
// running `go test -tags=realpostgres` without compose up does not
// see a confusing connection error.

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
)

func TestRealPostgres_RepositorySmoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN unset — skipping realpostgres smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := postgres.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   "realpg-project",
	}
	repo, err := postgres.New(ctx, cfg)
	require.NoError(t, err)

	// Seed the projects(id) row the project_id FK (migration 0015) needs
	// before any data-plane write under this project binding.
	_, err = postgres.NewProjectStore(repo).EnsureDefaultProject(
		ctx, "realpg-project", "realpg-scope", "realpg",
	)
	require.NoError(t, err)

	// Round-trip a user to prove the wire and migrations both work
	// against a real Postgres process.
	now := time.Now()
	id, err := repo.CreateUser(ctx, &service.User{
		Email:     "rp-" + time.Now().Format("150405.000000") + "@example.com",
		Name:      "RealPostgres",
		Role:      "member",
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NotEmpty(t, id)

	got, err := repo.GetUser(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
}
