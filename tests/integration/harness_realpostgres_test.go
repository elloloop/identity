//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo"
)

func StartServer(t *testing.T, opts ...HarnessOption) *Harness {
	t.Helper()

	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set")
	}

	cfg := newTestConfig()
	uniq := fmt.Sprintf("it-realpostgres-%d", time.Now().UnixNano())
	cfg.DefaultTenantID = uniq
	// The data-plane binds to the project (ADR-0002); use a unique project
	// per run so concurrent runs on the shared CI database stay isolated.
	cfg.DefaultProjectID = uniq
	hOpts := applyHarnessOptions(cfg, opts)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    5,
		PostgresAutoMigrate: true,
		ProjectID:           cfg.DefaultProjectID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}
	// Seed the projects(id) row the project_id FK (migration 0015) needs.
	if _, err := built.ProjectStore.EnsureDefaultProject(
		context.Background(), cfg.DefaultProjectID, cfg.DefaultTenantID, "integration",
	); err != nil {
		t.Fatalf("seed default project: %v", err)
	}

	mailer := NewRecordingMailer()
	return startHarness(t, cfg, built.Repository, built.DB, nil, mailer, hOpts.oauthRegistry, hOpts.idvProvider)
}
