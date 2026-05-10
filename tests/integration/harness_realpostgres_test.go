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
	cfg.DefaultTenantID = fmt.Sprintf("it-realpostgres-%d", time.Now().UnixNano())
	hOpts := applyHarnessOptions(cfg, opts)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    5,
		PostgresAutoMigrate: true,
		TenantID:            cfg.DefaultTenantID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}

	mailer := NewRecordingMailer()
	return startHarness(t, cfg, built.Repository, built.DB, nil, mailer, hOpts.oauthRegistry, hOpts.idvProvider)
}
