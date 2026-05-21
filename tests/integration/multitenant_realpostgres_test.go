//go:build realpostgres

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/repo"
	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
)

// newMultiTenantBackend wires the cross-tenant test against a live
// Postgres. Returns nil (and skips) when GATEWAY_POSTGRES_DSN is unset.
//
// The per-tenant Repository factory re-scopes the system repo's shared
// connection pool via WithTenant, so the per-request resolution path
// does not open a fresh pool per call.
func newMultiTenantBackend(t *testing.T) *multiTenantBackend {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set — skipping real-postgres multi-tenant test")
		return nil
	}

	systemTenant := fmt.Sprintf("mt-system-%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	systemPgRepo, err := pgrepo.New(ctx, pgrepo.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    systemTenant,
	})
	if err != nil {
		t.Fatalf("pgrepo.New(system): %v", err)
	}
	t.Cleanup(systemPgRepo.Close)

	return &multiTenantBackend{
		defaultTenant: systemTenant,
		systemRepo:    systemPgRepo,
		systemDB:      systemPgRepo,
		tenantAdmin:   repo.NewPostgresTenantAdmin(),
		repoForTenant: func(tenantID string) service.Repository {
			return systemPgRepo.WithTenant(tenantID)
		},
		mailer: pgSilentMailer{},
	}
}
