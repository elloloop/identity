//go:build realentdb

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/repo"
	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	"github.com/elloloop/identity/internal/repo/entdb/entclient"
	"github.com/elloloop/identity/internal/service"
)

// newMultiTenantBackend wires the cross-tenant test against a live
// EntDB. Returns nil (and skips) when GATEWAY_ENTDB_ADDRESS is unset.
func newMultiTenantBackend(t *testing.T) *multiTenantBackend {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS not set — skipping real-entdb multi-tenant test")
		return nil
	}

	client, err := entclient.New(addr)
	if err != nil {
		t.Fatalf("entdb.NewClient: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("entdb connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	systemTenant := fmt.Sprintf("mt-system-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, client, systemTenant)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:      repo.DriverEntDB,
		EntDBClient: client,
		TenantID:    systemTenant,
	}, nil)
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}

	tenantAdmin, err := repo.NewTenantAdmin(client)
	if err != nil {
		t.Fatalf("repo.NewTenantAdmin: %v", err)
	}

	return &multiTenantBackend{
		defaultTenant: systemTenant,
		systemRepo:    built.Repository,
		systemDB:      built.DB,
		tenantAdmin:   tenantAdmin,
		repoForTenant: func(tenantID string) service.Repository {
			return entdbrepo.NewRepository(client, tenantID)
		},
		mailer: &silentMailer{},
	}
}
