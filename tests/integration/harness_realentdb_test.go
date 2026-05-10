//go:build integration && realentdb

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/repo"
)

func StartServer(t *testing.T, opts ...HarnessOption) *Harness {
	t.Helper()

	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS not set")
	}

	cfg := newTestConfig()
	cfg.DefaultTenantID = fmt.Sprintf("it-realentdb-%d", time.Now().UnixNano())
	hOpts := applyHarnessOptions(cfg, opts)

	client, err := entdb.NewClient(addr)
	if err != nil {
		t.Fatalf("entdb.NewClient: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("entdb connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:      repo.DriverEntDB,
		EntDBClient: client,
		TenantID:    cfg.DefaultTenantID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}

	mailer := NewRecordingMailer()
	return startHarness(t, cfg, built.Repository, built.DB, nil, mailer, hOpts.oauthRegistry, hOpts.idvProvider)
}
