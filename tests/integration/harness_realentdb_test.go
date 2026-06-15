//go:build integration && realentdb

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/internal/repo/entdb/entclient"
)

func StartServer(t *testing.T, opts ...HarnessOption) *Harness {
	t.Helper()

	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS not set")
	}

	cfg := newTestConfig()
	uniq := fmt.Sprintf("it-realentdb-%d", time.Now().UnixNano())
	cfg.DefaultTenantID = uniq
	// The data-plane partitions on the project id (ADR-0002), and the entdb
	// SDK partition key must be non-empty and pre-provisioned. Pin the
	// boot-default project to the same id we provision below so the service
	// layer (requestProjectID → WithProject → SDK Tenant) operates under the
	// partition this harness actually created, not the global "default".
	cfg.DefaultProjectID = uniq
	hOpts := applyHarnessOptions(cfg, opts)

	client, err := entclient.New(addr)
	if err != nil {
		t.Fatalf("entdb.NewClient: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("entdb connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ensureRealEntDBTenant(t, client, cfg.DefaultProjectID)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:      repo.DriverEntDB,
		EntDBClient: client,
		ProjectID:   cfg.DefaultProjectID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}

	mailer := NewRecordingMailer()
	return startHarness(t, cfg, built.Repository, built.DB, nil, mailer, hOpts.oauthRegistry, hOpts.idvProvider)
}
