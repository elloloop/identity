package identityserver

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo"
)

// TestEnsureDefaultProject_NoControlPlane covers the postgres-only guard:
// when the built repository has no control plane (entdb/memory →
// ProjectStore nil), the bootstrap is a no-op and never errors. No
// database is required.
func TestEnsureDefaultProject_NoControlPlane(t *testing.T) {
	t.Parallel()

	err := ensureDefaultProject(
		context.Background(),
		&repo.Built{}, // ProjectStore nil, as for memory/entdb
		&Config{DefaultProjectID: "default", DefaultTenantID: "local"},
		zap.NewNop(),
	)
	if err != nil {
		t.Fatalf("ensureDefaultProject with nil ProjectStore: want nil, got %v", err)
	}
}

// TestEnsureDefaultProject_SeedsPostgres drives the real boot-time
// bootstrap against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN
// (CI's coverage job sets it; the test skips when unset). It asserts the
// default project is seeded mapped onto the DefaultTenantID storage scope,
// that re-running is idempotent, and that a blank DefaultProjectID is a
// no-op even when a control plane is present.
func TestEnsureDefaultProject_SeedsPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres default-project bootstrap test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	built, err := repo.Build(ctx, repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		TenantID:            "bootstrap-scope",
		PostgresAutoMigrate: true,
	}, nil)
	if err != nil {
		t.Fatalf("repo.Build postgres: %v", err)
	}

	const projectID, scope = "bootstrap-test-project", "bootstrap-scope"
	cfg := &Config{DefaultProjectID: projectID, DefaultTenantID: scope}

	if err := ensureDefaultProject(ctx, built, cfg, zap.NewNop()); err != nil {
		t.Fatalf("ensureDefaultProject (seed): %v", err)
	}

	got, err := built.ProjectStore.GetProjectByID(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectByID after seed: %v", err)
	}
	if got == nil {
		t.Fatal("default project not seeded")
	}
	if got.StorageScopeID != scope {
		t.Errorf("default project storage scope = %q, want %q (maps onto DefaultTenantID)", got.StorageScopeID, scope)
	}

	// Idempotent: a second boot does not error or duplicate.
	if err := ensureDefaultProject(ctx, built, cfg, zap.NewNop()); err != nil {
		t.Fatalf("ensureDefaultProject (idempotent re-run): %v", err)
	}

	// A blank DefaultProjectID is a no-op even with a live control plane.
	cfg.DefaultProjectID = ""
	if err := ensureDefaultProject(ctx, built, cfg, zap.NewNop()); err != nil {
		t.Fatalf("ensureDefaultProject (blank id): want no-op nil, got %v", err)
	}
}

// TestEnsureProjectAuthDomains_SeedsBrandedHosts drives the branded-domain
// boot seed against a live Postgres: the first configured host becomes the
// project's verified primary, additional hosts are seeded too, and every
// host then resolves to the default project via the Host→project resolver.
func TestEnsureProjectAuthDomains_SeedsBrandedHosts(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping auth-domain seed test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	built, err := repo.Build(ctx, repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		TenantID:            "authdom-scope",
		PostgresAutoMigrate: true,
	}, nil)
	if err != nil {
		t.Fatalf("repo.Build postgres: %v", err)
	}

	const projectID = "authdom-test-project"
	cfg := &Config{
		DefaultProjectID:          projectID,
		DefaultTenantID:           "authdom-scope",
		DefaultProjectAuthDomains: "auth.brandseed.test, login.brandseed.test",
	}
	if err := ensureDefaultProject(ctx, built, cfg, zap.NewNop()); err != nil {
		t.Fatalf("ensureDefaultProject: %v", err)
	}

	// No domains configured → no-op.
	bare := &Config{DefaultProjectID: projectID, DefaultTenantID: "authdom-scope"}
	if err := ensureProjectAuthDomains(ctx, built, bare, zap.NewNop()); err != nil {
		t.Fatalf("ensureProjectAuthDomains (no domains): %v", err)
	}

	// Seed the branded hosts.
	if err := ensureProjectAuthDomains(ctx, built, cfg, zap.NewNop()); err != nil {
		t.Fatalf("ensureProjectAuthDomains (seed): %v", err)
	}

	for _, host := range []string{"auth.brandseed.test", "login.brandseed.test"} {
		p, err := built.ProjectStore.GetProjectByAuthHostname(ctx, host)
		if err != nil {
			t.Fatalf("resolve %s: %v", host, err)
		}
		if p == nil || p.ID != projectID {
			t.Fatalf("host %s resolved to %v, want project %q", host, p, projectID)
		}
	}

	// The first host is the verified primary.
	domains, err := built.ProjectStore.ListProjectAuthDomains(ctx, projectID)
	if err != nil {
		t.Fatalf("ListProjectAuthDomains: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(domains))
	}
	if !domains[0].IsPrimary || domains[0].Hostname != "auth.brandseed.test" {
		t.Errorf("primary = %+v, want auth.brandseed.test primary", domains[0])
	}
	if domains[0].VerifiedAtMs == 0 {
		t.Error("deployer-owned domain must be seeded verified")
	}

	// Idempotent re-seed.
	if err := ensureProjectAuthDomains(ctx, built, cfg, zap.NewNop()); err != nil {
		t.Fatalf("ensureProjectAuthDomains (idempotent): %v", err)
	}
	domains, _ = built.ProjectStore.ListProjectAuthDomains(ctx, projectID)
	if len(domains) != 2 {
		t.Fatalf("re-seed duplicated domains: got %d, want 2", len(domains))
	}
}
