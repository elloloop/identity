package repo

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestBuild_PostgresProjectStore asserts the postgres driver returns a
// non-nil, functional control-plane ProjectStore (the field later slices
// and the boot-time default-project bootstrap depend on), against a live
// Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN. CI's coverage job sets
// that env var; the test skips when unset so the default unit-test job
// passes without a backend.
func TestBuild_PostgresProjectStore(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres ProjectStore wiring test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	built, err := Build(ctx, Config{
		Driver:              DriverPostgres,
		PostgresDSN:         dsn,
		TenantID:            "repo-build-scope",
		PostgresAutoMigrate: true,
	}, nil)
	if err != nil {
		t.Fatalf("Build postgres: %v", err)
	}
	if built.ProjectStore == nil {
		t.Fatal("Build postgres: ProjectStore is nil, want non-nil control-plane store")
	}

	// The login-governance plane is postgres-only too: Build wires the
	// tenant/domain/policy read stores and the bundle accessor returns a
	// non-nil LoginGovernance the auth service enforces against.
	if built.TenantStore == nil || built.DomainStore == nil || built.LoginPolicyStore == nil {
		t.Fatalf("Build postgres: governance stores nil (tenant=%v domain=%v policy=%v)",
			built.TenantStore, built.DomainStore, built.LoginPolicyStore)
	}
	if built.LoginGovernance() == nil {
		t.Fatal("Build postgres: LoginGovernance() is nil, want non-nil governance bundle")
	}
	// The control-plane admin write-store accessor is non-nil for postgres —
	// it backs the AdminCreateProject family.
	if built.ControlPlaneStore() == nil {
		t.Fatal("Build postgres: ControlPlaneStore() is nil, want non-nil admin store")
	}

	// The store shares the repository's pool and is functional: a project
	// seeded through it round-trips. Distinct id/scope keep this test from
	// colliding with the postgres package's own control-plane tests on the
	// shared CI database.
	proj, err := built.ProjectStore.EnsureDefaultProject(
		ctx, "repo-build-test-project", "repo-build-scope", "Repo Build Test",
	)
	if err != nil {
		t.Fatalf("EnsureDefaultProject through Build's store: %v", err)
	}
	if proj == nil || proj.ID != "repo-build-test-project" {
		t.Fatalf("EnsureDefaultProject: got %+v, want id repo-build-test-project", proj)
	}
}
