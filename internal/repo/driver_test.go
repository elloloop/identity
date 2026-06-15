package repo

import (
	"context"
	"math"
	"strings"
	"testing"

	entclient "github.com/elloloop/identity/internal/repo/entdb/entclient"
	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"go.uber.org/zap"
)

func TestBuildMemoryDriver(t *testing.T) {
	t.Parallel()

	built, err := Build(context.Background(), Config{Driver: DriverMemory}, nil)
	if err != nil {
		t.Fatalf("Build memory: %v", err)
	}
	if built == nil || built.Repository == nil || built.DB == nil {
		t.Fatalf("Build memory returned incomplete result: %#v", built)
	}
	// The control plane is postgres-only; memory has none.
	if built.ProjectStore != nil {
		t.Errorf("Build memory: ProjectStore = %v, want nil", built.ProjectStore)
	}
	assertNoGovernancePlane(t, built, "memory")
}

// assertNoGovernancePlane verifies a control-plane-free driver's accessors
// return true nils (not interfaces wrapping typed-nil pointers) so the
// service layer's `== nil` checks behave. Covers ProjectResolver,
// TenantAutoFormer and LoginGovernance together.
func assertNoGovernancePlane(t *testing.T, built *Built, driver string) {
	t.Helper()
	if r := built.ProjectResolver(); r != nil {
		t.Errorf("Build %s: ProjectResolver() = %v, want true nil", driver, r)
	}
	if af := built.TenantAutoFormer(); af != nil {
		t.Errorf("Build %s: TenantAutoFormer() = %v, want true nil", driver, af)
	}
	if cp := built.ControlPlaneStore(); cp != nil {
		t.Errorf("Build %s: ControlPlaneStore() = %v, want true nil", driver, cp)
	}
	if g := built.LoginGovernance(); g != nil {
		t.Errorf("Build %s: LoginGovernance() = %v, want true nil", driver, g)
	}
}

func TestBuildMemoryDriver_AcceptsExplicitLogger(t *testing.T) {
	t.Parallel()

	built, err := Build(context.Background(), Config{Driver: DriverMemory}, zap.NewNop())
	if err != nil || built == nil {
		t.Fatalf("Build memory with logger: built=%v err=%v", built, err)
	}
}

func TestBuildRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"unknown_driver", Config{Driver: Driver("unknown")}},
		{"entdb_missing_client", Config{Driver: DriverEntDB, ProjectID: "tenant"}},
		{"entdb_missing_project", Config{Driver: DriverEntDB, EntDBClient: &sdk.DbClient{}}},
		{"postgres_missing_dsn", Config{Driver: DriverPostgres, ProjectID: "tenant"}},
		{"postgres_missing_project", Config{Driver: DriverPostgres, PostgresDSN: "postgres://example"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if built, err := Build(context.Background(), tt.cfg, nil); err == nil || built != nil {
				t.Fatalf("Build(%#v) = %#v, %v; want nil, error", tt.cfg, built, err)
			}
		})
	}
}

func TestBuild_PostgresMaxConnsExceedsInt32(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Driver:           DriverPostgres,
		PostgresDSN:      "postgres://example",
		ProjectID:        "tenant",
		PostgresMaxConns: math.MaxInt32 + 1,
	}
	_, err := Build(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds int32") {
		t.Fatalf("Build with oversized max connections: err = %v, want int32 overflow", err)
	}
}

func TestBuild_EntDBHappyPath(t *testing.T) {
	t.Parallel()

	// sdk.NewClient does not dial — Connect is lazy — so this is safe
	// to construct without a server. We only assert Build returns a
	// non-nil Built; the actual reads/writes against the unconnected
	// client live in the real-entdb integration tests.
	client, err := entclient.New("localhost:50051")
	if err != nil {
		t.Fatalf("sdk.NewClient: %v", err)
	}
	built, err := Build(context.Background(), Config{
		Driver:      DriverEntDB,
		EntDBClient: client,
		ProjectID:   "tenant-1",
	}, nil)
	if err != nil {
		t.Fatalf("Build entdb: %v", err)
	}
	if built == nil || built.Repository == nil || built.DB == nil {
		t.Fatalf("Build entdb returned incomplete result: %+v", built)
	}
	// The control plane is postgres-only; entdb has none.
	if built.ProjectStore != nil {
		t.Errorf("Build entdb: ProjectStore = %v, want nil", built.ProjectStore)
	}
	assertNoGovernancePlane(t, built, "entdb")
}
