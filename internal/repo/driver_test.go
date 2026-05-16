package repo

import (
	"context"
	"math"
	"strings"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
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
		{"entdb_missing_client", Config{Driver: DriverEntDB, TenantID: "tenant"}},
		{"entdb_missing_tenant", Config{Driver: DriverEntDB, EntDBClient: &sdk.DbClient{}}},
		{"postgres_missing_dsn", Config{Driver: DriverPostgres, TenantID: "tenant"}},
		{"postgres_missing_tenant", Config{Driver: DriverPostgres, PostgresDSN: "postgres://example"}},
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
		TenantID:         "tenant",
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
	client, err := sdk.NewClient("localhost:50051")
	if err != nil {
		t.Fatalf("sdk.NewClient: %v", err)
	}
	built, err := Build(context.Background(), Config{
		Driver:      DriverEntDB,
		EntDBClient: client,
		TenantID:    "tenant-1",
	}, nil)
	if err != nil {
		t.Fatalf("Build entdb: %v", err)
	}
	if built == nil || built.Repository == nil || built.DB == nil {
		t.Fatalf("Build entdb returned incomplete result: %+v", built)
	}
}
