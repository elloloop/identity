package repo

import (
	"context"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
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
