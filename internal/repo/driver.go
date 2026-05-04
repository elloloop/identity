// Package repo selects between concrete service.Repository / service.DB
// drivers (entdb, postgres, memory) and re-exports the constructors
// for the production binary's wiring code.
//
// The drivers themselves live under sub-packages — internal/repo/entdb
// for the EntDB-backed driver, internal/repo/memory for the in-process
// driver used by tests. A future internal/repo/postgres driver lands
// there too. Splitting them keeps each driver's dependencies isolated
// (the entdb driver pulls in the SDK; memory pulls in nothing).
package repo

import (
	"context"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.uber.org/zap"

	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	memrepo "github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// Driver names a concrete persistence backend.
type Driver string

const (
	// DriverEntDB targets the EntDB gRPC server via the typed SDK.
	DriverEntDB Driver = "entdb"
	// DriverPostgres targets a Postgres database. The Postgres
	// driver is being built by another team — Build returns a not-
	// implemented error until that lands.
	DriverPostgres Driver = "postgres"
	// DriverMemory targets a process-local in-memory store, useful
	// for unit tests and local development.
	DriverMemory Driver = "memory"
)

// Config selects which driver to build and carries the parameters
// each driver needs.
type Config struct {
	// Driver is the chosen backend. Required.
	Driver Driver

	// EntDB-specific.
	EntDBClient *sdk.DbClient
	TenantID    string

	// Postgres-specific (TODO: postgres agent fills these in).
	PostgresDSN string
}

// Built bundles the constructed Repository + DB pair so callers can
// wire them into the service layer in one shot.
type Built struct {
	Repository service.Repository
	DB         service.DB
}

// Build returns a Built configured per cfg.Driver.
//
// The Postgres driver is left as a TODO — the Postgres agent owns
// internal/repo/postgres and will implement Build for the postgres
// driver in their PR.
func Build(_ context.Context, cfg Config, logger *zap.Logger) (*Built, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	switch cfg.Driver {
	case DriverEntDB:
		if cfg.EntDBClient == nil {
			return nil, fmt.Errorf("repo: Build: entdb driver requires EntDBClient")
		}
		if cfg.TenantID == "" {
			return nil, fmt.Errorf("repo: Build: entdb driver requires TenantID")
		}
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		return &Built{
			Repository: entdbrepo.NewRepository(cfg.EntDBClient, cfg.TenantID),
			DB:         entdbrepo.NewDBAdapter(cfg.EntDBClient),
		}, nil
	case DriverMemory:
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		mem := memrepo.New()
		return &Built{
			Repository: mem,
			DB:         mem,
		}, nil
	case DriverPostgres:
		// TODO(postgres-agent): wire internal/repo/postgres here.
		return nil, fmt.Errorf("repo: Build: postgres driver not yet implemented")
	default:
		return nil, fmt.Errorf("repo: Build: unknown driver %q", cfg.Driver)
	}
}

// NewEntDBRepository keeps the legacy import path working for
// callers that already wire the entdb driver explicitly. New code
// should use Build with cfg.Driver = DriverEntDB.
func NewEntDBRepository(client *sdk.DbClient, tenantID string) service.Repository {
	return entdbrepo.NewRepository(client, tenantID)
}

// NewDBAdapter keeps the legacy import path working. See note on
// NewEntDBRepository.
func NewDBAdapter(client *sdk.DbClient) service.DB {
	return entdbrepo.NewDBAdapter(client)
}
