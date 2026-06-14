// Package repo selects between concrete service.Repository / service.DB
// drivers (entdb, postgres, memory) for the production binary's wiring
// code.
//
// Each driver lives in its own sub-package — internal/repo/entdb for
// the EntDB-backed driver, internal/repo/postgres for the SQL driver,
// internal/repo/memory for the in-process store used by tests. The
// split keeps each driver's dependencies isolated (entdb pulls in the
// SDK; postgres pulls in pgx; memory pulls in nothing).
package repo

import (
	"context"
	"errors"
	"fmt"
	"math"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"go.uber.org/zap"

	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	memrepo "github.com/elloloop/identity/internal/repo/memory"
	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
)

// Driver names a concrete persistence backend.
type Driver string

const (
	// DriverEntDB targets the EntDB gRPC server via the typed SDK.
	DriverEntDB Driver = "entdb"
	// DriverPostgres targets a Postgres database via pgx/v5.
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

	// Postgres-specific.
	PostgresDSN         string
	PostgresMaxConns    int
	PostgresAutoMigrate bool
}

// Built bundles the constructed Repository + DB pair so callers can
// wire them into the service layer in one shot.
type Built struct {
	Repository service.Repository
	DB         service.DB

	// ProjectStore is the control-plane registry store. It is non-nil
	// ONLY for the postgres driver — projects are a control-plane concern
	// and entdb/memory have no control plane. The composition root uses it
	// to seed the default project on boot. It shares Repository's pool, so
	// closing the repository releases it too; do not close it separately.
	ProjectStore *pgrepo.ProjectStore

	// AutoFormStore auto-forms a company tenant from a new user's email
	// domain at signup. Non-nil ONLY for the postgres driver; shares
	// Repository's pool.
	AutoFormStore *pgrepo.AutoFormStore
}

// ProjectResolver returns the control-plane project resolver as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (entdb/memory). It exists so callers avoid the typed-nil trap:
// assigning a nil *ProjectStore straight into a service.ProjectResolver
// variable yields a non-nil interface wrapping a nil pointer.
func (b *Built) ProjectResolver() service.ProjectResolver {
	if b.ProjectStore == nil {
		return nil
	}
	return b.ProjectStore
}

// TenantAutoFormer returns the tenant auto-formation store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (entdb/memory) — avoiding the typed-nil trap.
func (b *Built) TenantAutoFormer() service.TenantAutoFormStore {
	if b.AutoFormStore == nil {
		return nil
	}
	return b.AutoFormStore
}

// Build returns a Built configured per cfg.Driver.
func Build(ctx context.Context, cfg Config, logger *zap.Logger) (*Built, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	switch cfg.Driver {
	case DriverEntDB:
		if cfg.EntDBClient == nil {
			return nil, errors.New("repo: Build: entdb driver requires EntDBClient")
		}
		if cfg.TenantID == "" {
			return nil, errors.New("repo: Build: entdb driver requires TenantID")
		}
		dbAdapter, err := NewDBAdapter(cfg.EntDBClient)
		if err != nil {
			return nil, fmt.Errorf("repo: Build: entdb db adapter: %w", err)
		}
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		return &Built{
			Repository: entdbrepo.NewRepository(cfg.EntDBClient, cfg.TenantID),
			DB:         dbAdapter,
		}, nil
	case DriverMemory:
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		mem := memrepo.New()
		return &Built{
			Repository: mem,
			DB:         mem,
		}, nil
	case DriverPostgres:
		if cfg.PostgresDSN == "" {
			return nil, errors.New("repo: Build: postgres driver requires PostgresDSN (set GATEWAY_POSTGRES_DSN)")
		}
		if cfg.TenantID == "" {
			return nil, errors.New("repo: Build: postgres driver requires TenantID")
		}
		if cfg.PostgresMaxConns > math.MaxInt32 {
			return nil, fmt.Errorf("repo: Build: postgres max connections exceeds int32: %d", cfg.PostgresMaxConns)
		}
		pgRepo, err := pgrepo.New(ctx, pgrepo.Config{
			DSN:         cfg.PostgresDSN,
			MaxConns:    int32(cfg.PostgresMaxConns), // #nosec G115 -- bounds checked above.
			AutoMigrate: cfg.PostgresAutoMigrate,
			TenantID:    cfg.TenantID,
		})
		if err != nil {
			return nil, fmt.Errorf("repo: Build: postgres: %w", err)
		}
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		return &Built{
			Repository:    pgRepo,
			DB:            pgRepo,
			ProjectStore:  pgrepo.NewProjectStore(pgRepo),
			AutoFormStore: pgrepo.NewAutoFormStore(pgRepo),
		}, nil
	default:
		return nil, fmt.Errorf("repo: Build: unknown driver %q", cfg.Driver)
	}
}
