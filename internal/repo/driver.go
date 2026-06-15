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

	// EntDBClient is the EntDB SDK client (entdb driver only).
	EntDBClient *sdk.DbClient

	// ProjectID is the storage shard the boot-default Repository/DB binds
	// to (ADR-0002): the Project is identity's isolation shard, so the
	// data-plane partition is the project id. Per-request scopes are derived
	// from it via WithProject. Required for entdb and postgres.
	ProjectID string

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

	// DomainStore, TenantStore, MembershipStore and LoginPolicyStore are the
	// per-project governance stores. They back the tenant domain-verification
	// RPCs (DomainStore/TenantStore/MembershipStore) and the login path's
	// LoginPolicy enforcement (TenantStore/DomainStore/LoginPolicyStore).
	// Non-nil ONLY for the postgres driver (the only one with a governance
	// plane); each shares Repository's pool.
	DomainStore      *pgrepo.DomainStore
	TenantStore      *pgrepo.TenantStore
	MembershipStore  *pgrepo.MembershipStore
	LoginPolicyStore *pgrepo.LoginPolicyStore

	// InvitationStore backs the tenant-invitation RPCs. Non-nil ONLY for the
	// postgres driver; shares Repository's pool.
	InvitationStore *pgrepo.InvitationStore
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

// ControlPlaneStore returns the control-plane project write-store as the
// driver-agnostic service.ControlPlaneProjectStore the admin RPCs use, or a
// true nil when this build has no control plane (entdb/memory) — avoiding the
// typed-nil trap.
func (b *Built) ControlPlaneStore() service.ControlPlaneProjectStore {
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

// DomainStoreIface returns the domain governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (entdb/memory) — avoiding the typed-nil trap.
func (b *Built) DomainStoreIface() service.DomainStore {
	if b.DomainStore == nil {
		return nil
	}
	return b.DomainStore
}

// TenantStoreIface returns the tenant governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (entdb/memory) — avoiding the typed-nil trap.
func (b *Built) TenantStoreIface() service.TenantStore {
	if b.TenantStore == nil {
		return nil
	}
	return b.TenantStore
}

// MembershipStoreIface returns the membership governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (entdb/memory) — avoiding the typed-nil trap.
func (b *Built) MembershipStoreIface() service.MembershipStore {
	if b.MembershipStore == nil {
		return nil
	}
	return b.MembershipStore
}

// InvitationStoreIface returns the invitation governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (entdb/memory) — avoiding the typed-nil trap.
func (b *Built) InvitationStoreIface() service.InvitationStore {
	if b.InvitationStore == nil {
		return nil
	}
	return b.InvitationStore
}

// LoginGovernance returns the read-side governance bundle the login path
// consults to enforce a claimed tenant's LoginPolicy, or a true nil when
// this build has no governance plane (entdb/memory). Returning nil — rather
// than a bundle of typed-nil stores — keeps AuthService's nil check honest.
func (b *Built) LoginGovernance() *service.LoginGovernance {
	if b.TenantStore == nil || b.DomainStore == nil || b.LoginPolicyStore == nil {
		return nil
	}
	return &service.LoginGovernance{
		Domains:  b.DomainStore,
		Tenants:  b.TenantStore,
		Policies: b.LoginPolicyStore,
	}
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
		if cfg.ProjectID == "" {
			return nil, errors.New("repo: Build: entdb driver requires ProjectID")
		}
		dbAdapter, err := NewDBAdapter(cfg.EntDBClient)
		if err != nil {
			return nil, fmt.Errorf("repo: Build: entdb db adapter: %w", err)
		}
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		return &Built{
			Repository: entdbrepo.NewRepository(cfg.EntDBClient, cfg.ProjectID),
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
		if cfg.ProjectID == "" {
			return nil, errors.New("repo: Build: postgres driver requires ProjectID")
		}
		if cfg.PostgresMaxConns > math.MaxInt32 {
			return nil, fmt.Errorf("repo: Build: postgres max connections exceeds int32: %d", cfg.PostgresMaxConns)
		}
		pgRepo, err := pgrepo.New(ctx, pgrepo.Config{
			DSN:         cfg.PostgresDSN,
			MaxConns:    int32(cfg.PostgresMaxConns), // #nosec G115 -- bounds checked above.
			AutoMigrate: cfg.PostgresAutoMigrate,
			ProjectID:   cfg.ProjectID,
		})
		if err != nil {
			return nil, fmt.Errorf("repo: Build: postgres: %w", err)
		}
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		return &Built{
			Repository:       pgRepo,
			DB:               pgRepo,
			ProjectStore:     pgrepo.NewProjectStore(pgRepo),
			AutoFormStore:    pgrepo.NewAutoFormStore(pgRepo),
			DomainStore:      pgrepo.NewDomainStore(pgRepo),
			TenantStore:      pgrepo.NewTenantStore(pgRepo),
			MembershipStore:  pgrepo.NewMembershipStore(pgRepo),
			LoginPolicyStore: pgrepo.NewLoginPolicyStore(pgRepo),
			InvitationStore:  pgrepo.NewInvitationStore(pgRepo),
		}, nil
	default:
		return nil, fmt.Errorf("repo: Build: unknown driver %q", cfg.Driver)
	}
}
