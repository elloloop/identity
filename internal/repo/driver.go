// Package repo selects between concrete service.Repository / service.DB
// drivers (postgres, sqlite, memory) for the production binary's
// wiring code.
//
// Each driver lives in its own sub-package — internal/repo/postgres for
// the SQL driver, internal/repo/sqlite for the pure-Go embedded/single-node
// driver, and internal/repo/memory for the in-process store used by tests.
// The split keeps each driver's dependencies isolated (postgres pulls in
// pgx; sqlite pulls in modernc.org/sqlite; memory pulls in nothing).
package repo

import (
	"context"
	"errors"
	"fmt"
	"math"

	"go.uber.org/zap"

	memrepo "github.com/elloloop/identity/internal/repo/memory"
	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	sqliterepo "github.com/elloloop/identity/internal/repo/sqlite"
	"github.com/elloloop/identity/internal/service"
)

// Driver names a concrete persistence backend.
type Driver string

const (
	// DriverPostgres targets a Postgres database via pgx/v5.
	DriverPostgres Driver = "postgres"
	// DriverMemory targets a process-local in-memory store, useful
	// for unit tests and local development.
	DriverMemory Driver = "memory"
	// DriverSQLite targets a pure-Go SQLite database (file or :memory:)
	// via modernc.org/sqlite — the lightweight embedded/single-node tier.
	DriverSQLite Driver = "sqlite"
)

// Config selects which driver to build and carries the parameters
// each driver needs.
type Config struct {
	// Driver is the chosen backend. Required.
	Driver Driver

	// ProjectID is the storage shard the boot-default Repository/DB binds
	// to (ADR-0002): the Project is identity's isolation shard, so the
	// data-plane partition is the project id. Per-request scopes are derived
	// from it via WithProject. Required for postgres.
	ProjectID string

	// Postgres-specific.
	PostgresDSN         string
	PostgresMaxConns    int
	PostgresAutoMigrate bool

	// SQLite-specific. SQLitePath is the database file path or ":memory:".
	SQLitePath     string
	SQLiteMaxConns int

	// RequireVerifiedAuthDomain restricts a project's primary auth-domain
	// (the host that drives branded link URLs) to DNS-verified hostnames
	// when true (the safe default). When false, a deployer opts into letting
	// an unverified is_primary host drive branded links. Threaded into the
	// postgres ProjectStore resolver.
	RequireVerifiedAuthDomain bool
}

// Built bundles the constructed Repository + DB pair so callers can
// wire them into the service layer in one shot.
type Built struct {
	Repository service.Repository
	DB         service.DB

	// ProjectStore is the control-plane registry store. It is non-nil
	// ONLY for the postgres driver — projects are a control-plane concern
	// and memory has no control plane. The composition root uses it
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

	// PlatformAdminStore backs the zero-config first-admin bootstrap
	// (CreateFirstPlatformAdmin). Non-nil ONLY for the postgres driver (the
	// only one with a platform_admins table); shares Repository's pool.
	PlatformAdminStore *pgrepo.PlatformAdminStore
}

// ProjectResolver returns the control-plane project resolver as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory). It exists so callers avoid the typed-nil trap:
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
// true nil when this build has no control plane (memory) — avoiding the
// typed-nil trap.
func (b *Built) ControlPlaneStore() service.ControlPlaneProjectStore {
	if b.ProjectStore == nil {
		return nil
	}
	return b.ProjectStore
}

// TenantAutoFormer returns the tenant auto-formation store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory) — avoiding the typed-nil trap.
func (b *Built) TenantAutoFormer() service.TenantAutoFormStore {
	if b.AutoFormStore == nil {
		return nil
	}
	return b.AutoFormStore
}

// DomainStoreIface returns the domain governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory) — avoiding the typed-nil trap.
func (b *Built) DomainStoreIface() service.DomainStore {
	if b.DomainStore == nil {
		return nil
	}
	return b.DomainStore
}

// TenantStoreIface returns the tenant governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory) — avoiding the typed-nil trap.
func (b *Built) TenantStoreIface() service.TenantStore {
	if b.TenantStore == nil {
		return nil
	}
	return b.TenantStore
}

// MembershipStoreIface returns the membership governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory) — avoiding the typed-nil trap.
func (b *Built) MembershipStoreIface() service.MembershipStore {
	if b.MembershipStore == nil {
		return nil
	}
	return b.MembershipStore
}

// InvitationStoreIface returns the invitation governance store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory) — avoiding the typed-nil trap.
func (b *Built) InvitationStoreIface() service.InvitationStore {
	if b.InvitationStore == nil {
		return nil
	}
	return b.InvitationStore
}

// PlatformAdminStoreIface returns the platform-admin store as a
// driver-agnostic interface, or a true nil when this build has no control
// plane (memory) — avoiding the typed-nil trap.
func (b *Built) PlatformAdminStoreIface() service.PlatformAdminStore {
	if b.PlatformAdminStore == nil {
		return nil
	}
	return b.PlatformAdminStore
}

// LoginPolicyStoreIface returns the login-policy governance store as a
// driver-agnostic interface, or a true nil when this build has no governance
// plane (memory) — avoiding the typed-nil trap. It backs the operator
// LoginPolicy-authoring admin RPCs.
func (b *Built) LoginPolicyStoreIface() service.LoginPolicyStore {
	if b.LoginPolicyStore == nil {
		return nil
	}
	return b.LoginPolicyStore
}

// LoginGovernance returns the read-side governance bundle the login path
// consults to enforce a claimed tenant's LoginPolicy, or a true nil when
// this build has no governance plane (memory). Returning nil — rather
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
	case DriverMemory:
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		mem := memrepo.New()
		return &Built{
			Repository: mem,
			DB:         mem,
		}, nil
	case DriverSQLite:
		if cfg.SQLitePath == "" {
			return nil, errors.New("repo: Build: sqlite driver requires SQLitePath (set GATEWAY_SQLITE_PATH, or \":memory:\")")
		}
		if cfg.ProjectID == "" {
			return nil, errors.New("repo: Build: sqlite driver requires ProjectID")
		}
		sqliteRepo, err := sqliterepo.New(ctx, sqliterepo.Config{
			Path:      cfg.SQLitePath,
			MaxConns:  cfg.SQLiteMaxConns,
			ProjectID: cfg.ProjectID,
		})
		if err != nil {
			return nil, fmt.Errorf("repo: Build: sqlite: %w", err)
		}
		// The SQLite backend is the single-project embedded tier: it seeds the
		// boot-default project (the project_id FK anchor) but has no
		// control-plane registry/governance stores — those stay Postgres-only.
		if err := sqliteRepo.EnsureDefaultProject(ctx, cfg.ProjectID, cfg.ProjectID); err != nil {
			sqliteRepo.Close()
			return nil, fmt.Errorf("repo: Build: sqlite: seed default project: %w", err)
		}
		logger.Info("repo_driver_selected", zap.String("driver", string(cfg.Driver)))
		return &Built{
			Repository: sqliteRepo,
			DB:         sqliteRepo,
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
			Repository:         pgRepo,
			DB:                 pgRepo,
			ProjectStore:       pgrepo.NewProjectStore(pgRepo, cfg.RequireVerifiedAuthDomain),
			AutoFormStore:      pgrepo.NewAutoFormStore(pgRepo),
			DomainStore:        pgrepo.NewDomainStore(pgRepo),
			TenantStore:        pgrepo.NewTenantStore(pgRepo),
			MembershipStore:    pgrepo.NewMembershipStore(pgRepo),
			LoginPolicyStore:   pgrepo.NewLoginPolicyStore(pgRepo),
			InvitationStore:    pgrepo.NewInvitationStore(pgRepo),
			PlatformAdminStore: pgrepo.NewPlatformAdminStore(pgRepo),
		}, nil
	default:
		return nil, fmt.Errorf("repo: Build: unknown driver %q", cfg.Driver)
	}
}
