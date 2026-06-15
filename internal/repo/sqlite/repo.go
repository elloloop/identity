// Package sqlite is the pure-Go SQLite Repository driver — the
// lightweight / embedded backend tier (single file or :memory:), sitting
// between Postgres (production, multi-node) and memory (tests). It uses
// modernc.org/sqlite (NO cgo) so the embeddable library cross-compiles
// cleanly.
//
// The driver implements service.Repository over the SQLite data plane
// (every row scoped by `WHERE project_id = $1`, the backend-agnostic
// isolation boundary — ADR-0002) and satisfies service.DB with the same
// no-op graph surface the memory driver uses. The control plane (projects
// registry beyond the boot default, tenants, domains, governance) is
// Postgres-only; SQLite targets the single-project embedded tier, so it
// keeps only a `projects` table to anchor the project_id FK chain and the
// EnsureDefaultProject boot seed.
//
// Schema lives in migrations/ as a squashed final-state SQL file, applied
// on New() via golang-migrate's pure-Go sqlite driver. JSONB columns are
// stored as TEXT; partial/expression indexes are preserved; there is no
// RLS (that stays Postgres-only defense-in-depth).
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver (pure Go).

	"github.com/elloloop/identity/internal/service"
)

// sqliteRepository is the SQLite-backed implementation of identity's
// persistence contracts. It is created via New().
type sqliteRepository struct {
	db        *sqldb
	projectID string
	// closer is the shared *sql.DB; only the root repository (the one New()
	// returned) owns it, so WithProject-derived scopes leave it nil and never
	// close the pool out from under their siblings.
	closer *sql.DB
}

// New opens (or creates) the SQLite database at cfg.Path, applies pending
// migrations, and returns a project-scoped repository. The returned store
// implements both service.Repository and service.DB.
//
// For an on-disk path the file is created if missing. For an in-memory
// database (cfg.Path == ":memory:") the store is bound to a single shared
// connection so every query sees the same database — a fresh connection to
// ":memory:" would otherwise get an independent empty database.
func New(ctx context.Context, cfg Config) (*sqliteRepository, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	dsn, inMemory := cfg.dsn()
	return open(ctx, dsn, inMemory, cfg.MaxConns, cfg.ProjectID)
}

// open is the shared constructor body: it opens the pool at dsn, sizes it,
// pings, migrates, and binds it to projectID. New() and the in-memory test
// helper both funnel through it so the setup path stays single-sourced.
func open(ctx context.Context, dsn string, inMemory bool, maxConns int, projectID string) (*sqliteRepository, error) {
	pool, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	if inMemory {
		// A shared in-memory database lives only as long as a connection to it
		// is open. Pinning the pool to a single connection keeps the one
		// database alive for the process and serialises writers (SQLite is a
		// single-writer engine anyway), which also sidesteps "database is
		// locked" under the concurrency conformance suite.
		pool.SetMaxOpenConns(1)
	} else {
		pool.SetMaxOpenConns(maxConns)
	}

	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}

	if err := runMigrations(pool); err != nil {
		_ = pool.Close()
		return nil, err
	}

	return &sqliteRepository{
		db:        &sqldb{db: pool},
		projectID: projectID,
		closer:    pool,
	}, nil
}

// WithProject returns a Repository sharing this store's connection pool but
// scoped to a different project (storage shard), used by the per-request
// project-resolution path (ADR-0002). The returned value shares the pool, so
// it must NOT be Closed independently — Close on the original releases it for
// all derived scopes.
func (r *sqliteRepository) WithProject(projectID string) service.Repository {
	cp := *r
	cp.projectID = projectID
	cp.closer = nil // derived scopes do not own the pool.
	return &cp
}

// Close releases the underlying pool. Safe to call multiple times and on a
// WithProject-derived scope (where it is a no-op).
func (r *sqliteRepository) Close() {
	if r != nil && r.closer != nil {
		_ = r.closer.Close()
		r.closer = nil
	}
}

// EnsureDefaultProject seeds the boot-default projects(id) row the
// project_id foreign key chain requires before any data-plane write. It is
// idempotent: a second call with the same id is a no-op. The composition
// root calls it once at boot, mirroring the postgres ProjectStore seed.
func (r *sqliteRepository) EnsureDefaultProject(ctx context.Context, projectID, name string) error {
	if projectID == "" {
		return fmt.Errorf("sqlite: EnsureDefaultProject: %w: empty project id", service.ErrInvalidArgument)
	}
	now := nowMs()
	const q = `
		INSERT INTO projects (id, storage_scope_id, name, status, config_json, created_at_ms, updated_at_ms)
		VALUES ($1, $2, $3, 'active', '{}', $4, $5)
		ON CONFLICT (id) DO NOTHING`
	if _, err := r.db.Exec(ctx, q, projectID, "scope-"+projectID, name, now, now); err != nil {
		return wrapErr("EnsureDefaultProject", err)
	}
	return nil
}

// ── Helpers (parallel to the postgres driver's repo.go) ───────────────

// newID returns a fresh random hex ID. SQLite has no gen_random_uuid(), and
// we want the inserted ID available to the caller via the value (not
// RETURNING) so node ids stay opaque strings, matching the other drivers.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func nowMs() int64 { return time.Now().UnixMilli() }

// nullableInt64 normalises map[string]any numeric values to int64.
func nullableInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// nullableBool normalises map[string]any bool values.
func nullableBool(v any) (bool, bool) {
	if b, ok := v.(bool); ok {
		return b, true
	}
	return false, false
}

// nullableString normalises map[string]any string values.
func nullableString(v any) (string, bool) {
	if s, ok := v.(string); ok {
		return s, true
	}
	return "", false
}

// Compile-time checks that *sqliteRepository satisfies both persistence
// contracts.
var (
	_ service.Repository = (*sqliteRepository)(nil)
	_ service.DB         = (*sqliteRepository)(nil)
)
