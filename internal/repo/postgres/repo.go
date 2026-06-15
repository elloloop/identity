package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elloloop/identity/internal/service"
)

// pgRepository is the Postgres-backed implementation of identity's
// persistence contracts. It is created via New().
type pgRepository struct {
	pool      *tracedPool
	projectID string
	cfg       Config
}

// New constructs a Postgres-backed repository:
//
//  1. Parse / validate cfg.
//  2. Open a pgxpool with cfg.MaxConns, cfg.ConnTimeout.
//  3. Optionally run pending migrations (cfg.AutoMigrate=true).
//  4. Ping to fail fast on a misconfigured DSN.
//
// The returned store implements both service.Repository and service.DB.
// The caller is responsible for keeping the *pgRepository alive for the
// lifetime of the service; pool resources are released by Close().
func New(ctx context.Context, cfg Config) (*pgRepository, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse DSN: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	// MaxConnLifetime: roll connections at 1 hour to play nicely with
	// upstream pgbouncer / RDS proxy idle timeouts and any rotation of
	// IAM-issued credentials.
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute
	if cfg.ConnTimeout > 0 {
		poolCfg.ConnConfig.ConnectTimeout = cfg.ConnTimeout
	}
	// RLS defense-in-depth (migration 0016): set the app.current_project_id
	// GUC on every connection the pool hands out, scoped to the acquiring
	// repository's project (read from the acquire context, injected by the
	// tracedPool). PrepareConn runs on EVERY Acquire — including the implicit
	// acquire inside pool.Query/Exec/QueryRow/Begin — so it covers all query
	// paths and re-sets the GUC each time, which prevents a pooled connection
	// from carrying one project's scope into another project's query (rls.go).
	poolCfg.PrepareConn = prepareConnForRLS

	rawPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	pool := newTracedPool(rawPool, cfg.ProjectID)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	if cfg.AutoMigrate {
		if err := runMigrations(cfg.DSN); err != nil {
			pool.Close()
			return nil, err
		}
	}

	return &pgRepository{
		pool:      pool,
		projectID: cfg.ProjectID,
		cfg:       cfg,
	}, nil
}

// WithProject returns a Repository sharing this store's connection pool
// but scoped to a different project (storage shard). Used by the
// per-request project-resolution path (ADR-0002), where every request
// needs a project-scoped Repository but opening a fresh pool per request
// would exhaust connections. The returned value shares the pool, so it
// must NOT be Closed independently — Close on the original releases the
// pool for all derived scopes.
func (r *pgRepository) WithProject(projectID string) service.Repository {
	cp := *r
	cp.projectID = projectID
	cp.cfg.ProjectID = projectID
	// Derive a tracedPool view bound to the new project. It shares the same
	// underlying *pgxpool.Pool (no new connections), but carries projectID so
	// every query it issues sets the app.current_project_id RLS GUC to this
	// project — not the project the base repository was bound to.
	cp.pool = r.pool.forProject(projectID)
	return &cp
}

// Close releases all pool resources. Safe to call multiple times.
//
// Repository does not declare a Close method, so callers that want the
// pool released should hold the *pgRepository concrete type — typically
// the application bootstrapper that called New().
func (r *pgRepository) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}

// ── Helpers ───────────────────────────────────────────────────────

// newID returns a fresh random hex ID. We do not depend on
// gen_random_uuid() server-side because we want the inserted ID
// available to the caller via the value, not RETURNING — fewer
// round-trips, identical semantics.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is "the OS RNG is broken" — panicking
		// matches the behaviour elsewhere in this codebase
		// (service/auth.go::generateRefreshToken).
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func nowMs() int64 { return time.Now().UnixMilli() }

// noRows reports whether err is pgx.ErrNoRows (the canonical "scan a
// row that wasn't there"). We surface that as nil-result to the
// service layer.
func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// nullableInt64 normalises map[string]any numeric values to int64, so
// callers can pass Go ints, int32s, int64s or float64-from-JSON
// uniformly.
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

// Compile-time check that *pgRepository satisfies the service.Repository
// interface. Failures here mean the Repository surface drifted and we
// missed an implementation.
var _ service.Repository = (*pgRepository)(nil)
