package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// PlatformAdminStore is the Postgres-backed, control-plane store for platform
// operator accounts (the platform_admins table from migration 0013). Like the
// other control-plane stores it is platform-global (not project/tenant
// scoped) and shares its caller's connection pool.
type PlatformAdminStore struct {
	pool *tracedPool
}

var _ service.PlatformAdminStore = (*PlatformAdminStore)(nil)

// NewPlatformAdminStore builds a platform-admin store sharing the given
// repository's connection pool. The store must NOT be closed independently —
// closing the owning *pgRepository releases the pool for every derived store.
func NewPlatformAdminStore(r *pgRepository) *PlatformAdminStore {
	return &PlatformAdminStore{pool: r.pool}
}

// bootstrapAdvisoryLockKey is the session-global key the first-admin bootstrap
// takes a transaction-scoped advisory lock on. It serializes ALL concurrent
// CreateFirstPlatformAdmin attempts so the "is the table empty?" check and the
// insert are one atomic decision — no two callers can both observe an empty
// table and both insert. The constant is arbitrary but fixed; it lives here so
// the lock is taken on exactly one key, never a literal scattered at call
// sites. (Chosen as the ASCII of "PADM" so it is recognisable in pg_locks.)
const bootstrapAdvisoryLockKey int64 = 0x5041444d // "PADM"

// CreateFirstPlatformAdmin inserts the first platform admin atomically and
// ONLY while the table is empty. It takes a transaction-scoped advisory lock
// first, so concurrent bootstraps are fully serialized: the winner sees an
// empty table and inserts; every loser, running after the winner commits,
// sees a non-empty table and returns (created=false, nil) without writing.
//
// The advisory lock — rather than relying on the table's own constraints — is
// what makes "empty?" race-safe: under READ COMMITTED two plain
// SELECT-then-INSERT transactions could each see zero rows and both insert
// distinct-email admins, defeating the one-time guarantee. Serializing on a
// single lock key closes that window.
func (s *PlatformAdminStore) CreateFirstPlatformAdmin(ctx context.Context, a *service.PlatformAdmin) (bool, error) {
	if a == nil {
		return false, errors.New("postgres: CreateFirstPlatformAdmin: nil admin")
	}
	if a.Email == "" {
		return false, fmt.Errorf("%w: missing email", service.ErrInvalidArgument)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, wrapPgErr("CreateFirstPlatformAdmin(begin)", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize every bootstrap attempt on one key for the life of this tx.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapAdvisoryLockKey); err != nil {
		return false, wrapPgErr("CreateFirstPlatformAdmin(lock)", err)
	}

	// With the lock held, the table's emptiness is stable for this tx.
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM platform_admins`).Scan(&count); err != nil {
		return false, wrapPgErr("CreateFirstPlatformAdmin(count)", err)
	}
	if count > 0 {
		// An admin already exists — the bootstrap is permanently closed.
		// Commit (releasing the lock) and report "not created".
		if err := tx.Commit(ctx); err != nil {
			return false, wrapPgErr("CreateFirstPlatformAdmin(commit-existing)", err)
		}
		return false, nil
	}

	id := a.ID
	if id == "" {
		id = newID()
	}
	status := a.Status
	if status == "" {
		status = service.PlatformAdminStatusActive
	}
	createdAt := a.CreatedAtMs
	if createdAt == 0 {
		createdAt = nowMs()
	}
	const q = `
		INSERT INTO platform_admins (
			id, email, password_hash, totp_required, status,
			created_at_ms, last_login_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`
	if _, err := tx.Exec(
		ctx, q,
		id, a.Email, a.PasswordHash, a.TOTPRequired, status,
		createdAt, a.LastLoginAtMs,
	); err != nil {
		return false, wrapPgErr("CreateFirstPlatformAdmin(insert)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, wrapPgErr("CreateFirstPlatformAdmin(commit)", err)
	}
	a.ID = id
	a.Status = status
	a.CreatedAtMs = createdAt
	return true, nil
}

// CountPlatformAdmins returns the number of platform admins (any status).
func (s *PlatformAdminStore) CountPlatformAdmins(ctx context.Context) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM platform_admins`).Scan(&count); err != nil {
		return 0, wrapPgErr("CountPlatformAdmins", err)
	}
	return count, nil
}
