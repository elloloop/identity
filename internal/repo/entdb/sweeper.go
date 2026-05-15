package entdb

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

// The five DeleteExpired* sweepers are unimplemented on the EntDB
// backend in this revision. The implementation needs FilterLt on
// expires_at, which shipped upstream in tenant-shard-db v1.12.0, but
// identity is still pinned to the v1.10.x server image while
// upstream tenant-shard-db#508 (entdb-server schema-less mode) is
// resolved.
//
// Until the v1.12 migration (issue #82) lands, these methods return
// service.ErrSweepNotImplemented so the background sweeper in
// internal/app/sweeper.go logs once and continues without erroring.
// All other backends (memory + Postgres) implement the sweep
// today; see internal/repo/postgres/sweeper.go.
//
// Tracking: GH #94 (sweeper) and #82 (v1.12 migration).

func (r *entRepository) DeleteExpiredWebAuthnChallenges(_ context.Context, _ int64, _ int) (int, error) {
	return 0, service.ErrSweepNotImplemented
}

func (r *entRepository) DeleteExpiredEmailVerificationTokens(_ context.Context, _ int64, _ int) (int, error) {
	return 0, service.ErrSweepNotImplemented
}

func (r *entRepository) DeleteExpiredPasswordResetTokens(_ context.Context, _ int64, _ int) (int, error) {
	return 0, service.ErrSweepNotImplemented
}

func (r *entRepository) DeleteExpiredEmailChangeTokens(_ context.Context, _ int64, _ int) (int, error) {
	return 0, service.ErrSweepNotImplemented
}

func (r *entRepository) DeleteExpiredLoginChallenges(_ context.Context, _ int64, _ int) (int, error) {
	return 0, service.ErrSweepNotImplemented
}
