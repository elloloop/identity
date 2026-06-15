package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

const sessionColumns = `id, sid, user_id, created_at_ms, revoked_at_ms`

func scanSession(row pgx.Row) (*service.SessionRecord, error) {
	var s service.SessionRecord
	if err := row.Scan(
		&s.NodeID, &s.SID, &s.UserID, &s.CreatedAtMs, &s.RevokedAtMs,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *pgRepository) CreateSession(ctx context.Context, s *service.SessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("postgres: CreateSession: nil session")
	}
	if s.SID == "" {
		return "", fmt.Errorf("%w: missing sid", service.ErrInvalidArgument)
	}
	if s.UserID == "" {
		return "", fmt.Errorf("%w: missing user_id", service.ErrInvalidArgument)
	}
	if s.CreatedAtMs == 0 {
		s.CreatedAtMs = nowMs()
	}
	id := s.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO sessions (
			id, project_id, sid, user_id, created_at_ms, revoked_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)`
	if _, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, s.SID, s.UserID, s.CreatedAtMs, s.RevokedAtMs,
	); err != nil {
		// Surface a sid-collision as ErrAlreadyExists so the service
		// layer can convert to the right gRPC code; the canonical
		// duplicate-key error from pgx is otherwise opaque.
		if isUniqueViolation(err) {
			return "", fmt.Errorf("%w: sid %q", service.ErrAlreadyExists, s.SID)
		}
		return "", wrapPgErr("CreateSession", err)
	}
	s.NodeID = id
	return id, nil
}

func (r *pgRepository) GetSessionBySid(ctx context.Context, sid string) (*service.SessionRecord, error) {
	if sid == "" {
		return nil, nil
	}
	const q = `SELECT ` + sessionColumns + `
		FROM sessions
		WHERE project_id = $1 AND sid = $2
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, sid)
	s, err := scanSession(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetSessionBySid", err)
	}
	return s, nil
}

// RevokeSession is idempotent: the WHERE clause only matches active
// rows, so re-revoking a session is a successful no-op.
func (r *pgRepository) RevokeSession(ctx context.Context, sid string, atMs int64) error {
	if sid == "" {
		return nil
	}
	const q = `
		UPDATE sessions
		   SET revoked_at_ms = $3
		 WHERE project_id = $1 AND sid = $2 AND revoked_at_ms = 0`
	if _, err := r.pool.Exec(ctx, q, r.projectID, sid, atMs); err != nil {
		return wrapPgErr("RevokeSession", err)
	}
	return nil
}

// RevokeSessionsForUser revokes every still-active session for the
// user. The WHERE clause skips already-revoked rows so the original
// revoke timestamp survives if a per-session revoke ran first.
func (r *pgRepository) RevokeSessionsForUser(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return nil
	}
	const q = `
		UPDATE sessions
		   SET revoked_at_ms = $3
		 WHERE project_id = $1 AND user_id = $2 AND revoked_at_ms = 0`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapPgErr("RevokeSessionsForUser", err)
	}
	return nil
}
