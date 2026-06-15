package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

const sessionColumns = `id, sid, user_id, created_at_ms, revoked_at_ms`

func scanSession(s scanner) (*service.SessionRecord, error) {
	var rec service.SessionRecord
	if err := s.Scan(
		&rec.NodeID, &rec.SID, &rec.UserID, &rec.CreatedAtMs, &rec.RevokedAtMs,
	); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (r *sqliteRepository) CreateSession(ctx context.Context, s *service.SessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("sqlite: CreateSession: nil session")
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
		INSERT INTO sessions (id, project_id, sid, user_id, created_at_ms, revoked_at_ms)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := r.db.Exec(ctx, q, id, r.projectID, s.SID, s.UserID, s.CreatedAtMs, s.RevokedAtMs); err != nil {
		if isUniqueViolation(err) {
			return "", fmt.Errorf("%w: sid %q", service.ErrAlreadyExists, s.SID)
		}
		return "", wrapErr("CreateSession", err)
	}
	s.NodeID = id
	return id, nil
}

func (r *sqliteRepository) GetSessionBySid(ctx context.Context, sid string) (*service.SessionRecord, error) {
	if sid == "" {
		return nil, nil
	}
	const q = `SELECT ` + sessionColumns + ` FROM sessions WHERE project_id = $1 AND sid = $2 LIMIT 1`
	s, err := scanSession(r.db.QueryRow(ctx, q, r.projectID, sid))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetSessionBySid", err)
	}
	return s, nil
}

func (r *sqliteRepository) RevokeSession(ctx context.Context, sid string, atMs int64) error {
	if sid == "" {
		return nil
	}
	const q = `
		UPDATE sessions SET revoked_at_ms = $3
		 WHERE project_id = $1 AND sid = $2 AND revoked_at_ms = 0`
	if _, err := r.db.Exec(ctx, q, r.projectID, sid, atMs); err != nil {
		return wrapErr("RevokeSession", err)
	}
	return nil
}

func (r *sqliteRepository) RevokeSessionsForUser(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return nil
	}
	const q = `
		UPDATE sessions SET revoked_at_ms = $3
		 WHERE project_id = $1 AND user_id = $2 AND revoked_at_ms = 0`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapErr("RevokeSessionsForUser", err)
	}
	return nil
}
