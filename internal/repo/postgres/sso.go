package postgres

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) CreateSSOSession(ctx context.Context, s *service.SSOSessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("postgres: CreateSSOSession: nil record")
	}
	id := s.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO sso_sessions (
			id, project_id, token_hash, user_id, login_method,
			expires_at_ms, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, s.TokenHash, s.UserID, s.LoginMethod,
		s.ExpiresAt, s.CreatedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateSSOSession", err)
	}
	s.NodeID = id
	return id, nil
}

// GetSSOSessionByHash returns the session bound to tokenHash, or
// (nil, nil) when it names no live session. Expiry is the caller's
// check — the row is returned as-is so the service compares against
// its own clock.
func (r *pgRepository) GetSSOSessionByHash(ctx context.Context, tokenHash string) (*service.SSOSessionRecord, error) {
	if tokenHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, token_hash, user_id, login_method, expires_at_ms, created_at_ms
		  FROM sso_sessions
		 WHERE project_id = $1 AND token_hash = $2`
	var s service.SSOSessionRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, tokenHash).Scan(
		&s.NodeID, &s.TokenHash, &s.UserID, &s.LoginMethod,
		&s.ExpiresAt, &s.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetSSOSessionByHash", err)
	}
	return &s, nil
}

// RevokeSSOSessionsForUser hard-deletes every session the user holds —
// revocation IS deletion, so a revoked cookie can never be resurrected.
// Idempotent: a user with no sessions touches zero rows.
func (r *pgRepository) RevokeSSOSessionsForUser(ctx context.Context, userID string) error {
	const q = `
		DELETE FROM sso_sessions
		 WHERE project_id = $1 AND user_id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapPgErr("RevokeSSOSessionsForUser", err)
	}
	return nil
}
