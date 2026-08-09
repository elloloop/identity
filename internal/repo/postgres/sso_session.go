package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

const ssoSessionColumns = `id, token_hash, user_id, login_method, ip_address, user_agent,
	created_at_ms, last_used_at_ms, expires_at_ms, revoked_at_ms`

func scanSSOSession(row pgx.Row) (*service.SSOSessionRecord, error) {
	var s service.SSOSessionRecord
	if err := row.Scan(
		&s.NodeID, &s.TokenHash, &s.UserID, &s.LoginMethod, &s.IPAddress, &s.UserAgent,
		&s.CreatedAtMs, &s.LastUsedAtMs, &s.ExpiresAtMs, &s.RevokedAtMs,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *pgRepository) CreateSSOSession(ctx context.Context, s *service.SSOSessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("postgres: CreateSSOSession: nil session")
	}
	if s.TokenHash == "" {
		return "", fmt.Errorf("%w: missing token_hash", service.ErrInvalidArgument)
	}
	if s.UserID == "" {
		return "", fmt.Errorf("%w: missing user_id", service.ErrInvalidArgument)
	}
	if s.CreatedAtMs == 0 {
		s.CreatedAtMs = nowMs()
	}
	if s.LastUsedAtMs == 0 {
		s.LastUsedAtMs = s.CreatedAtMs
	}
	id := s.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO sso_sessions (
			id, project_id, token_hash, user_id, login_method, ip_address, user_agent,
			created_at_ms, last_used_at_ms, expires_at_ms, revoked_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`
	if _, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, s.TokenHash, s.UserID, s.LoginMethod, s.IPAddress, s.UserAgent,
		s.CreatedAtMs, s.LastUsedAtMs, s.ExpiresAtMs, s.RevokedAtMs,
	); err != nil {
		if isUniqueViolation(err) {
			return "", fmt.Errorf("%w: sso session token", service.ErrAlreadyExists)
		}
		return "", wrapPgErr("CreateSSOSession", err)
	}
	s.NodeID = id
	return id, nil
}

// FindSSOSessionByHash returns expired and revoked rows too — the caller
// decides what an inactive session means, and a single query keeps the
// fast path to one round trip.
func (r *pgRepository) FindSSOSessionByHash(ctx context.Context, tokenHash string) (*service.SSOSessionRecord, error) {
	if tokenHash == "" {
		return nil, nil
	}
	const q = `SELECT ` + ssoSessionColumns + `
		FROM sso_sessions
		WHERE project_id = $1 AND token_hash = $2
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, tokenHash)
	s, err := scanSSOSession(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindSSOSessionByHash", err)
	}
	return s, nil
}

// TouchSSOSession re-anchors the rolling expiry. It refuses to resurrect a
// revoked row: a concurrent "sign out everywhere" must win against a
// continue-as that raced it.
func (r *pgRepository) TouchSSOSession(ctx context.Context, tokenHash string, lastUsedAtMs, expiresAtMs int64) error {
	if tokenHash == "" {
		return nil
	}
	const q = `
		UPDATE sso_sessions
		   SET last_used_at_ms = $3, expires_at_ms = $4
		 WHERE project_id = $1 AND token_hash = $2 AND revoked_at_ms = 0`
	if _, err := r.pool.Exec(ctx, q, r.projectID, tokenHash, lastUsedAtMs, expiresAtMs); err != nil {
		return wrapPgErr("TouchSSOSession", err)
	}
	return nil
}

// RevokeSSOSession is idempotent: the WHERE clause only matches active
// rows, so the first revocation's timestamp survives.
func (r *pgRepository) RevokeSSOSession(ctx context.Context, tokenHash string, atMs int64) error {
	if tokenHash == "" {
		return nil
	}
	const q = `
		UPDATE sso_sessions
		   SET revoked_at_ms = $3
		 WHERE project_id = $1 AND token_hash = $2 AND revoked_at_ms = 0`
	if _, err := r.pool.Exec(ctx, q, r.projectID, tokenHash, atMs); err != nil {
		return wrapPgErr("RevokeSSOSession", err)
	}
	return nil
}

func (r *pgRepository) RevokeSSOSessionsForUser(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return nil
	}
	const q = `
		UPDATE sso_sessions
		   SET revoked_at_ms = $3
		 WHERE project_id = $1 AND user_id = $2 AND revoked_at_ms = 0`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapPgErr("RevokeSSOSessionsForUser", err)
	}
	return nil
}
