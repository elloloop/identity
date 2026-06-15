package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// #nosec G101 -- SQL column list contains token field names, not credentials.
const refreshTokenColumns = `
	id, token_hash, user_id, device_info, device_name,
	ip_address, user_agent,
	expires_at_ms, created_at_ms, last_used_at_ms, consumed_at_ms`

func scanRefreshToken(s scanner) (*service.RefreshTokenRecord, error) {
	var t service.RefreshTokenRecord
	if err := s.Scan(
		&t.NodeID, &t.TokenHash, &t.UserID, &t.DeviceInfo, &t.DeviceName,
		&t.IPAddress, &t.UserAgent,
		&t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt, &t.ConsumedAtMs,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *sqliteRepository) FindRefreshTokenByHash(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	if hash == "" {
		return nil, nil
	}
	const q = `SELECT ` + refreshTokenColumns + `
		FROM refresh_tokens
		WHERE project_id = $1 AND token_hash = $2 AND consumed_at_ms = 0
		LIMIT 1`
	t, err := scanRefreshToken(r.db.QueryRow(ctx, q, r.projectID, hash))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindRefreshTokenByHash", err)
	}
	return t, nil
}

func (r *sqliteRepository) FindRefreshTokenByHashIncludingConsumed(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	if hash == "" {
		return nil, nil
	}
	const q = `SELECT ` + refreshTokenColumns + `
		FROM refresh_tokens
		WHERE project_id = $1 AND token_hash = $2
		LIMIT 1`
	t, err := scanRefreshToken(r.db.QueryRow(ctx, q, r.projectID, hash))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindRefreshTokenByHashIncludingConsumed", err)
	}
	return t, nil
}

func (r *sqliteRepository) CreateRefreshToken(ctx context.Context, t *service.RefreshTokenRecord) (string, error) {
	if t == nil {
		return "", errors.New("sqlite: CreateRefreshToken: nil record")
	}
	id := t.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO refresh_tokens (
			id, project_id, token_hash, user_id,
			device_info, device_name, ip_address, user_agent,
			expires_at_ms, created_at_ms, last_used_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err := r.db.Exec(
		ctx, q,
		id, r.projectID, t.TokenHash, t.UserID,
		t.DeviceInfo, t.DeviceName, t.IPAddress, t.UserAgent,
		t.ExpiresAt, t.CreatedAt, t.LastUsedAt, t.ConsumedAtMs,
	)
	if err != nil {
		return "", wrapErr("CreateRefreshToken", err)
	}
	t.NodeID = id
	return id, nil
}

func (r *sqliteRepository) DeleteRefreshToken(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	const q = `DELETE FROM refresh_tokens WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, nodeID); err != nil {
		return wrapErr("DeleteRefreshToken", err)
	}
	return nil
}

func (r *sqliteRepository) DeleteRefreshTokensForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM refresh_tokens WHERE project_id = $1 AND user_id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapErr("DeleteRefreshTokensForUser", err)
	}
	return nil
}

func (r *sqliteRepository) ConsumeRefreshTokenByHash(ctx context.Context, hash string, atMs int64) error {
	if hash == "" {
		return service.ErrUnauthenticated
	}
	const q = `
		UPDATE refresh_tokens SET consumed_at_ms = $3
		 WHERE project_id = $1 AND token_hash = $2 AND consumed_at_ms = 0`
	tag, err := r.db.Exec(ctx, q, r.projectID, hash, atMs)
	if err != nil {
		return wrapErr("ConsumeRefreshTokenByHash", err)
	}
	if tag.RowsAffected() == 0 {
		return service.ErrUnauthenticated
	}
	return nil
}
