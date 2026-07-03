package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// #nosec G101 -- SQL column list contains token field names, not credentials.
const refreshTokenColumns = `
	id, token_hash, user_id, device_info, device_name,
	ip_address, user_agent,
	expires_at_ms, created_at_ms, last_used_at_ms, session_started_at_ms, consumed_at_ms, sid`

func scanRefreshToken(row pgx.Row) (*service.RefreshTokenRecord, error) {
	var t service.RefreshTokenRecord
	if err := row.Scan(
		&t.NodeID, &t.TokenHash, &t.UserID, &t.DeviceInfo, &t.DeviceName,
		&t.IPAddress, &t.UserAgent,
		&t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt, &t.SessionStartedAt, &t.ConsumedAtMs, &t.SID,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *pgRepository) FindRefreshTokenByHash(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	if hash == "" {
		return nil, nil
	}
	const q = `SELECT ` + refreshTokenColumns + `
		FROM refresh_tokens
		WHERE project_id = $1 AND token_hash = $2 AND consumed_at_ms = 0
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, hash)
	t, err := scanRefreshToken(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindRefreshTokenByHash", err)
	}
	return t, nil
}

func (r *pgRepository) FindRefreshTokenByHashIncludingConsumed(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	if hash == "" {
		return nil, nil
	}
	const q = `SELECT ` + refreshTokenColumns + `
		FROM refresh_tokens
		WHERE project_id = $1 AND token_hash = $2
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, hash)
	t, err := scanRefreshToken(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindRefreshTokenByHashIncludingConsumed", err)
	}
	return t, nil
}

func (r *pgRepository) CreateRefreshToken(ctx context.Context, t *service.RefreshTokenRecord) (string, error) {
	if t == nil {
		return "", errors.New("postgres: CreateRefreshToken: nil record")
	}
	id := t.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO refresh_tokens (
			id, project_id, token_hash, user_id,
			device_info, device_name, ip_address, user_agent,
			expires_at_ms, created_at_ms, last_used_at_ms, session_started_at_ms, consumed_at_ms, sid
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14
		)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, t.TokenHash, t.UserID,
		t.DeviceInfo, t.DeviceName, t.IPAddress, t.UserAgent,
		t.ExpiresAt, t.CreatedAt, t.LastUsedAt, t.SessionStartedAt, t.ConsumedAtMs, t.SID,
	)
	if err != nil {
		return "", wrapPgErr("CreateRefreshToken", err)
	}
	t.NodeID = id
	return id, nil
}

func (r *pgRepository) DeleteRefreshToken(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	const q = `DELETE FROM refresh_tokens WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, nodeID); err != nil {
		return wrapPgErr("DeleteRefreshToken", err)
	}
	return nil
}

func (r *pgRepository) DeleteRefreshTokensForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM refresh_tokens WHERE project_id = $1 AND user_id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapPgErr("DeleteRefreshTokensForUser", err)
	}
	return nil
}

// ConsumeRefreshTokenByHash atomically marks the row as consumed iff it
// is currently unconsumed. The "currently unconsumed" check is the
// WHERE clause; UPDATE returns the number of affected rows, which we
// inspect to detect the loser of a concurrent rotation.
func (r *pgRepository) ConsumeRefreshTokenByHash(ctx context.Context, hash string, atMs int64) error {
	if hash == "" {
		return service.ErrUnauthenticated
	}
	const q = `
		UPDATE refresh_tokens
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND token_hash = $2 AND consumed_at_ms = 0`
	tag, err := r.pool.Exec(ctx, q, r.projectID, hash, atMs)
	if err != nil {
		return wrapPgErr("ConsumeRefreshTokenByHash", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the row didn't exist, or it was already consumed —
		// service layer treats both as a replay/race loss.
		return service.ErrUnauthenticated
	}
	return nil
}
