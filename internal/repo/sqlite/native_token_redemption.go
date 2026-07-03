package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// RecordNativeTokenRedemption inserts the replay key of a redeemed native ID
// token, enforcing single-use. The (project_id, replay_key) unique index is
// the serialization point: the first INSERT wins and returns nil; a second
// INSERT of the same key — a replay of the same bearer token — hits the
// unique violation and returns ErrNativeTokenReplayed. Mirrors the postgres
// driver's semantics exactly (see conformance).
func (r *sqliteRepository) RecordNativeTokenRedemption(ctx context.Context, rec *service.NativeTokenRedemptionRecord) (string, error) {
	if rec == nil {
		return "", errors.New("sqlite: RecordNativeTokenRedemption: nil record")
	}
	if rec.ReplayKey == "" {
		return "", fmt.Errorf("%w: missing replay key", service.ErrInvalidArgument)
	}
	id := rec.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO native_token_redemptions (
			id, project_id, replay_key, expires_at_ms, created_at_ms
		) VALUES ($1, $2, $3, $4, $5)`
	if _, err := r.db.Exec(ctx, q, id, r.projectID, rec.ReplayKey, rec.ExpiresAt, rec.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return "", service.ErrNativeTokenReplayed
		}
		return "", wrapErr("RecordNativeTokenRedemption", err)
	}
	rec.NodeID = id
	return id, nil
}
