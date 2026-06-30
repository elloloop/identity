package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/service"
)

// #nosec G101 -- SQL column list contains key field names, not credentials.
const passkeyColumns = `
	id, credential_id, user_id, public_key, sign_count,
	device_name, aaguid, transports, backup_eligible, backup_state,
	created_at_ms, last_used_at_ms`

func scanPasskey(s scanner) (*service.PasskeyCredRecord, error) {
	var c service.PasskeyCredRecord
	if err := s.Scan(
		&c.NodeID, &c.CredentialID, &c.UserID, &c.PublicKey, &c.SignCount,
		&c.DeviceName, &c.AAGUID, &c.Transports, &c.BackupEligible, &c.BackupState,
		&c.CreatedAt, &c.LastUsedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *sqliteRepository) ListPasskeyCredentials(ctx context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `SELECT ` + passkeyColumns + `
		FROM passkeys
		WHERE project_id = $1 AND user_id = $2
		ORDER BY created_at_ms ASC`
	rs, err := r.db.Query(ctx, q, r.projectID, userID)
	if err != nil {
		return nil, wrapErr("ListPasskeyCredentials", err)
	}
	defer rs.Close()
	out := make([]*service.PasskeyCredRecord, 0)
	for rs.Next() {
		c, err := scanPasskey(rs)
		if err != nil {
			return nil, wrapErr("ListPasskeyCredentials", err)
		}
		out = append(out, c)
	}
	if err := rs.Err(); err != nil {
		return nil, wrapErr("ListPasskeyCredentials", err)
	}
	return out, nil
}

func (r *sqliteRepository) GetPasskeyCredentialByCredID(ctx context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
	if credentialID == "" {
		return nil, nil
	}
	const q = `SELECT ` + passkeyColumns + `
		FROM passkeys
		WHERE project_id = $1 AND credential_id = $2
		LIMIT 1`
	c, err := scanPasskey(r.db.QueryRow(ctx, q, r.projectID, credentialID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetPasskeyCredentialByCredID", err)
	}
	return c, nil
}

func (r *sqliteRepository) CreatePasskeyCredential(ctx context.Context, c *service.PasskeyCredRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: CreatePasskeyCredential: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO passkeys (
			id, project_id, credential_id, user_id, public_key, sign_count,
			device_name, aaguid, transports, backup_eligible, backup_state,
			created_at_ms, last_used_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err := r.db.Exec(
		ctx, q,
		id, r.projectID, c.CredentialID, c.UserID, c.PublicKey, c.SignCount,
		c.DeviceName, c.AAGUID, c.Transports, c.BackupEligible, c.BackupState,
		c.CreatedAt, c.LastUsedAt,
	)
	if err != nil {
		return "", wrapErr("CreatePasskeyCredential", err)
	}
	c.NodeID = id
	return id, nil
}

var passkeyFieldColumns = map[string]struct {
	col, kind string
}{
	"sign_count":   {"sign_count", "int64"},
	"last_used_at": {"last_used_at_ms", "int64"},
	"device_name":  {"device_name", "string"},
}

func (r *sqliteRepository) UpdatePasskeyCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("sqlite: UpdatePasskeyCredential: missing node id")
	}
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for k, v := range fields {
		spec, ok := passkeyFieldColumns[k]
		if !ok {
			continue
		}
		var arg any
		switch spec.kind {
		case "string":
			s, ok := nullableString(v)
			if !ok {
				continue
			}
			arg = s
		case "int64":
			n, ok := nullableInt64(v)
			if !ok {
				continue
			}
			arg = n
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", spec.col, idx))
		args = append(args, arg)
		idx++
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, r.projectID, nodeID)
	q := fmt.Sprintf(`UPDATE passkeys SET %s WHERE project_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1)
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return wrapErr("UpdatePasskeyCredential", err)
	}
	return nil
}

func (r *sqliteRepository) DeletePasskeyCredentialsForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM passkeys WHERE project_id = $1 AND user_id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapErr("DeletePasskeyCredentialsForUser", err)
	}
	return nil
}

// ── Passkey challenges ────────────────────────────────────────────

func (r *sqliteRepository) GetPasskeyChallenge(ctx context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	if nodeID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, challenge, user_id, challenge_type, email, expires_at_ms, created_at_ms
		  FROM passkey_challenges
		 WHERE project_id = $1 AND id = $2`
	var c service.PasskeyChallengeRecord
	err := r.db.QueryRow(ctx, q, r.projectID, nodeID).Scan(
		&c.NodeID, &c.Challenge, &c.UserID, &c.ChallengeType, &c.Email, &c.ExpiresAt, &c.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetPasskeyChallenge", err)
	}
	return &c, nil
}

func (r *sqliteRepository) CreatePasskeyChallenge(ctx context.Context, c *service.PasskeyChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: CreatePasskeyChallenge: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO passkey_challenges (
			id, project_id, challenge, user_id, challenge_type, email, expires_at_ms, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.Exec(ctx, q, id, r.projectID, c.Challenge, c.UserID, c.ChallengeType, c.Email, c.ExpiresAt, c.CreatedAt)
	if err != nil {
		return "", wrapErr("CreatePasskeyChallenge", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *sqliteRepository) DeletePasskeyChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	const q = `DELETE FROM passkey_challenges WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, nodeID); err != nil {
		return wrapErr("DeletePasskeyChallenge", err)
	}
	return nil
}
