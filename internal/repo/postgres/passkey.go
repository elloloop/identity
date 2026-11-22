package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// #nosec G101 -- SQL column list contains key field names, not credentials.
const passkeyColumns = `
	id, credential_id, user_id, public_key, sign_count,
	device_name, aaguid, transports, backup_eligible, backup_state,
	created_at_ms, last_used_at_ms, reauthentication_eligible`

func scanPasskey(row pgx.Row) (*service.PasskeyCredRecord, error) {
	var c service.PasskeyCredRecord
	if err := row.Scan(
		&c.NodeID, &c.CredentialID, &c.UserID, &c.PublicKey, &c.SignCount,
		&c.DeviceName, &c.AAGUID, &c.Transports, &c.BackupEligible, &c.BackupState,
		&c.CreatedAt, &c.LastUsedAt, &c.ReauthenticationEligible,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *pgRepository) ListPasskeyCredentials(ctx context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `SELECT ` + passkeyColumns + `
		FROM passkeys
		WHERE project_id = $1 AND user_id = $2
		ORDER BY created_at_ms ASC`
	rows, err := r.pool.Query(ctx, q, r.projectID, userID)
	if err != nil {
		return nil, wrapPgErr("ListPasskeyCredentials", err)
	}
	defer rows.Close()
	out := make([]*service.PasskeyCredRecord, 0)
	for rows.Next() {
		c, err := scanPasskey(rows)
		if err != nil {
			return nil, wrapPgErr("ListPasskeyCredentials", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListPasskeyCredentials", err)
	}
	return out, nil
}

func (r *pgRepository) GetPasskeyCredentialByCredID(ctx context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
	if credentialID == "" {
		return nil, nil
	}
	const q = `SELECT ` + passkeyColumns + `
		FROM passkeys
		WHERE project_id = $1 AND credential_id = $2
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, credentialID)
	c, err := scanPasskey(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetPasskeyCredentialByCredID", err)
	}
	return c, nil
}

func (r *pgRepository) CreatePasskeyCredential(ctx context.Context, c *service.PasskeyCredRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreatePasskeyCredential: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO passkeys (
			id, project_id, credential_id, user_id, public_key, sign_count,
			device_name, aaguid, transports, backup_eligible, backup_state,
			created_at_ms, last_used_at_ms, reauthentication_eligible
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, c.CredentialID, c.UserID, c.PublicKey, c.SignCount,
		c.DeviceName, c.AAGUID, c.Transports, c.BackupEligible, c.BackupState,
		c.CreatedAt, c.LastUsedAt, c.ReauthenticationEligible,
	)
	if err != nil {
		return "", wrapPgErr("CreatePasskeyCredential", err)
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

func (r *pgRepository) UpdatePasskeyCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("postgres: UpdatePasskeyCredential: missing node id")
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
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return wrapPgErr("UpdatePasskeyCredential", err)
	}
	return nil
}

func (r *pgRepository) DeletePasskeyCredentialsForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM passkeys WHERE project_id = $1 AND user_id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapPgErr("DeletePasskeyCredentialsForUser", err)
	}
	return nil
}

func (r *pgRepository) DeletePasskeyCredential(ctx context.Context, userID, credentialID string) error {
	if userID == "" || credentialID == "" {
		return service.ErrNotFound
	}
	const q = `DELETE FROM passkeys WHERE project_id = $1 AND user_id = $2 AND credential_id = $3`
	tag, err := r.pool.Exec(ctx, q, r.projectID, userID, credentialID)
	if err != nil {
		return wrapPgErr("DeletePasskeyCredential", err)
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

// ── Passkey challenges ────────────────────────────────────────────

func (r *pgRepository) GetPasskeyChallenge(ctx context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	if nodeID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, challenge, user_id, challenge_type, email, expires_at_ms, created_at_ms, action, resource_id
		  FROM passkey_challenges
		 WHERE project_id = $1 AND id = $2`
	var c service.PasskeyChallengeRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, nodeID).Scan(
		&c.NodeID, &c.Challenge, &c.UserID, &c.ChallengeType, &c.Email,
		&c.ExpiresAt, &c.CreatedAt, &c.Action, &c.ResourceID,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetPasskeyChallenge", err)
	}
	return &c, nil
}

func (r *pgRepository) CreatePasskeyChallenge(ctx context.Context, c *service.PasskeyChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreatePasskeyChallenge: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO passkey_challenges (
			id, project_id, challenge, user_id, challenge_type, email,
			expires_at_ms, created_at_ms, action, resource_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, c.Challenge, c.UserID, c.ChallengeType, c.Email,
		c.ExpiresAt, c.CreatedAt, c.Action, c.ResourceID,
	)
	if err != nil {
		return "", wrapPgErr("CreatePasskeyChallenge", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *pgRepository) DeletePasskeyChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	const q = `DELETE FROM passkey_challenges WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, nodeID); err != nil {
		return wrapPgErr("DeletePasskeyChallenge", err)
	}
	return nil
}

func (r *pgRepository) ConsumeReauthenticationChallenge(ctx context.Context, nodeID, userID, action, resourceID string, atMs int64) (bool, error) {
	if nodeID == "" || userID == "" || action == "" {
		return false, nil
	}
	const q = `DELETE FROM passkey_challenges
      WHERE project_id = $1 AND id = $2 AND user_id = $3 AND action = $4
      AND resource_id = $5 AND expires_at_ms > $6 AND created_at_ms <= $6
      AND challenge_type = 'authentication'`
	result, err := r.pool.Exec(ctx, q, r.projectID, nodeID, userID, action, resourceID, atMs)
	if err != nil {
		return false, wrapPgErr("ConsumeReauthenticationChallenge", err)
	}
	return result.RowsAffected() == 1, nil
}

func (r *pgRepository) MarkPasskeyReauthenticationEligible(ctx context.Context, verified *service.PasskeyCredRecord) (bool, error) {
	if verified == nil || verified.NodeID == "" || verified.UserID == "" || verified.PublicKey == "" {
		return false, nil
	}
	result, err := r.pool.Exec(ctx, `UPDATE passkeys SET reauthentication_eligible=true WHERE project_id=$1 AND id=$2 AND user_id=$3 AND credential_id=$4 AND public_key=$5`, r.projectID, verified.NodeID, verified.UserID, verified.CredentialID, verified.PublicKey)
	if err != nil {
		return false, wrapPgErr("MarkPasskeyReauthenticationEligible", err)
	}
	return result.RowsAffected() == 1, nil
}
