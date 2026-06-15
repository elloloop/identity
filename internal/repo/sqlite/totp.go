package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/service"
)

func (r *sqliteRepository) GetTotpCredential(ctx context.Context, userID string) (*service.TotpCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, user_id, secret_encrypted, verified, created_at_ms, last_used_at_ms
		  FROM totp_secrets
		 WHERE project_id = $1 AND user_id = $2
		 ORDER BY created_at_ms DESC
		 LIMIT 1`
	var (
		c        service.TotpCredRecord
		verified int64
	)
	err := r.db.QueryRow(ctx, q, r.projectID, userID).Scan(
		&c.NodeID, &c.UserID, &c.SecretEncrypted, &verified, &c.CreatedAt, &c.LastUsedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetTotpCredential", err)
	}
	c.Verified = verified != 0
	return &c, nil
}

func (r *sqliteRepository) CreateTotpCredential(ctx context.Context, c *service.TotpCredRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: CreateTotpCredential: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO totp_secrets (
			id, project_id, user_id, secret_encrypted, verified, created_at_ms, last_used_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, q, id, r.projectID, c.UserID, c.SecretEncrypted, c.Verified, c.CreatedAt, c.LastUsedAt)
	if err != nil {
		return "", wrapErr("CreateTotpCredential", err)
	}
	c.NodeID = id
	return id, nil
}

var totpFieldColumns = map[string]struct {
	col, kind string
}{
	"verified":         {"verified", "bool"},
	"last_used_at":     {"last_used_at_ms", "int64"},
	"secret_encrypted": {"secret_encrypted", "string"},
}

func (r *sqliteRepository) UpdateTotpCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("sqlite: UpdateTotpCredential: missing node id")
	}
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for k, v := range fields {
		spec, ok := totpFieldColumns[k]
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
		case "bool":
			b, ok := nullableBool(v)
			if !ok {
				continue
			}
			arg = b
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
	q := fmt.Sprintf(`UPDATE totp_secrets SET %s WHERE project_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1)
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return wrapErr("UpdateTotpCredential", err)
	}
	return nil
}

func (r *sqliteRepository) DeleteTotpCredential(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	const q = `DELETE FROM totp_secrets WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, nodeID); err != nil {
		return wrapErr("DeleteTotpCredential", err)
	}
	return nil
}

func (r *sqliteRepository) DeleteTotpCredentialsForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM totp_secrets WHERE project_id = $1 AND user_id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapErr("DeleteTotpCredentialsForUser", err)
	}
	return nil
}
