package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) CreateRecoveryCode(ctx context.Context, c *service.RecoveryCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreateRecoveryCode: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO recovery_codes (
			id, project_id, user_id, code_hash, used,
			created_at_ms, used_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, c.UserID, c.CodeHash, c.Used,
		c.CreatedAt, c.UsedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateRecoveryCode", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *pgRepository) FindRecoveryCodeByHash(ctx context.Context, userID, hash string) (*service.RecoveryCodeRecord, error) {
	if userID == "" || hash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, user_id, code_hash, used, created_at_ms, used_at_ms
		  FROM recovery_codes
		 WHERE project_id = $1 AND user_id = $2 AND code_hash = $3
		 LIMIT 1`
	var c service.RecoveryCodeRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, userID, hash).Scan(
		&c.NodeID, &c.UserID, &c.CodeHash, &c.Used, &c.CreatedAt, &c.UsedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindRecoveryCodeByHash", err)
	}
	return &c, nil
}

var recoveryFieldColumns = map[string]struct {
	col, kind string
}{
	"used":    {"used", "bool"},
	"used_at": {"used_at_ms", "int64"},
}

func (r *pgRepository) UpdateRecoveryCode(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("postgres: UpdateRecoveryCode: missing node id")
	}
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for k, v := range fields {
		spec, ok := recoveryFieldColumns[k]
		if !ok {
			continue
		}
		var arg any
		switch spec.kind {
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
	q := fmt.Sprintf(`UPDATE recovery_codes SET %s WHERE project_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1)
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return wrapPgErr("UpdateRecoveryCode", err)
	}
	return nil
}

func (r *pgRepository) DeleteRecoveryCodesForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM recovery_codes WHERE project_id = $1 AND user_id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapPgErr("DeleteRecoveryCodesForUser", err)
	}
	return nil
}
