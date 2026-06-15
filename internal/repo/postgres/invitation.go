package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) FindInvitationByHash(ctx context.Context, tokenHash string) (*service.InvitationRecord, error) {
	if tokenHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, token_hash, email, user_id, invited_by, role,
		       expires_at_ms, accepted_at_ms, created_at_ms
		  FROM user_invitations
		 WHERE project_id = $1 AND token_hash = $2
		 LIMIT 1`
	var inv service.InvitationRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, tokenHash).Scan(
		&inv.NodeID, &inv.TokenHash, &inv.Email, &inv.UserID, &inv.InvitedBy, &inv.Role,
		&inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindInvitationByHash", err)
	}
	return &inv, nil
}

var invitationFieldColumns = map[string]struct {
	col, kind string
}{
	"accepted_at": {"accepted_at_ms", "int64"},
	"user_id":     {"user_id", "string"},
}

func (r *pgRepository) UpdateInvitation(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("postgres: UpdateInvitation: missing node id")
	}
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for k, v := range fields {
		spec, ok := invitationFieldColumns[k]
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
	q := fmt.Sprintf(`UPDATE user_invitations SET %s WHERE project_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1)
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return wrapPgErr("UpdateInvitation", err)
	}
	return nil
}
