package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) FindQrLoginSession(ctx context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
	if sessionID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, session_id, status, user_id,
		       new_device_info, new_device_ip, new_device_user_agent,
		       approved_device_info, poll_secret_hash,
		       expires_at_ms, created_at_ms, updated_at_ms
		  FROM qr_login_sessions
		 WHERE project_id = $1 AND session_id = $2
		 LIMIT 1`
	var s service.QrLoginSessionRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, sessionID).Scan(
		&s.NodeID, &s.SessionID, &s.Status, &s.UserID,
		&s.NewDeviceInfo, &s.NewDeviceIP, &s.NewDeviceUserAgent,
		&s.ApprovedDeviceInfo, &s.PollSecretHash,
		&s.ExpiresAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindQrLoginSession", err)
	}
	return &s, nil
}

func (r *pgRepository) CreateQrLoginSession(ctx context.Context, s *service.QrLoginSessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("postgres: CreateQrLoginSession: nil record")
	}
	id := s.NodeID
	if id == "" {
		id = newID()
	}
	status := s.Status
	if status == "" {
		status = "pending"
	}
	const q = `
		INSERT INTO qr_login_sessions (
			id, project_id, session_id, status, user_id,
			new_device_info, new_device_ip, new_device_user_agent,
			approved_device_info, poll_secret_hash,
			expires_at_ms, created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, s.SessionID, status, s.UserID,
		s.NewDeviceInfo, s.NewDeviceIP, s.NewDeviceUserAgent,
		s.ApprovedDeviceInfo, s.PollSecretHash,
		s.ExpiresAt, s.CreatedAt, s.UpdatedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateQrLoginSession", err)
	}
	s.NodeID = id
	return id, nil
}

var qrFieldColumns = map[string]struct {
	col, kind string
}{
	"status":               {"status", "string"},
	"user_id":              {"user_id", "string"},
	"approved_device_info": {"approved_device_info", "string"},
	"updated_at":           {"updated_at_ms", "int64"},
}

func (r *pgRepository) UpdateQrLoginSession(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("postgres: UpdateQrLoginSession: missing node id")
	}
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for k, v := range fields {
		spec, ok := qrFieldColumns[k]
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
	q := fmt.Sprintf(`UPDATE qr_login_sessions SET %s WHERE project_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1)
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return wrapPgErr("UpdateQrLoginSession", err)
	}
	return nil
}

// ConsumeQrLoginSession atomically transitions an approved session to
// consumed via a single UPDATE gated on the current status. The
// `WHERE status = 'approved'` clause is the CAS predicate; UPDATE
// returns the number of rows touched, which we inspect to detect a
// concurrent loser.
func (r *pgRepository) ConsumeQrLoginSession(ctx context.Context, nodeID string, atMs int64) error {
	if nodeID == "" {
		return service.ErrQrLoginNotPending
	}
	const q = `
		UPDATE qr_login_sessions
		   SET status = 'consumed', updated_at_ms = $3
		 WHERE project_id = $1 AND id = $2 AND status = 'approved'`
	tag, err := r.pool.Exec(ctx, q, r.projectID, nodeID, atMs)
	if err != nil {
		return wrapPgErr("ConsumeQrLoginSession", err)
	}
	if tag.RowsAffected() == 0 {
		return service.ErrQrLoginNotPending
	}
	return nil
}
