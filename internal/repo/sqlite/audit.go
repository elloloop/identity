package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// CreateAuditEvent persists one audit event to the audit_events table and
// returns its id. A blank Event.ID is server-minted. Details is stored as a
// JSON text object; a nil/empty map is stored as "{}".
func (r *sqliteRepository) CreateAuditEvent(ctx context.Context, e *service.AuditEvent) (string, error) {
	if e == nil {
		return "", errors.New("sqlite: CreateAuditEvent: nil event")
	}
	id := e.ID
	if id == "" {
		id = newID()
	}
	createdAt := e.CreatedAt
	if createdAt == 0 {
		createdAt = nowMs()
	}
	details, err := marshalAuditDetails(e.Details)
	if err != nil {
		return "", wrapErr("CreateAuditEvent", err)
	}
	const q = `
		INSERT INTO audit_events (
			id, project_id, event_type, actor, target, ip_address, user_agent,
			success, details, occurred_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err = r.db.Exec(ctx, q, id, r.projectID, e.EventType, e.ActorUserID, e.TargetUserID,
		e.IPAddress, e.UserAgent, e.Success, details, createdAt)
	if err != nil {
		return "", wrapErr("CreateAuditEvent", err)
	}
	return id, nil
}

// ListAuditEventsForUser returns the events where userID is the actor OR the
// target, newest first (occurred-at desc, then id desc), capped at limit.
func (r *sqliteRepository) ListAuditEventsForUser(ctx context.Context, userID string, limit int) ([]*service.AuditEvent, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("sqlite: ListAuditEventsForUser: limit must be > 0, got %d", limit)
	}
	const q = `
		SELECT id, event_type, actor, target, ip_address, user_agent, success, details, occurred_at_ms
		  FROM audit_events
		 WHERE project_id = $1 AND (actor = $2 OR target = $2)
		 ORDER BY occurred_at_ms DESC, id DESC
		 LIMIT $3`
	rs, err := r.db.Query(ctx, q, r.projectID, userID, limit)
	if err != nil {
		return nil, wrapErr("ListAuditEventsForUser", err)
	}
	defer rs.Close()

	out := make([]*service.AuditEvent, 0)
	for rs.Next() {
		var (
			e       service.AuditEvent
			success int64
			details string
		)
		if err := rs.Scan(&e.ID, &e.EventType, &e.ActorUserID, &e.TargetUserID,
			&e.IPAddress, &e.UserAgent, &success, &details, &e.CreatedAt); err != nil {
			return nil, wrapErr("ListAuditEventsForUser", err)
		}
		e.Success = success != 0
		e.Details = unmarshalAuditDetails(details)
		out = append(out, &e)
	}
	if err := rs.Err(); err != nil {
		return nil, wrapErr("ListAuditEventsForUser", err)
	}
	return out, nil
}

// marshalAuditDetails encodes an audit event's details map as a JSON object
// string. An empty map is stored as "{}".
func marshalAuditDetails(details map[string]any) (string, error) {
	if len(details) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("marshal audit details: %w", err)
	}
	return string(b), nil
}

// unmarshalAuditDetails decodes a JSON object string into a details map. An
// empty or unparseable value yields an empty (non-nil) map so callers never
// dereference nil.
func unmarshalAuditDetails(raw string) map[string]any {
	out := map[string]any{}
	if raw == "" || raw == "{}" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}
