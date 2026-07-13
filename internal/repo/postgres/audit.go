package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// CreateAuditEvent persists one audit event to the audit_events table and
// returns its id. A blank Event.ID is server-minted. Details is stored as
// JSONB; a nil/empty map is stored as an empty object.
func (r *pgRepository) CreateAuditEvent(ctx context.Context, e *service.AuditEvent) (string, error) {
	if e == nil {
		return "", errors.New("postgres: CreateAuditEvent: nil event")
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
		return "", wrapPgErr("CreateAuditEvent", err)
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_events (
			id, project_id, event_type, actor, target, ip_address, user_agent,
			success, details, occurred_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ($9)::jsonb, $10)
	`, id, r.projectID, e.EventType, e.ActorUserID, e.TargetUserID, e.IPAddress, e.UserAgent, e.Success, details, createdAt)
	if err != nil {
		return "", wrapPgErr("CreateAuditEvent", err)
	}
	return id, nil
}

// ListAuditEventsForUser returns the events where userID is the actor OR the
// target, newest first (occurred-at desc, then id desc), capped at limit.
func (r *pgRepository) ListAuditEventsForUser(ctx context.Context, userID string, limit int) ([]*service.AuditEvent, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("postgres: ListAuditEventsForUser: limit must be > 0, got %d", limit)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, event_type, actor, target, ip_address, user_agent, success, details::text, occurred_at_ms
		  FROM audit_events
		 WHERE project_id = $1 AND (actor = $2 OR target = $2)
		 ORDER BY occurred_at_ms DESC, id DESC
		 LIMIT $3
	`, r.projectID, userID, limit)
	if err != nil {
		return nil, wrapPgErr("ListAuditEventsForUser", err)
	}
	defer rows.Close()

	out := make([]*service.AuditEvent, 0)
	for rows.Next() {
		e, err := scanAuditEventRow(rows)
		if err != nil {
			return nil, wrapPgErr("ListAuditEventsForUser", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListAuditEventsForUser", err)
	}
	return out, nil
}

// auditRetentionSweepBatch caps how many audit rows a single DELETE statement
// removes, so the storage-limitation sweep never takes a table-wide lock on a
// large audit_events table. DeleteAuditEventsBefore loops at this size until the
// backlog older than the cutoff is fully drained.
const auditRetentionSweepBatch = 1000

// DeleteAuditEventsBefore deletes audit events whose occurred_at_ms is strictly
// less than cutoffMs, in capped batches, and returns the total number removed.
// Postgres has no native DELETE ... LIMIT, so each batch pins its work with a
// subquery ordered by occurred_at_ms ASC (oldest first) — deterministic across
// retries and index-friendly. The loop ends once a batch removes fewer rows
// than the cap, i.e. the eligible set is exhausted.
func (r *pgRepository) DeleteAuditEventsBefore(ctx context.Context, cutoffMs int64) (int, error) {
	total := 0
	for {
		tag, err := r.pool.Exec(ctx, `
			DELETE FROM audit_events
			 WHERE id IN (
			     SELECT id FROM audit_events
			      WHERE project_id = $1 AND occurred_at_ms < $2
			      ORDER BY occurred_at_ms ASC
			      LIMIT $3
			 )`, r.projectID, cutoffMs, auditRetentionSweepBatch)
		if err != nil {
			return total, wrapPgErr("DeleteAuditEventsBefore", err)
		}
		removed := int(tag.RowsAffected())
		total += removed
		if removed < auditRetentionSweepBatch {
			return total, nil
		}
	}
}

// scanAuditEventRow reads one audit_events row into the service domain type.
func scanAuditEventRow(row interface{ Scan(...any) error }) (*service.AuditEvent, error) {
	var id, eventType, actor, target, ipAddress, userAgent, details string
	var success bool
	var createdAt int64
	if err := row.Scan(&id, &eventType, &actor, &target, &ipAddress, &userAgent, &success, &details, &createdAt); err != nil {
		return nil, err
	}
	return &service.AuditEvent{
		ID:           id,
		EventType:    eventType,
		ActorUserID:  actor,
		TargetUserID: target,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Success:      success,
		Details:      unmarshalAuditDetails(details),
		CreatedAt:    createdAt,
	}, nil
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
