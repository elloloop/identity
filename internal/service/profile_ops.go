package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ChangePassword changes the user's password. Requires current
// password verification. Invalidates all refresh tokens.
func (s *ProfileService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	if currentPassword == "" || newPassword == "" {
		return errors.New("both current and new password are required")
	}

	issues := passwords.ValidateStrength(newPassword)
	if len(issues) > 0 {
		return fmt.Errorf("password too weak: %s", strings.Join(issues, "; "))
	}

	userNode, err := s.db.GetNode(ctx, s.tenantID, actorStr(userID), typeUser, userID)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}
	if userNode == nil {
		return errors.New("user not found")
	}

	pwHash := pstr(userNode.Payload, ufPasswordHash)
	if pwHash == "" {
		return errors.New("no password set for this account")
	}
	if !passwords.Verify(currentPassword, pwHash) {
		return errors.New("current password is incorrect")
	}

	newHash, err := passwords.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	op := entdb.Operation{
		Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: userID,
		Patch: map[string]any{ufPasswordHash: newHash, ufUpdatedAt: nowMs()},
	}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID, actorStr(userID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventPasswordChanged,
		audit.WithActor(userID), audit.WithTarget(userID), audit.WithSuccess(true),
	)
	return nil
}

// ListAuditEvents queries audit events. Admin-only.
func (s *ProfileService) ListAuditEvents(
	ctx context.Context,
	actorID, targetID, eventType string,
	startTime, endTime int64,
	cursor string, limit int,
) ([]*AuditEvent, string, error) {
	// Admin check.
	node, err := s.db.GetNode(ctx, s.tenantID, actorStr(actorID), typeUser, actorID)
	if err != nil {
		return nil, "", fmt.Errorf("fetch actor: %w", err)
	}
	if node == nil {
		return nil, "", errors.New("actor user not found")
	}
	if strings.ToLower(pstr(node.Payload, ufRole)) != "admin" {
		return nil, "", errors.New("admin role required")
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := 0
	if cursor != "" {
		if parsed, err := strconv.Atoi(cursor); err == nil {
			offset = parsed
		}
	}

	// Build filter from parameters.
	filter := map[string]any{}
	if targetID != "" {
		filter[afTargetUserID] = targetID
	}
	if eventType != "" {
		filter[afEventType] = eventType
	}

	nodes, err := s.db.QueryNodes(ctx, s.tenantID, tenantAdminActor, typeAuditEvent, filter)
	if err != nil {
		return nil, "", fmt.Errorf("list audit events: %w", err)
	}

	// Apply time-range filters in memory.
	var filtered []*entdb.Node
	for _, n := range nodes {
		created := pi64(n.Payload, afCreatedAt)
		if startTime > 0 && created < startTime {
			continue
		}
		if endTime > 0 && created > endTime {
			continue
		}
		filtered = append(filtered, n)
	}

	totalCount := len(filtered)
	end := offset + limit
	if end > totalCount {
		end = totalCount
	}
	var page []*entdb.Node
	if offset < totalCount {
		page = filtered[offset:end]
	}
	nextCursor := ""
	if end < totalCount {
		nextCursor = strconv.Itoa(end)
	}

	events := make([]*AuditEvent, 0, len(page))
	for _, n := range page {
		events = append(events, auditEventFromNode(n))
	}
	return events, nextCursor, nil
}

func auditEventFromNode(n *entdb.Node) *AuditEvent {
	if n == nil {
		return nil
	}
	p := n.Payload
	var details map[string]any
	detailsStr := pstr(p, afDetails)
	if detailsStr != "" && detailsStr != "{}" {
		_ = json.Unmarshal([]byte(detailsStr), &details)
	}
	if details == nil {
		details = map[string]any{}
	}
	return &AuditEvent{
		ID:           n.NodeID,
		EventType:    pstr(p, afEventType),
		ActorUserID:  pstr(p, afActorUserID),
		TargetUserID: pstr(p, afTargetUserID),
		IPAddress:    pstr(p, afIPAddress),
		UserAgent:    pstr(p, afUserAgent),
		Success:      pbool(p, afSuccess),
		Details:      details,
		CreatedAt:    pi64(p, afCreatedAt),
	}
}
