package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/elloloop/identity/internal/graph"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ChangePassword changes the user's password after verifying the
// current password. On success every one of the user's sessions is
// revoked (their refresh tokens are deleted), forcing re-authentication
// on all devices — the documented credential-change behavior.
//
// The caller's own session is included: this RPC does not carry the
// current session/token id (the handler only resolves the authenticated
// user id from the JWT), so we cannot single out and preserve the
// caller's session. The user re-signs in with their new password. The
// session revoke is best-effort — the password is already committed when
// it runs, so a revoke failure is logged rather than failing the RPC.
func (s *ProfileService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	if currentPassword == "" || newPassword == "" {
		return errors.New("both current and new password are required")
	}

	userNode, err := s.db(ctx).GetNode(ctx, s.projectID(ctx), actorStr(userID), typeUser, userID)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}
	if userNode == nil {
		return errors.New("user not found")
	}

	// Enforce the owning tenant's password policy (an org may tighten the
	// global minimum length) for the account's own email domain — the same
	// resolution signup/reset/passwordless use — so a member of a governed
	// tenant cannot set a password weaker than their org allows.
	if err := s.governance.validatePasswordStrength(
		ctx, s.projectID(ctx), s.logger, pstr(userNode.Payload, ufEmail), newPassword,
	); err != nil {
		return err
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

	op := graph.Operation{
		Type: graph.OpUpdateNode, TypeID: typeUser, NodeID: userID,
		Patch: map[string]any{ufPasswordHash: newHash, ufUpdatedAt: nowMs()},
	}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.projectID(ctx), actorStr(userID), []graph.Operation{op}); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// A credential change must force re-authentication on every device.
	// The password is already committed, so a revoke failure is logged
	// (stale sessions live until their natural expiry) rather than failing
	// the RPC after a successful password change.
	revoked, err := s.revokeAllUserSessions(ctx, userID)
	if err != nil {
		s.logger.Warn("change_password_session_revoke_failed",
			zap.String("user_id", userID), zap.Error(err))
	}

	s.audit.Log(
		ctx, audit.EventPasswordChanged,
		audit.WithActor(userID), audit.WithTarget(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"sessions_revoked": revoked}),
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
	node, err := s.db(ctx).GetNode(ctx, s.projectID(ctx), actorStr(actorID), typeUser, actorID)
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

	nodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), tenantAdminActor, typeAuditEvent, filter)
	if err != nil {
		return nil, "", fmt.Errorf("list audit events: %w", err)
	}

	// Apply time-range filters in memory.
	var filtered []*graph.Node
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
	var page []*graph.Node
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

func auditEventFromNode(n *graph.Node) *AuditEvent {
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
