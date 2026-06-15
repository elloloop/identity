package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/elloloop/identity/internal/graph"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// HelpService implements the admin-help-request flow. End users who
// cannot log in raise a help request; admins resolve or reject them
// from the dashboard.
type HelpService struct {
	bootDB           DB
	defaultProjectID string
	audit            *audit.Logger
	logger           *zap.Logger
}

// NewHelpService creates a HelpService.
func NewHelpService(db DB, projectID string, auditLog *audit.Logger, logger *zap.Logger) *HelpService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &HelpService{bootDB: db, defaultProjectID: projectID, audit: auditLog, logger: logger}
}

// projectID returns the storage shard (project) the request operates under:
// the per-request ProjectScope when present, else the boot default. It is
// the partition argument the graph DB transport keys on (the postgres DB
// ignores it and filters on its WithProject-bound project instead).
func (s *HelpService) projectID(ctx context.Context) string {
	return requestProjectID(ctx, s.defaultProjectID)
}

// db returns the DB bound to the request's project.
func (s *HelpService) db(ctx context.Context) DB {
	return scopedDB(ctx, s.bootDB, s.defaultProjectID)
}

// RequestAdminHelp creates a help request. Always returns nil error
// to prevent email enumeration — internal failures are logged and
// swallowed. Rate limited to 3 requests per email per 24 hours.
func (s *HelpService) RequestAdminHelp(
	ctx context.Context, email, reason, sourceIP, userAgent string,
) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || !strings.Contains(email, "@") {
		return errors.New("valid email is required")
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}

	now := nowMs()
	dayAgo := now - 24*3600*1000

	// Rate limit: count pending requests for this email in the last 24h.
	recent, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), tenantAdminActor, typeAdminHelpReq,
		map[string]any{hfStatus: "pending"})
	if err != nil {
		s.logger.Warn("admin_help_rate_check_failed", zap.String("email", redactEmail(email)), zap.Error(err))
		recent = nil
	}

	countRecent := 0
	for _, n := range recent {
		nodeEmail := strings.ToLower(pstr(n.Payload, hfEmail))
		nodeCreated := pi64(n.Payload, hfCreatedAt)
		if nodeEmail == email && nodeCreated >= dayAgo {
			countRecent++
		}
	}
	if countRecent >= 3 {
		s.logger.Info("admin_help_rate_limited",
			zap.String("email", redactEmail(email)), zap.Int("count", countRecent))
		// Always return nil — no enumeration.
		return nil
	}

	data := map[string]any{
		hfEmail:           email,
		hfReason:          strings.TrimSpace(reason),
		hfSourceIP:        sourceIP,
		hfUserAgent:       truncate(userAgent, 512),
		hfStatus:          "pending",
		hfResolvedBy:      "",
		hfResolutionNotes: "",
		hfResolvedAt:      int64(0),
		hfCreatedAt:       now,
	}

	op := graph.Operation{Type: graph.OpCreateNode, TypeID: typeAdminHelpReq, Data: data}
	result, err := s.db(ctx).ExecuteAtomic(ctx, s.projectID(ctx), tenantAdminActor, []graph.Operation{op})
	if err != nil {
		s.logger.Error("admin_help_create_failed", zap.String("email", redactEmail(email)), zap.Error(err))
		// Best-effort: still return nil.
		return nil
	}

	requestID := ""
	if len(result.CreatedNodeIDs) > 0 {
		requestID = result.CreatedNodeIDs[0]
	}

	s.audit.Log(
		ctx, audit.EventAdminHelpRequested,
		audit.WithTarget(requestID),
		audit.WithIP(sourceIP),
		audit.WithUserAgent(userAgent),
		audit.WithDetails(map[string]any{"email": email}),
	)
	s.logger.Info("admin_help_requested",
		zap.String("email", redactEmail(email)), zap.String("request_id", requestID))
	return nil
}

// ListHelpRequests returns a paginated list of help requests.
// Admin-only. Returns pendingCount (all pending, regardless of filter).
func (s *HelpService) ListHelpRequests(
	ctx context.Context, actorID, statusFilter, cursor string, limit int,
) ([]*HelpRequest, string, int, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, "", 0, err
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

	// Fetch help requests with optional status filter.
	filter := map[string]any{}
	if statusFilter != "" {
		filter[hfStatus] = strings.ToLower(statusFilter)
	}
	nodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), tenantAdminActor, typeAdminHelpReq, filter)
	if err != nil {
		return nil, "", 0, fmt.Errorf("list help requests: %w", err)
	}

	totalCount := len(nodes)
	end := offset + limit
	if end > totalCount {
		end = totalCount
	}
	var page []*graph.Node
	if offset < totalCount {
		page = nodes[offset:end]
	}
	nextCursor := ""
	if end < totalCount {
		nextCursor = strconv.Itoa(end)
	}

	requests := make([]*HelpRequest, 0, len(page))
	for _, n := range page {
		requests = append(requests, helpRequestFromNode(n))
	}

	// Always compute pending count from unfiltered query.
	pendingCount := 0
	pendingNodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), tenantAdminActor, typeAdminHelpReq,
		map[string]any{hfStatus: "pending"})
	if err == nil {
		pendingCount = len(pendingNodes)
	}

	return requests, nextCursor, pendingCount, nil
}

// ResolveHelpRequest marks a help request as resolved or rejected.
// Admin-only.
func (s *HelpService) ResolveHelpRequest(
	ctx context.Context, actorID, requestID string, reject bool, notes string,
) (*HelpRequest, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if requestID == "" {
		return nil, errors.New("request_id is required")
	}

	node, err := s.db(ctx).GetNode(ctx, s.projectID(ctx), tenantAdminActor, typeAdminHelpReq, requestID)
	if err != nil {
		return nil, fmt.Errorf("fetch help request: %w", err)
	}
	if node == nil {
		return nil, errors.New("help request not found")
	}

	currentStatus := strings.ToLower(pstrOr(node.Payload, hfStatus, "pending"))
	if currentStatus != "pending" {
		return nil, fmt.Errorf("help request is not pending (status=%s)", currentStatus)
	}

	newStatus := "resolved"
	if reject {
		newStatus = "rejected"
	}
	if len(notes) > 2048 {
		notes = notes[:2048]
	}

	now := nowMs()
	patch := map[string]any{
		hfStatus:          newStatus,
		hfResolvedBy:      actorID,
		hfResolutionNotes: strings.TrimSpace(notes),
		hfResolvedAt:      now,
	}

	op := graph.Operation{Type: graph.OpUpdateNode, TypeID: typeAdminHelpReq, NodeID: requestID, Patch: patch}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.projectID(ctx), actorStr(actorID), []graph.Operation{op}); err != nil {
		return nil, fmt.Errorf("resolve help request: %w", err)
	}

	// Build result from original + patch.
	hr := helpRequestFromNode(node)
	hr.Status = newStatus
	hr.ResolvedBy = actorID
	hr.ResolutionNotes = strings.TrimSpace(notes)
	hr.ResolvedAt = now

	s.audit.Log(
		ctx, audit.EventAdminHelpResolved,
		audit.WithActor(actorID), audit.WithTarget(requestID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"outcome": newStatus}),
	)
	return hr, nil
}

// requireAdmin checks that the actor is an admin.
func (s *HelpService) requireAdmin(ctx context.Context, actorID string) error {
	node, err := s.db(ctx).GetNode(ctx, s.projectID(ctx), actorStr(actorID), typeUser, actorID)
	if err != nil {
		return fmt.Errorf("fetch actor: %w", err)
	}
	if node == nil {
		return errors.New("actor user not found")
	}
	if strings.ToLower(pstr(node.Payload, ufRole)) != "admin" {
		return errors.New("admin role required")
	}
	return nil
}
