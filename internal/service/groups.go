package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// GroupService implements working-group CRUD and membership operations.
// The underlying EntDB node type is WorkingGroup (type_id 2).
type GroupService struct {
	db              DB
	defaultTenantID string
	audit           *audit.Logger
	logger          *zap.Logger
}

// NewGroupService creates a GroupService.
func NewGroupService(db DB, tenantID string, auditLog *audit.Logger, logger *zap.Logger) *GroupService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GroupService{db: db, defaultTenantID: tenantID, audit: auditLog, logger: logger}
}

// tenantID returns the request's resolved tenant, falling back to the
// boot-time DefaultTenantID in mode=single (decision log §1). The DB
// interface takes the tenant per call, so this service needs only the
// resolved id.
func (s *GroupService) tenantID(ctx context.Context) string {
	if scope := TenantScopeFromContext(ctx); scope != nil && scope.TenantID != "" {
		return scope.TenantID
	}
	return s.defaultTenantID
}

// CreateGroup creates a new working group.
func (s *GroupService) CreateGroup(ctx context.Context, actorID, name, description string) (*Group, error) {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("group name is required")
	}

	now := nowMs()
	data := map[string]any{
		gfName:        name,
		gfDescription: strings.TrimSpace(description),
		gfCreatedBy:   actorID,
		gfCreatedAt:   now,
		gfUpdatedAt:   now,
	}
	op := entdb.Operation{Type: entdb.OpCreateNode, TypeID: typeWorkingGroup, Data: data}
	result, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op})
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}

	groupID := ""
	if len(result.CreatedNodeIDs) > 0 {
		groupID = result.CreatedNodeIDs[0]
	}

	s.logger.Info("group_created", zap.String("group_id", groupID), zap.String("actor", actorID))

	return &Group{
		ID: groupID, Name: name, Description: strings.TrimSpace(description),
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// UpdateGroup patches name and/or description of a group.
func (s *GroupService) UpdateGroup(ctx context.Context, actorID, groupID, name, description string) (*Group, error) {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return nil, err
	}
	if groupID == "" {
		return nil, errors.New("group_id is required")
	}

	patch := map[string]any{gfUpdatedAt: nowMs()}
	if name != "" {
		patch[gfName] = strings.TrimSpace(name)
	}
	if description != "" {
		patch[gfDescription] = strings.TrimSpace(description)
	}

	op := entdb.Operation{Type: entdb.OpUpdateNode, TypeID: typeWorkingGroup, NodeID: groupID, Patch: patch}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
		return nil, fmt.Errorf("update group: %w", err)
	}

	// Re-fetch.
	node, err := s.db.GetNode(ctx, s.tenantID(ctx), tenantAdminActor, typeWorkingGroup, groupID)
	if err != nil {
		return nil, fmt.Errorf("re-fetch group: %w", err)
	}
	if node == nil {
		return nil, errors.New("group not found after update")
	}
	return groupFromNode(node), nil
}

// DeleteGroup deletes a working group.
func (s *GroupService) DeleteGroup(ctx context.Context, actorID, groupID string) error {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return err
	}
	if groupID == "" {
		return errors.New("group_id is required")
	}

	op := entdb.Operation{Type: entdb.OpDeleteNode, TypeID: typeWorkingGroup, NodeID: groupID}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}

	s.logger.Info("group_deleted", zap.String("group_id", groupID), zap.String("actor", actorID))
	return nil
}

// ListGroups returns a paginated list of groups.
func (s *GroupService) ListGroups(ctx context.Context, actorID, cursor string, limit int) ([]*Group, string, error) {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 20
	}
	offset := 0
	if cursor != "" {
		if parsed, err := strconv.Atoi(cursor); err == nil {
			offset = parsed
		}
	}

	nodes, err := s.db.QueryNodes(ctx, s.tenantID(ctx), tenantAdminActor, typeWorkingGroup, nil)
	if err != nil {
		return nil, "", fmt.Errorf("list groups: %w", err)
	}

	totalCount := len(nodes)
	end := offset + limit
	if end > totalCount {
		end = totalCount
	}
	var page []*entdb.Node
	if offset < totalCount {
		page = nodes[offset:end]
	}
	nextCursor := ""
	if end < totalCount {
		nextCursor = strconv.Itoa(end)
	}

	groups := make([]*Group, 0, len(page))
	for _, n := range page {
		groups = append(groups, groupFromNode(n))
	}
	return groups, nextCursor, nil
}

// AddGroupMember creates a MEMBER_OF edge from user to group.
func (s *GroupService) AddGroupMember(ctx context.Context, actorID, groupID, userID string) error {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return err
	}
	if groupID == "" || userID == "" {
		return errors.New("group_id and user_id are required")
	}

	op := entdb.Operation{
		Type: entdb.OpCreateEdge, EdgeTypeID: edgeMemberOf,
		FromNodeID: userID, ToNodeID: groupID,
	}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("add group member: %w", err)
	}

	s.logger.Info(
		"group_member_added",
		zap.String("group_id", groupID), zap.String("user_id", userID),
	)
	return nil
}

// RemoveGroupMember deletes the MEMBER_OF edge from user to group.
func (s *GroupService) RemoveGroupMember(ctx context.Context, actorID, groupID, userID string) error {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return err
	}
	if groupID == "" || userID == "" {
		return errors.New("group_id and user_id are required")
	}

	op := entdb.Operation{
		Type: entdb.OpDeleteEdge, EdgeTypeID: edgeMemberOf,
		FromNodeID: userID, ToNodeID: groupID,
	}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}

	s.logger.Info(
		"group_member_removed",
		zap.String("group_id", groupID), zap.String("user_id", userID),
	)
	return nil
}

// ListGroupMembers returns all users that belong to a group via
// MEMBER_OF edges.
func (s *GroupService) ListGroupMembers(ctx context.Context, actorID, groupID string) ([]*User, error) {
	if _, err := requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID); err != nil {
		return nil, err
	}
	if groupID == "" {
		return nil, errors.New("group_id is required")
	}

	edges, err := s.db.GetEdgesTo(ctx, s.tenantID(ctx), tenantAdminActor, groupID, edgeMemberOf)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}

	users := make([]*User, 0, len(edges))
	for _, e := range edges {
		userNode, err := s.db.GetNode(ctx, s.tenantID(ctx), tenantAdminActor, typeUser, e.FromNodeID)
		if err != nil || userNode == nil {
			continue
		}
		users = append(users, userFromNode(userNode))
	}
	return users, nil
}
