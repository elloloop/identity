package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ProfileService implements self-service profile, session, passkey,
// password, and audit log operations.
type ProfileService struct {
	bootDB          DB
	defaultTenantID string
	audit           *audit.Logger
	logger          *zap.Logger
}

// NewProfileService creates a ProfileService.
func NewProfileService(db DB, tenantID string, auditLog *audit.Logger, logger *zap.Logger) *ProfileService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ProfileService{bootDB: db, defaultTenantID: tenantID, audit: auditLog, logger: logger}
}

// tenantID returns the request's resolved tenant, falling back to the
// boot-time DefaultTenantID in mode=single (decision log §1).
func (s *ProfileService) tenantID(ctx context.Context) string {
	if scope := TenantScopeFromContext(ctx); scope != nil && scope.TenantID != "" {
		return scope.TenantID
	}
	return s.defaultTenantID
}

// db returns the DB scoped to the request's resolved tenant (see the
// AdminService.db comment for why the two drivers differ); it falls
// back to the boot-time DB in mode=single.
func (s *ProfileService) db(ctx context.Context) DB {
	if scope := TenantScopeFromContext(ctx); scope != nil && scope.DB != nil {
		return scope.DB
	}
	return s.bootDB
}

// UpdateProfile updates the authenticated user's name and/or avatar.
func (s *ProfileService) UpdateProfile(ctx context.Context, userID, name, avatarURL string) (*User, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	node, err := s.db(ctx).GetNode(ctx, s.tenantID(ctx), actorStr(userID), typeUser, userID)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	if node == nil {
		return nil, errors.New("user not found")
	}

	patch := map[string]any{ufUpdatedAt: nowMs()}
	if n := strings.TrimSpace(name); n != "" {
		patch[ufName] = n
	}
	if a := strings.TrimSpace(avatarURL); a != "" {
		patch[ufAvatarURL] = a
	}

	op := entdb.Operation{Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: userID, Patch: patch}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(userID), []entdb.Operation{op}); err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}

	// Re-fetch.
	updated, err := s.db(ctx).GetNode(ctx, s.tenantID(ctx), actorStr(userID), typeUser, userID)
	if err != nil || updated == nil {
		// Fallback: apply patch manually.
		u := userFromNode(node)
		if n := strings.TrimSpace(name); n != "" {
			u.Name = n
		}
		if a := strings.TrimSpace(avatarURL); a != "" {
			u.AvatarURL = a
		}
		return u, nil
	}
	return userFromNode(updated), nil
}

// ListMySessions returns all active sessions for the user.
func (s *ProfileService) ListMySessions(ctx context.Context, userID string) ([]*Session, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	nodes, err := s.db(ctx).QueryNodes(ctx, s.tenantID(ctx), tenantAdminActor, typeRefreshToken,
		map[string]any{rfUserID: userID})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	now := nowMs()
	sessions := make([]*Session, 0, len(nodes))
	for _, n := range nodes {
		sess := sessionFromNode(n)
		if sess.ExpiresAt > now {
			sessions = append(sessions, sess)
		}
	}
	return sessions, nil
}

// RevokeSession revokes a specific session. The session must belong
// to the calling user.
func (s *ProfileService) RevokeSession(ctx context.Context, userID, sessionID string) error {
	if sessionID == "" {
		return errors.New("session_id is required")
	}

	node, err := s.db(ctx).GetNode(ctx, s.tenantID(ctx), tenantAdminActor, typeRefreshToken, sessionID)
	if err != nil {
		return fmt.Errorf("fetch session: %w", err)
	}
	if node == nil {
		return errors.New("session not found")
	}
	if pstr(node.Payload, rfUserID) != userID {
		return errors.New("session does not belong to you")
	}

	op := entdb.Operation{Type: entdb.OpDeleteNode, TypeID: typeRefreshToken, NodeID: sessionID}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.tenantID(ctx), tenantAdminActor, []entdb.Operation{op}); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventSessionRevoked,
		audit.WithActor(userID), audit.WithTarget(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"session_id": sessionID}),
	)
	return nil
}

// RevokeAllSessions revokes every session for the user. Requires
// password confirmation.
func (s *ProfileService) RevokeAllSessions(ctx context.Context, userID, password string) (int, error) {
	if password == "" {
		return 0, errors.New("password confirmation required")
	}

	userNode, err := s.db(ctx).GetNode(ctx, s.tenantID(ctx), actorStr(userID), typeUser, userID)
	if err != nil {
		return 0, fmt.Errorf("fetch user: %w", err)
	}
	if userNode == nil {
		return 0, errors.New("user not found")
	}
	pwHash := pstr(userNode.Payload, ufPasswordHash)
	if pwHash == "" || !passwords.Verify(password, pwHash) {
		return 0, errors.New("invalid password")
	}

	nodes, err := s.db(ctx).QueryNodes(ctx, s.tenantID(ctx), tenantAdminActor, typeRefreshToken,
		map[string]any{rfUserID: userID})
	if err != nil {
		return 0, fmt.Errorf("list sessions: %w", err)
	}

	count := 0
	for _, n := range nodes {
		op := entdb.Operation{Type: entdb.OpDeleteNode, TypeID: typeRefreshToken, NodeID: n.NodeID}
		if _, err := s.db(ctx).ExecuteAtomic(ctx, s.tenantID(ctx), tenantAdminActor, []entdb.Operation{op}); err != nil {
			s.logger.Warn("revoke_session_delete_failed", zap.String("session_id", n.NodeID))
			continue
		}
		count++
	}

	s.audit.Log(
		ctx, audit.EventSessionRevoked,
		audit.WithActor(userID), audit.WithTarget(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"scope": "all", "revoked_count": count}),
	)
	return count, nil
}

// ListMyPasskeys returns all passkey credentials for the user.
func (s *ProfileService) ListMyPasskeys(ctx context.Context, userID string) ([]*PasskeyInfo, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	nodes, err := s.db(ctx).QueryNodes(ctx, s.tenantID(ctx), actorStr(userID), typePasskeyCredCred,
		map[string]any{pkfUserID: userID})
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}

	passkeys := make([]*PasskeyInfo, 0, len(nodes))
	for _, n := range nodes {
		passkeys = append(passkeys, passkeyInfoFromNode(n))
	}
	return passkeys, nil
}

// DeletePasskey deletes a passkey belonging to the user.
func (s *ProfileService) DeletePasskey(ctx context.Context, userID, credentialID string) error {
	if credentialID == "" {
		return errors.New("credential_id is required")
	}

	// Find the passkey by credential_id.
	nodes, err := s.db(ctx).QueryNodes(ctx, s.tenantID(ctx), actorStr(userID), typePasskeyCredCred,
		map[string]any{pkfCredentialID: credentialID})
	if err != nil {
		return fmt.Errorf("find passkey: %w", err)
	}
	if len(nodes) == 0 {
		return errors.New("passkey not found")
	}
	cred := nodes[0]
	if pstr(cred.Payload, pkfUserID) != userID {
		return errors.New("passkey does not belong to you")
	}

	op := entdb.Operation{Type: entdb.OpDeleteNode, TypeID: typePasskeyCredCred, NodeID: cred.NodeID}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(userID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventPasskeyRemoved,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"credential_id": credentialID}),
	)
	return nil
}
