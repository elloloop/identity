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
	defaultRepo     Repository
	defaultTenantID string
	audit           *audit.Logger
	logger          *zap.Logger
}

// NewProfileService creates a ProfileService.
//
// The repo argument may be nil — in that case only the DB-backed paths
// work (Sessions, AuditEvents). Profile/password operations need repo
// to be set; nil triggers ErrServiceUnavailable at call time, the same
// shape the no-persistence stub takes.
func NewProfileService(repo Repository, db DB, tenantID string, auditLog *audit.Logger, logger *zap.Logger) *ProfileService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ProfileService{
		bootDB:          db,
		defaultRepo:     repo,
		defaultTenantID: tenantID,
		audit:           auditLog,
		logger:          logger,
	}
}

// repo returns the Repository scoped to the request's resolved tenant,
// falling back to the boot-time Repository in mode=single.
func (s *ProfileService) repo(ctx context.Context) Repository {
	if scope := TenantScopeFromContext(ctx); scope != nil && scope.Repo != nil {
		return scope.Repo
	}
	return s.defaultRepo
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
// Routes through the Repository interface (which every backend
// implements fully) rather than the low-level DB.GetNode/ExecuteAtomic
// pair (which the memory backend stubs out as ErrServiceUnavailable).
func (s *ProfileService) UpdateProfile(ctx context.Context, userID, name, avatarURL string) (*User, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	repo := s.repo(ctx)
	if repo == nil {
		return nil, ErrServiceUnavailable
	}

	user, err := repo.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Repository.UpdateUser takes field-name keys (matching the canonical
	// Repository.UpdateUser pattern used by AuthService for OAuth upserts
	// and invitation redemption — every backend implements those keys).
	patch := map[string]any{"updated_at": nowMs()}
	if n := strings.TrimSpace(name); n != "" {
		patch["name"] = n
	}
	if a := strings.TrimSpace(avatarURL); a != "" {
		patch["avatar_url"] = a
	}

	if err := repo.UpdateUser(ctx, userID, patch); err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}

	updated, err := repo.GetUser(ctx, userID)
	if err != nil || updated == nil {
		// Fallback: apply patch on the pre-update snapshot so callers
		// still see their submitted values even if the re-fetch races.
		if n := strings.TrimSpace(name); n != "" {
			user.Name = n
		}
		if a := strings.TrimSpace(avatarURL); a != "" {
			user.AvatarURL = a
		}
		return user, nil
	}
	return updated, nil
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
