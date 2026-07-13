package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/graph"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ProfileService implements self-service profile, session, passkey,
// password, and audit log operations.
type ProfileService struct {
	bootDB           DB
	defaultRepo      Repository
	defaultProjectID string
	audit            *audit.Logger
	logger           *zap.Logger
	// minorData drops non-essential PII (avatar URL) from a CHILD-band
	// account's profile updates (COPPA data-minimization). Zero-value is a
	// safe no-op, so a caller that omits WithMinorDataMinimizer is unchanged.
	minorData MinorDataMinimizer
	// governance, when set (postgres driver only), is the read-side bundle the
	// per-tenant password policy resolves through, so ChangePassword enforces
	// the same tightened complexity rules the login path does. Nil for drivers
	// without a governance plane, in which case the global baseline applies.
	governance *LoginGovernance

	// accountDeletionGraceDays is the self-service deletion grace window (days)
	// DeleteMyAccount schedules the purge after. A non-positive value falls back
	// to DefaultAccountDeletionGraceDays so a misconfiguration can never schedule
	// an immediate (grace-less) purge. Wired from config via
	// WithAccountDeletionGraceDays.
	accountDeletionGraceDays int

	// exportMaxAuditEvents caps how many of the caller's own audit events a
	// self-service data export includes (newest first). A non-positive value
	// falls back to DefaultExportMaxAuditEvents so an export can never trigger
	// an unbounded audit scan. Wired from config via WithExportMaxAuditEvents.
	exportMaxAuditEvents int
}

// NewProfileService creates a ProfileService.
//
// The repo argument may be nil — in that case only the DB-backed paths
// work (Sessions, AuditEvents). Profile/password operations need repo
// to be set; nil triggers ErrServiceUnavailable at call time, the same
// shape the no-persistence stub takes.
func NewProfileService(repo Repository, db DB, projectID string, auditLog *audit.Logger, logger *zap.Logger) *ProfileService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ProfileService{
		bootDB:           db,
		defaultRepo:      repo,
		defaultProjectID: projectID,
		audit:            auditLog,
		logger:           logger,
	}
}

// WithMinorDataMinimizer wires COPPA data-minimization: when active, a
// CHILD-band account's profile updates drop non-essential PII (avatar URL).
// Returns the service for chaining. Off by default (zero-value is a no-op).
func (s *ProfileService) WithMinorDataMinimizer(m MinorDataMinimizer) *ProfileService {
	s.minorData = m
	return s
}

// WithLoginGovernance wires the optional login-governance bundle so
// ChangePassword enforces the owning tenant's password policy (mirrors
// AuthService.WithLoginGovernance). A nil bundle keeps the global baseline.
func (s *ProfileService) WithLoginGovernance(g *LoginGovernance) *ProfileService {
	s.governance = g
	return s
}

// repo returns the Repository bound to the request's project (ADR-0002),
// falling back to the boot-default project when no scope is present.
func (s *ProfileService) repo(ctx context.Context) Repository {
	return scopedRepository(ctx, s.defaultRepo, s.defaultProjectID)
}

// projectID returns the storage shard (project) the request operates under:
// the per-request ProjectScope when present, else the boot default. It is
// the partition argument the graph DB transport keys on (the postgres DB
// ignores it and filters on its WithProject-bound project instead).
func (s *ProfileService) projectID(ctx context.Context) string {
	return requestProjectID(ctx, s.defaultProjectID)
}

// db returns the DB bound to the request's project.
func (s *ProfileService) db(ctx context.Context) DB {
	return scopedDB(ctx, s.bootDB, s.defaultProjectID)
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
	// COPPA data-minimization: an avatar URL is non-essential PII the server
	// refuses to collect/persist for a CHILD-band account. Silently drop it
	// (the rest of the update still applies) when minimization is active.
	// Adults/teens and minimization-off deployments are unaffected.
	minimizeChild := s.minorData.BlocksChild(user.DateOfBirthMs)

	patch := map[string]any{"updated_at": nowMs()}
	if n := strings.TrimSpace(name); n != "" {
		patch["name"] = n
	}
	if a := strings.TrimSpace(avatarURL); a != "" {
		if minimizeChild {
			s.logger.Info("profile_avatar_dropped_minor", zap.String("user_id", userID))
		} else {
			patch["avatar_url"] = a
		}
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
		if a := strings.TrimSpace(avatarURL); a != "" && !minimizeChild {
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

	nodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), tenantAdminActor, typeRefreshToken,
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

	node, err := s.db(ctx).GetNode(ctx, s.projectID(ctx), tenantAdminActor, typeRefreshToken, sessionID)
	if err != nil {
		return fmt.Errorf("fetch session: %w", err)
	}
	if node == nil {
		return errors.New("session not found")
	}
	if pstr(node.Payload, rfUserID) != userID {
		return errors.New("session does not belong to you")
	}

	op := graph.Operation{Type: graph.OpDeleteNode, TypeID: typeRefreshToken, NodeID: sessionID}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.projectID(ctx), tenantAdminActor, []graph.Operation{op}); err != nil {
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

	userNode, err := s.db(ctx).GetNode(ctx, s.projectID(ctx), actorStr(userID), typeUser, userID)
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

	count, err := s.revokeAllUserSessions(ctx, userID)
	if err != nil {
		return 0, err
	}

	s.audit.Log(
		ctx, audit.EventSessionRevoked,
		audit.WithActor(userID), audit.WithTarget(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"scope": "all", "revoked_count": count}),
	)
	return count, nil
}

// revokeAllUserSessions deletes every refresh-token (session) node owned
// by userID via the graph DB — the same store ListMySessions/RevokeSession
// read and write — and returns the number revoked. Best-effort per
// session: a failed delete is logged and skipped so one bad row does not
// strand the rest. Shared by RevokeAllSessions (explicit sign-out) and
// ChangePassword (credential change forces re-auth everywhere). The
// caller is responsible for any access-control/audit concerns; this
// helper only performs the revocation.
func (s *ProfileService) revokeAllUserSessions(ctx context.Context, userID string) (int, error) {
	nodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), tenantAdminActor, typeRefreshToken,
		map[string]any{rfUserID: userID})
	if err != nil {
		return 0, fmt.Errorf("list sessions: %w", err)
	}

	count := 0
	for _, n := range nodes {
		op := graph.Operation{Type: graph.OpDeleteNode, TypeID: typeRefreshToken, NodeID: n.NodeID}
		if _, err := s.db(ctx).ExecuteAtomic(ctx, s.projectID(ctx), tenantAdminActor, []graph.Operation{op}); err != nil {
			s.logger.Warn("revoke_session_delete_failed", zap.String("session_id", n.NodeID))
			continue
		}
		count++
	}
	return count, nil
}

// ListMyPasskeys returns all passkey credentials for the user.
func (s *ProfileService) ListMyPasskeys(ctx context.Context, userID string) ([]*PasskeyInfo, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	nodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), actorStr(userID), typePasskeyCredCred,
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
	nodes, err := s.db(ctx).QueryNodes(ctx, s.projectID(ctx), actorStr(userID), typePasskeyCredCred,
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

	op := graph.Operation{Type: graph.OpDeleteNode, TypeID: typePasskeyCredCred, NodeID: cred.NodeID}
	if _, err := s.db(ctx).ExecuteAtomic(ctx, s.projectID(ctx), actorStr(userID), []graph.Operation{op}); err != nil {
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
