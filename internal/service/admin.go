package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passwords"
)

// AdminService implements admin user-management operations.
// All methods verify that the acting user has role=admin.
type AdminService struct {
	db              DB
	defaultTenantID string
	audit           *audit.Logger
	cfg             *config.Config
	mailer          email.Transport
	logger          *zap.Logger
}

// NewAdminService creates an AdminService.
//
// mailer may be nil; if nil, a log-only transport is substituted so
// invitation emails are at least visible in the logs during local dev.
// Email-side-effect failures never block the surrounding RPC.
func NewAdminService(db DB, tenantID string, auditLog *audit.Logger, cfg *config.Config, mailer email.Transport, logger *zap.Logger) *AdminService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if mailer == nil {
		mailer = email.NewLogOnly(logger)
	}
	return &AdminService{db: db, defaultTenantID: tenantID, audit: auditLog, cfg: cfg, mailer: mailer, logger: logger}
}

// tenantID returns the request's resolved tenant, falling back to the
// boot-time DefaultTenantID in mode=single (decision log §1). The DB
// interface takes the tenant per call, so admin operations need only the
// resolved id — no per-tenant DB handle.
func (s *AdminService) tenantID(ctx context.Context) string {
	if scope := TenantScopeFromContext(ctx); scope != nil && scope.TenantID != "" {
		return scope.TenantID
	}
	return s.defaultTenantID
}

func requireAdminActor(ctx context.Context, db DB, tenantID, actorID string) (*User, error) {
	node, err := db.GetNode(ctx, tenantID, actorStr(actorID), typeUser, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch actor: %w", err)
	}
	if node == nil {
		return nil, errors.New("actor user not found")
	}
	u := userFromNode(node)
	if strings.ToLower(u.Role) != "admin" {
		return nil, errors.New("admin role required")
	}
	return u, nil
}

// requireAdmin fetches the actor's user node and checks role=admin.
func (s *AdminService) requireAdmin(ctx context.Context, actorID string) (*User, error) {
	return requireAdminActor(ctx, s.db, s.tenantID(ctx), actorID)
}

// InviteUser creates a new user (invited or immediately active) and
// returns the user, an invitation token, setup URL, and optional
// temporary password.
func (s *AdminService) InviteUser(
	ctx context.Context,
	actorID, email, name, role, recoveryEmail string,
	quotaBytes int64, createImmediately bool,
) (*InviteResult, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, errors.New("valid email is required")
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		role = "member"
	}
	if role != "admin" && role != "member" && role != "guest" {
		return nil, errors.New("role must be admin|member|guest")
	}
	if name == "" {
		name = strings.Split(email, "@")[0]
	}

	// Check duplicate.
	existing, err := s.db.QueryNodes(ctx, s.tenantID(ctx), tenantAdminActor, typeUser, map[string]any{ufEmail: email})
	if err != nil {
		return nil, fmt.Errorf("duplicate check failed: %w", err)
	}
	if len(existing) > 0 {
		return nil, errors.New("a user with this email already exists")
	}

	now := nowMs()
	userData := map[string]any{
		ufEmail:         email,
		ufName:          strings.TrimSpace(name),
		ufAvatarURL:     "",
		ufRole:          role,
		ufRecoveryEmail: strings.TrimSpace(strings.ToLower(recoveryEmail)),
		ufQuotaBytes:    quotaBytes,
		ufInvitedBy:     actorID,
		ufInvitedAt:     now,
		ufCreatedAt:     now,
		ufUpdatedAt:     now,
	}

	tempPassword := ""
	if createImmediately {
		tempPassword = generateTempPassword()
		hash, err := passwords.Hash(tempPassword)
		if err != nil {
			return nil, fmt.Errorf("hash temp password: %w", err)
		}
		userData[ufPasswordHash] = hash
		userData[ufStatus] = "active"
	} else {
		userData[ufStatus] = "invited"
	}

	// Create user node.
	userOp := entdb.Operation{Type: entdb.OpCreateNode, TypeID: typeUser, Data: userData}
	result, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), tenantAdminActor, []entdb.Operation{userOp})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	userID := ""
	if len(result.CreatedNodeIDs) > 0 {
		userID = result.CreatedNodeIDs[0]
	}

	// tenant-shard-db v1.12+ requires every actor to be a registered
	// user AND a tenant member before they can issue tenant-scoped
	// writes of their own. The invitee's user node lives in the
	// tenant scope here, but on accept-invitation flows they need to
	// pass the `user:<id>` actor check on reads/writes of their own
	// data — that requires the registration step on top of the tenant
	// row create. No-op on drivers without a separate global registry
	// (postgres, in-memory fakes).
	if userID != "" {
		if err := s.db.RegisterUserInTenant(ctx, s.tenantID(ctx), userID, email, name, role); err != nil {
			return nil, fmt.Errorf("register invited user: %w", err)
		}
	}

	// Create invitation node.
	rawToken := randomToken(32)
	tokenHash := sha256Hex(rawToken)
	invData := map[string]any{
		invTokenHash: tokenHash,
		invEmail:     email,
		invUserID:    userID,
		invInvitedBy: actorID,
		invRole:      role,
		invExpiresAt: now + 7*24*3600*1000,
		invCreatedAt: now,
	}
	invOp := entdb.Operation{Type: entdb.OpCreateNode, TypeID: typeUserInvitation, Data: invData}
	_, err = s.db.ExecuteAtomic(ctx, s.tenantID(ctx), tenantAdminActor, []entdb.Operation{invOp})
	if err != nil {
		return nil, fmt.Errorf("create invitation: %w", err)
	}

	baseURL := strings.TrimRight(s.cfg.AppBaseURL, "/")
	if baseURL == "" {
		baseURL = "https://app.glassa.work"
	}
	setupURL := fmt.Sprintf("%s/auth/accept-invitation?token=%s", baseURL, rawToken)

	// Best-effort: render and send the invitation email. Failures here
	// never fail the RPC — the admin still gets the token in the
	// response and can hand it off out-of-band.
	s.sendInvitationEmail(ctx, email, name, role, setupURL)

	s.audit.Log(
		ctx, audit.EventUserInvited,
		audit.WithActor(actorID), audit.WithTarget(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"email": email, "role": role}),
	)

	status := "invited"
	if createImmediately {
		status = "active"
	}
	nowTime := time.UnixMilli(now)
	user := &User{
		ID: userID, Email: email, Name: strings.TrimSpace(name),
		Role: role, Status: status,
		RecoveryEmail: strings.TrimSpace(strings.ToLower(recoveryEmail)),
		QuotaBytes:    quotaBytes, CreatedAt: nowTime, UpdatedAt: nowTime,
	}
	return &InviteResult{
		User: user, InvitationToken: rawToken,
		SetupURL: setupURL, TemporaryPassword: tempPassword,
	}, nil
}

// DeactivateUser marks a user as deactivated and revokes sessions.
func (s *AdminService) DeactivateUser(ctx context.Context, actorID, targetUserID, reason string) error {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if targetUserID == "" {
		return errors.New("user_id is required")
	}
	if targetUserID == actorID {
		return errors.New("admins cannot deactivate themselves")
	}

	node, err := s.db.GetNode(ctx, s.tenantID(ctx), actorStr(targetUserID), typeUser, targetUserID)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}
	if node == nil {
		return errors.New("user not found")
	}

	now := nowMs()
	op := entdb.Operation{
		Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: targetUserID,
		Patch: map[string]any{ufStatus: "deactivated", ufDeactivatedAt: now, ufUpdatedAt: now},
	}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("deactivate user: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventUserDeactivated,
		audit.WithActor(actorID), audit.WithTarget(targetUserID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"reason": reason}),
	)
	return nil
}

// ReactivateUser sets a deactivated user back to active.
func (s *AdminService) ReactivateUser(ctx context.Context, actorID, targetUserID string) error {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if targetUserID == "" {
		return errors.New("user_id is required")
	}

	node, err := s.db.GetNode(ctx, s.tenantID(ctx), actorStr(targetUserID), typeUser, targetUserID)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}
	if node == nil {
		return errors.New("user not found")
	}

	now := nowMs()
	op := entdb.Operation{
		Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: targetUserID,
		Patch: map[string]any{ufStatus: "active", ufDeactivatedAt: int64(0), ufUpdatedAt: now},
	}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("reactivate user: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventUserReactivated,
		audit.WithActor(actorID), audit.WithTarget(targetUserID), audit.WithSuccess(true),
	)
	return nil
}

// ResetUserPassword generates a temp password or reset token for a user.
func (s *AdminService) ResetUserPassword(
	ctx context.Context, actorID, targetUserID string, generateTemp bool,
) (*ResetPasswordResult, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if targetUserID == "" {
		return nil, errors.New("user_id is required")
	}

	node, err := s.db.GetNode(ctx, s.tenantID(ctx), actorStr(targetUserID), typeUser, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	if node == nil {
		return nil, errors.New("user not found")
	}

	now := nowMs()
	res := &ResetPasswordResult{}

	if generateTemp {
		tempPw := generateTempPassword()
		hash, err := passwords.Hash(tempPw)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
		op := entdb.Operation{
			Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: targetUserID,
			Patch: map[string]any{ufPasswordHash: hash, ufUpdatedAt: now},
		}
		if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), actorStr(actorID), []entdb.Operation{op}); err != nil {
			return nil, fmt.Errorf("set temp password: %w", err)
		}
		res.TemporaryPassword = tempPw
	} else {
		rawToken := randomToken(32)
		tokenHash := sha256Hex(rawToken)
		op := entdb.Operation{
			Type: entdb.OpCreateNode, TypeID: typePasswordReset,
			Data: map[string]any{
				prfTokenHash: tokenHash, prfUserID: targetUserID,
				prfExpiresAt: now + int64(s.cfg.PasswordResetExpirySeconds)*1000,
				prfCreatedAt: now,
			},
		}
		if _, err := s.db.ExecuteAtomic(ctx, s.tenantID(ctx), tenantAdminActor, []entdb.Operation{op}); err != nil {
			return nil, fmt.Errorf("create reset token: %w", err)
		}
		res.ResetToken = rawToken
	}

	method := "reset_token"
	if generateTemp {
		method = "temp_password"
	}
	s.audit.Log(ctx, audit.EventAdminResetPassword,
		audit.WithActor(actorID), audit.WithTarget(targetUserID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": method}))
	return res, nil
}

// sendInvitationEmail renders and sends an invitation email. Failures
// are logged but never propagated — the admin always gets the
// invitation token back in the RPC response, so an email outage cannot
// strand a user.
func (s *AdminService) sendInvitationEmail(ctx context.Context, to, name, role, link string) {
	html, text, err := email.Render(email.TemplateInvitation, map[string]any{
		"UserName":    name,
		"InviterName": "An administrator",
		"OrgName":     s.cfg.TOTPIssuer,
		"Role":        role,
		"Link":        link,
	})
	if err != nil {
		s.logger.Warn("invitation_email_render_failed", zap.String("to", redactEmail(to)), zap.Error(err))
		return
	}
	msg := email.Message{
		To:      to,
		From:    s.cfg.SMTPFrom,
		Subject: "You're invited to " + s.cfg.TOTPIssuer,
		HTML:    html,
		Text:    text,
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("invitation_email_send_failed", zap.String("to", redactEmail(to)), zap.Error(err))
	}
}
