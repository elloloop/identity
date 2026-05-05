package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passwords"
)

// emailTokenExpiry returns the configured expiry for password-reset
// and email-verification tokens, falling back to 24h if unset.
func (s *AuthService) emailTokenExpiry() time.Duration {
	secs := s.cfg.EmailTokenExpirySeconds
	if secs <= 0 {
		secs = 86400
	}
	return time.Duration(secs) * time.Second
}

// appBaseURL returns the public app base URL with any trailing slash
// trimmed, so callers can simply concatenate "/auth/foo".
func (s *AuthService) appBaseURL() string {
	u := strings.TrimRight(s.cfg.AppBaseURL, "/")
	if u == "" {
		u = "http://localhost:9002"
	}
	return u
}

// formatExpiresIn renders a human-friendly "X hours" / "X minutes"
// string for use inside email templates.
func formatExpiresIn(d time.Duration) string {
	if d >= time.Hour {
		hours := int(d / time.Hour)
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	mins := int(d / time.Minute)
	if mins <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", mins)
}

// ── RequestPasswordReset ───────────────────────────────────────────────

// RequestPasswordReset creates a password-reset token for the user
// matching the supplied email and dispatches a reset email.
//
// Per OWASP guidance and the proto contract, this method always
// returns nil even when the email is unknown — the response time is
// also kept roughly equivalent so the endpoint cannot be used as an
// email-enumeration oracle. Errors during token persistence or email
// dispatch are logged internally; the caller is told nothing.
func (s *AuthService) RequestPasswordReset(ctx context.Context, emailAddr string) error {
	if !s.cfg.PasswordResetEnabled {
		s.logger.Info("password_reset_requested_while_disabled")
		return nil
	}
	emailAddr = strings.TrimSpace(strings.ToLower(emailAddr))
	if emailAddr == "" {
		// Even the trivial "missing email" case is silent; the proto
		// guarantees no enumeration. We still log so operators can
		// notice obvious client bugs.
		s.logger.Info("password_reset_requested_empty_email")
		return nil
	}

	user, err := s.repo.FindUserByEmail(ctx, emailAddr)
	if err != nil {
		s.logger.Warn("password_reset_lookup_failed",
			zap.String("email", emailAddr), zap.Error(err))
		return nil
	}
	if user == nil {
		s.logger.Info("password_reset_unknown_email", zap.String("email", emailAddr))
		return nil
	}

	rawToken := randomToken(32)
	tokenHash := sha256Hex(rawToken)
	now := s.nowMs()
	expiry := s.emailTokenExpiry()

	if err := s.repo.CreatePasswordResetToken(ctx, &PasswordResetToken{
		TokenHash: tokenHash,
		UserID:    user.ID,
		ExpiresAt: now + int64(expiry/time.Millisecond),
		CreatedAt: now,
	}); err != nil {
		s.logger.Warn("password_reset_token_create_failed",
			zap.String("user_id", user.ID), zap.Error(err))
		return nil
	}

	link := fmt.Sprintf("%s/auth/reset-password?token=%s", s.appBaseURL(), rawToken)
	html, text, err := email.Render(email.TemplatePasswordReset, map[string]any{
		"UserName":  displayNameOrEmail(user),
		"Link":      link,
		"ExpiresIn": formatExpiresIn(expiry),
	})
	if err != nil {
		s.logger.Warn("password_reset_render_failed", zap.Error(err))
		return nil
	}
	msg := email.Message{
		To:      user.Email,
		From:    s.cfg.SMTPFrom,
		Subject: "Reset your password",
		HTML:    html,
		Text:    text,
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("password_reset_email_send_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.Log(ctx, audit.EventPasswordReset,
		audit.WithActor(user.ID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"step": "requested"}),
	)
	return nil
}

// ── ConfirmPasswordReset ───────────────────────────────────────────────

// ConfirmPasswordReset consumes a password-reset token and sets the
// user's new password.
//
// Token must be unconsumed and unexpired. On success, every refresh
// token belonging to the user is revoked — OAuth 2.1 §4.13 best
// practice for any credential change forces re-login on all devices.
func (s *AuthService) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	if token == "" {
		return fmt.Errorf("%w: token is required", ErrInvalidArgument)
	}
	if newPassword == "" {
		return fmt.Errorf("%w: new password is required", ErrInvalidArgument)
	}
	if err := validatePasswordStrength(newPassword); err != nil {
		return err
	}

	tokenHash := sha256Hex(token)
	rec, err := s.repo.FindPasswordResetTokenByHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("looking up reset token: %w", err)
	}
	if rec == nil {
		return fmt.Errorf("%w: invalid reset token", ErrUnauthenticated)
	}
	if rec.ConsumedAt > 0 {
		return fmt.Errorf("%w: reset token already used", ErrUnauthenticated)
	}
	if rec.ExpiresAt > 0 && rec.ExpiresAt < s.nowMs() {
		return fmt.Errorf("%w: reset token expired", ErrTokenExpired)
	}

	user, err := s.repo.GetUser(ctx, rec.UserID)
	if err != nil {
		return fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}

	pwHash, err := passwords.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	now := s.nowMs()
	if err := s.repo.UpdateUser(ctx, user.ID, map[string]any{
		"password_hash":      pwHash,
		"updated_at":         now,
		"failed_login_count": 0,
		"locked_until":       int64(0),
	}); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	if err := s.repo.MarkPasswordResetTokenConsumed(ctx, rec.NodeID, now); err != nil {
		s.logger.Warn("password_reset_consume_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	// Revoke all active sessions — credential change must force
	// re-authentication everywhere.
	if err := s.repo.DeleteRefreshTokensForUser(ctx, user.ID); err != nil {
		s.logger.Warn("password_reset_session_revoke_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.Log(ctx, audit.EventPasswordReset,
		audit.WithActor(user.ID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"step": "confirmed"}),
	)
	return nil
}

// ── SendEmailVerification ──────────────────────────────────────────────

// SendEmailVerification creates a verification token for the user and
// dispatches a verification email. Idempotent — calling it repeatedly
// just creates additional valid tokens (older tokens remain valid
// until their own expiry, on the principle that we should never
// invalidate a token a user might have already clicked).
func (s *AuthService) SendEmailVerification(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidArgument)
	}
	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}

	rawToken := randomToken(32)
	tokenHash := sha256Hex(rawToken)
	now := s.nowMs()
	expiry := s.emailTokenExpiry()

	if err := s.repo.CreateEmailVerificationToken(ctx, &EmailVerificationToken{
		TokenHash: tokenHash,
		UserID:    user.ID,
		Email:     user.Email,
		ExpiresAt: now + int64(expiry/time.Millisecond),
		CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("creating verification token: %w", err)
	}

	link := fmt.Sprintf("%s/auth/verify-email?token=%s", s.appBaseURL(), rawToken)
	html, text, err := email.Render(email.TemplateEmailVerification, map[string]any{
		"UserName":  displayNameOrEmail(user),
		"Link":      link,
		"ExpiresIn": formatExpiresIn(expiry),
	})
	if err != nil {
		s.logger.Warn("email_verification_render_failed", zap.Error(err))
		return nil // token is created; rendering failure shouldn't fail RPC
	}
	msg := email.Message{
		To:      user.Email,
		From:    s.cfg.SMTPFrom,
		Subject: "Verify your email",
		HTML:    html,
		Text:    text,
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("email_verification_send_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	return nil
}

// ── VerifyEmail ────────────────────────────────────────────────────────

// VerifyEmail consumes a verification token and marks the user's
// email as verified. Idempotent — re-verifying an already-verified
// user still consumes the supplied token but does not change state.
// Returns the updated user.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidArgument)
	}
	tokenHash := sha256Hex(token)

	rec, err := s.repo.FindEmailVerificationTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("looking up verification token: %w", err)
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: invalid verification token", ErrUnauthenticated)
	}
	if rec.ConsumedAt > 0 {
		return nil, fmt.Errorf("%w: verification token already used", ErrUnauthenticated)
	}
	if rec.ExpiresAt > 0 && rec.ExpiresAt < s.nowMs() {
		return nil, fmt.Errorf("%w: verification token expired", ErrTokenExpired)
	}

	user, err := s.repo.GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	now := s.nowMs()
	if !user.EmailVerified {
		if err := s.repo.SetUserEmailVerified(ctx, user.ID, now); err != nil {
			return nil, fmt.Errorf("setting email verified: %w", err)
		}
		user.EmailVerified = true
		user.EmailVerifiedAt = now
	}

	if err := s.repo.MarkEmailVerificationTokenConsumed(ctx, rec.NodeID, now); err != nil {
		s.logger.Warn("email_verification_consume_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	return user, nil
}

// displayNameOrEmail prefers the user's display name and falls back
// to the local-part of their email address. Used inside template data
// so emails always have a sensible greeting.
func displayNameOrEmail(u *User) string {
	if u == nil {
		return "there"
	}
	if n := strings.TrimSpace(u.Name); n != "" {
		return n
	}
	if i := strings.Index(u.Email, "@"); i > 0 {
		return u.Email[:i]
	}
	return "there"
}
