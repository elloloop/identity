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

// ── RequestEmailChange ─────────────────────────────────────────────────

// RequestEmailChange initiates a primary-email rotation for the user.
//
// The caller must re-authenticate with their current password (OAuth 2.1
// best practice for any high-value credential change). The new address is
// validated and checked for uniqueness; an EmailChangeToken is created
// and two emails are dispatched:
//
//   - to the NEW address: a verification link the user must click to
//     complete the change.
//   - to the OLD address: a security notice informing the user that a
//     change has been requested.
//
// The email swap does NOT take effect until ConfirmEmailChange consumes
// the token. If another user claims the new_email between this call and
// the confirm call, the confirm call will fail with ErrAlreadyExists
// (last-write-wins is rejected — the contended new_email is still owned
// by the other user, so we cannot reassign it).
func (s *AuthService) RequestEmailChange(ctx context.Context, userID, newEmail, currentPassword string) error {
	if userID == "" {
		return fmt.Errorf("%w: user id is required", ErrUnauthenticated)
	}
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))
	if newEmail == "" {
		return fmt.Errorf("%w: new email is required", ErrInvalidArgument)
	}
	if !looksLikeEmail(newEmail) {
		return fmt.Errorf("%w: new email is not a valid address", ErrInvalidArgument)
	}
	if currentPassword == "" {
		return fmt.Errorf("%w: current password is required", ErrInvalidArgument)
	}

	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if user.PasswordHash == "" || !passwords.Verify(currentPassword, user.PasswordHash) {
		s.audit.Log(
			ctx, audit.EventPasswordChanged,
			audit.WithActor(userID), audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"step": "email_change_reauth"}),
		)
		return fmt.Errorf("%w: invalid password", ErrUnauthenticated)
	}

	// Reject if new == current (case-insensitively). Avoids creating a
	// pointless token + emails.
	if strings.EqualFold(strings.TrimSpace(user.Email), newEmail) {
		return fmt.Errorf("%w: new email matches current email", ErrInvalidArgument)
	}

	existing, err := s.repo.FindUserByEmail(ctx, newEmail)
	if err != nil {
		return fmt.Errorf("checking email uniqueness: %w", err)
	}
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("%w: email already in use", ErrAlreadyExists)
	}

	rawToken := randomToken(32)
	tokenHash := sha256Hex(rawToken)
	now := s.nowMs()
	expiry := s.emailTokenExpiry()

	if err := s.repo.CreateEmailChangeToken(ctx, &EmailChangeToken{
		TokenHash: tokenHash,
		UserID:    user.ID,
		OldEmail:  user.Email,
		NewEmail:  newEmail,
		ExpiresAt: now + int64(expiry/time.Millisecond),
		CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("creating email change token: %w", err)
	}

	link := fmt.Sprintf("%s/auth/confirm-email-change?token=%s", s.appBaseURL(), rawToken)
	expiresStr := formatExpiresIn(expiry)

	// Verification email to the NEW address — only here is the token
	// disclosed.
	if html, text, rerr := email.Render(email.TemplateEmailChangeVerify, map[string]any{
		"UserName":  displayNameOrEmail(user),
		"NewEmail":  newEmail,
		"OldEmail":  user.Email,
		"Link":      link,
		"ExpiresIn": expiresStr,
	}); rerr != nil {
		s.logger.Warn("email_change_verify_render_failed", zap.Error(rerr))
	} else {
		msg := email.Message{
			To:      newEmail,
			From:    s.cfg.SMTPFrom,
			Subject: "Confirm your new email address",
			HTML:    html,
			Text:    text,
		}
		if err := s.mailer.Send(ctx, msg); err != nil {
			s.logger.Warn("email_change_verify_send_failed",
				zap.String("user_id", user.ID), zap.Error(err))
		}
	}

	// Security notice to the OLD address — never contains the token.
	if user.Email != "" {
		if html, text, rerr := email.Render(email.TemplateEmailChangeNotice, map[string]any{
			"UserName":  displayNameOrEmail(user),
			"OldEmail":  user.Email,
			"NewEmail":  newEmail,
			"ExpiresIn": expiresStr,
		}); rerr != nil {
			s.logger.Warn("email_change_notice_render_failed", zap.Error(rerr))
		} else {
			msg := email.Message{
				To:      user.Email,
				From:    s.cfg.SMTPFrom,
				Subject: "Your email is being changed",
				HTML:    html,
				Text:    text,
			}
			if err := s.mailer.Send(ctx, msg); err != nil {
				s.logger.Warn("email_change_notice_send_failed",
					zap.String("user_id", user.ID), zap.Error(err))
			}
		}
	}

	s.audit.Log(
		ctx, audit.EventPasswordChanged,
		audit.WithActor(user.ID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"step": "email_change_requested"}),
	)
	return nil
}

// ── ConfirmEmailChange ─────────────────────────────────────────────────

// ConfirmEmailChange consumes a pending EmailChangeToken and swaps the
// user's primary email to the verified new address. Token must be
// unconsumed and unexpired. On success:
//
//   - user.email is updated to new_email
//   - user.email_verified is set to true (verified by clicking the link)
//   - user.email_verified_at is updated
//   - the token is marked consumed
//   - all of the user's refresh tokens are revoked (OAuth 2.1 §4.13:
//     credential changes force re-auth on every device)
//
// If the new address has been claimed by another user since the request,
// returns ErrAlreadyExists — the token is NOT consumed in that case so
// the user can call ConfirmEmailChange again if the conflict resolves
// before the token expires.
func (s *AuthService) ConfirmEmailChange(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidArgument)
	}
	tokenHash := sha256Hex(token)

	rec, err := s.repo.FindEmailChangeTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("looking up email change token: %w", err)
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: invalid email change token", ErrUnauthenticated)
	}
	if rec.ConsumedAt > 0 {
		return nil, fmt.Errorf("%w: email change token already used", ErrUnauthenticated)
	}
	if rec.ExpiresAt > 0 && rec.ExpiresAt < s.nowMs() {
		return nil, fmt.Errorf("%w: email change token expired", ErrTokenExpired)
	}

	user, err := s.repo.GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	existing, err := s.repo.FindUserByEmail(ctx, rec.NewEmail)
	if err != nil {
		return nil, fmt.Errorf("checking email uniqueness: %w", err)
	}
	if existing != nil && existing.ID != user.ID {
		return nil, fmt.Errorf("%w: email already in use", ErrAlreadyExists)
	}

	now := s.nowMs()
	if err := s.repo.UpdateUserEmail(ctx, user.ID, rec.NewEmail, now); err != nil {
		return nil, fmt.Errorf("updating user email: %w", err)
	}

	user.Email = rec.NewEmail
	user.EmailVerified = true
	user.EmailVerifiedAt = now
	user.UpdatedAt = time.UnixMilli(now)

	if err := s.repo.MarkEmailChangeTokenConsumed(ctx, rec.NodeID, now); err != nil {
		s.logger.Warn("email_change_consume_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}

	// Revoke all active sessions — credential change must force re-auth
	// on every device per OAuth 2.1 §4.13.
	if err := s.repo.DeleteRefreshTokensForUser(ctx, user.ID); err != nil {
		s.logger.Warn("email_change_session_revoke_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.Log(
		ctx, audit.EventPasswordChanged,
		audit.WithActor(user.ID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"step":      "email_change_confirmed",
			"old_email": rec.OldEmail,
			"new_email": rec.NewEmail,
		}),
	)
	return user, nil
}

// looksLikeEmail performs a minimal syntactic check on an email
// address. Real validation happens when the user clicks the link in
// the inbox; we just want to reject obviously malformed input early.
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.IndexByte(s[at+1:], '.') < 0 {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return true
}
