package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/emailaddr"
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

// appBaseURL returns the public app base URL for the request's project,
// with any trailing slash trimmed, so callers can simply concatenate
// "/auth/foo". When the request resolved to a project with a primary
// auth-domain, links are built on that branded hostname
// (https://<primary-auth-domain>) so a user sees a URL on the product's
// own domain. Otherwise it falls back to the configured GATEWAY_APP_BASE_URL
// (or a localhost dev default). Every emailed link that is not a reset or
// verification link (those honour GATEWAY_EMAIL_LINK_BASE_URL first) is built
// on it: magic links, email-change confirmations and both kinds of invitation.
func appBaseURL(ctx context.Context, cfg *config.Config) string {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.PrimaryAuthDomain != "" {
		return "https://" + scope.PrimaryAuthDomain
	}
	if cfg != nil {
		if u := strings.TrimRight(cfg.AppBaseURL, "/"); u != "" {
			return u
		}
	}
	return "http://localhost:9002"
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
// matching the supplied email and dispatches a reset email whose link
// carries the admitted params (see checkEmailLinkParams).
//
// Per OWASP guidance and the proto contract, every account-dependent
// outcome returns nil — an unknown email included — and the account is
// looked up and mailed through dispatchEmailSend, so neither the answer nor
// (with async dispatch) its timing is an email-enumeration oracle. Errors
// during token persistence or email dispatch are logged internally; the
// caller is told nothing. The one
// error it returns is ErrInvalidArgument for refused link params, which
// are checked first and from the request alone, so that answer is the
// same for every email.
func (s *AuthService) RequestPasswordReset(ctx context.Context, emailAddr string, params EmailLinkParams) error {
	link, err := s.checkEmailLinkParams(params)
	if err != nil {
		return err
	}
	if !s.cfg.PasswordResetEnabled {
		s.logger.Info("password_reset_requested_while_disabled")
		return nil
	}
	// Canonicalize to the key accounts are stored under (gmail dot/+ stripping,
	// IDN punycode) so a reset request with non-canonical casing/dots finds the
	// account instead of silently reporting "unknown email".
	emailAddr, usable := emailaddr.Mailbox(emailAddr)
	if !usable {
		// Even the trivial "missing email" case is silent; the proto
		// guarantees no enumeration. We still log so operators can
		// notice obvious client bugs.
		s.logger.Info("password_reset_requested_unusable_email")
		return nil
	}
	// Everything that depends on the account runs off the request, so the
	// response takes the same time whether or not a reset is mailed.
	s.dispatchEmailSend(ctx, "password_reset", func(ctx context.Context) {
		s.sendPasswordResetNow(ctx, emailAddr, link)
	})
	return nil
}

// sendPasswordResetNow is the body of RequestPasswordReset's dispatch: it
// finds the account, mints its reset token and mails the link. Silent — every
// outcome is logged, never surfaced.
func (s *AuthService) sendPasswordResetNow(ctx context.Context, emailAddr string, link emailLink) {
	user, err := s.repo(ctx).FindUserByEmail(ctx, emailAddr)
	if err != nil {
		s.logger.Warn("password_reset_lookup_failed",
			zap.String("email", redactEmail(emailAddr)), zap.Error(err))
		return
	}
	// A reset mail to an address the project refuses is spam the project pays
	// for: the account it would restore cannot log in anyway, and the message
	// tells its recipient the project knows them. Evaluated here rather than
	// before the lookup so it reuses that result — accessAllowsCodeSend would
	// run its own existence query for invite mode, and this path has already
	// paid for one. Login context (isSignup=false), since the account exists.
	// Silent, like every other refusal on this path: a fail-fast would turn the
	// RPC into an enumeration oracle, which the proto guarantees it is not.
	if scope := ProjectScopeFromContext(ctx); scope != nil && user != nil &&
		!accessPermits(s.cfg, scope.Access, canonicalize(emailAddr), false) {
		s.logger.Info("password_reset_send_suppressed_by_access",
			zap.String("email", redactEmail(emailAddr)))
		return
	}

	if user == nil {
		s.logger.Info("password_reset_unknown_email", zap.String("email", redactEmail(emailAddr)))
		return
	}

	if !s.emailThrottle.allow(emailAddr, s.nowMs()) {
		s.logger.Info("password_reset_throttled", zap.String("email", redactEmail(emailAddr)))
		return
	}

	rawToken := randomToken(32)
	tokenHash := sha256Hex(rawToken)
	now := s.nowMs()
	expiry := s.emailTokenExpiry()

	if err := s.repo(ctx).CreatePasswordResetToken(ctx, &PasswordResetToken{
		TokenHash: tokenHash,
		UserID:    user.ID,
		Email:     user.Email,
		ExpiresAt: now + int64(expiry/time.Millisecond),
		CreatedAt: now,
	}); err != nil {
		s.logger.Warn("password_reset_token_create_failed",
			zap.String("user_id", user.ID), zap.Error(err))
		return
	}

	brand := resolveBranding(ctx, s.cfg, link.product)
	html, text, err := email.Render(email.TemplatePasswordReset, brand.templateData(map[string]any{
		"UserName":  displayNameOrEmail(user),
		"Link":      s.emailLinkURL(ctx, emailLinkPageResetPassword, rawToken, link),
		"ExpiresIn": formatExpiresIn(expiry),
	}))
	if err != nil {
		s.logger.Warn("password_reset_render_failed", zap.Error(err))
		return
	}
	msg := email.Message{
		To:      user.Email,
		From:    s.cfg.SMTPFrom,
		Subject: "Reset your password",
		HTML:    html,
		Text:    text,
	}
	brand.applyTo(&msg)
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("password_reset_email_send_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.Log(
		ctx, audit.EventPasswordReset,
		audit.WithActor(user.ID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"step": "requested"}),
	)
}

// resetTokenBindsAddress reports whether the account still holds the address
// a reset token was issued for. An account without an address (a username
// account an admin reset) is matched only by a token issued without one.
func resetTokenBindsAddress(issuedFor, current string) bool {
	if current == "" {
		return issuedFor == ""
	}
	return ProofCarriesTo(issuedFor, current)
}

// ── ConfirmPasswordReset ───────────────────────────────────────────────

// ConfirmPasswordReset consumes a password-reset token and sets the
// user's new password.
//
// Token must be unconsumed and unexpired, and the account must still hold
// the address the token was issued for: whoever keeps a mailbox the account
// has moved away from must not keep a way in. That refusal reads as an
// invalid token and spends it. On success, every refresh
// token belonging to the user is revoked — OAuth 2.1 §4.13 best
// practice for any credential change forces re-login on all devices.
func (s *AuthService) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	if token == "" {
		return fmt.Errorf("%w: token is required", ErrInvalidArgument)
	}
	if newPassword == "" {
		return fmt.Errorf("%w: new password is required", ErrInvalidArgument)
	}
	// Global baseline check up front (before any token lookup); the
	// tenant-specific tightening runs once the owning user is resolved.
	if err := validatePasswordStrength(newPassword); err != nil {
		return err
	}

	tokenHash := sha256Hex(token)
	rec, err := s.repo(ctx).FindPasswordResetTokenByHash(ctx, tokenHash)
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

	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if !resetTokenBindsAddress(rec.Email, user.Email) {
		if err := s.repo(ctx).MarkPasswordResetTokenConsumed(ctx, rec.NodeID, s.nowMs()); err != nil {
			s.logger.Warn("password_reset_consume_failed",
				zap.String("user_id", user.ID), zap.Error(err))
		}
		s.logger.Info("password_reset_address_changed", zap.String("user_id", user.ID))
		return fmt.Errorf("%w: invalid reset token", ErrUnauthenticated)
	}

	// Enforce the user's tenant password policy now that the owning user
	// (and thus its email domain) is known.
	if err := s.validatePasswordStrengthForEmail(ctx, user.Email, newPassword); err != nil {
		return err
	}

	pwHash, err := passwords.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	now := s.nowMs()
	if err := s.repo(ctx).UpdateUser(ctx, user.ID, map[string]any{
		"password_hash":            pwHash,
		"password_change_required": false,
		"updated_at":               now,
		"failed_login_count":       0,
		"locked_until":             int64(0),
	}); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	if err := s.repo(ctx).MarkPasswordResetTokenConsumed(ctx, rec.NodeID, now); err != nil {
		s.logger.Warn("password_reset_consume_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	// Revoke all active sessions — credential change must force
	// re-authentication everywhere. In mode=session we also revoke
	// the Session rows so the in-flight access tokens stop working
	// immediately.
	if err := s.repo(ctx).DeleteRefreshTokensForUser(ctx, user.ID); err != nil {
		s.logger.Warn("password_reset_session_revoke_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	s.revokeUserSessionsIfModeSession(ctx, user.ID, "password_reset")

	s.audit.Log(
		ctx, audit.EventPasswordReset,
		audit.WithActor(user.ID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"step": "confirmed"}),
	)
	return nil
}

// ── SendEmailVerification ──────────────────────────────────────────────

// SendEmailVerification creates a verification token for the user and
// dispatches a verification email whose link carries the admitted params
// (see checkEmailLinkParams; refused params are ErrInvalidArgument).
// Idempotent — calling it repeatedly just creates additional valid tokens
// (older tokens remain valid until their own expiry, on the principle that
// we should never invalidate a token a user might have already clicked).
func (s *AuthService) SendEmailVerification(ctx context.Context, userID string, params EmailLinkParams) error {
	link, err := s.checkEmailLinkParams(params)
	if err != nil {
		return err
	}
	return s.sendEmailVerification(ctx, userID, link)
}

// sendEmailVerification is SendEmailVerification for a link that has already
// been checked; a resend the server initiates itself passes the zero link.
func (s *AuthService) sendEmailVerification(ctx context.Context, userID string, link emailLink) error {
	if userID == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidArgument)
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}

	if !s.emailThrottle.allow(strings.ToLower(user.Email), s.nowMs()) {
		s.logger.Info("email_verification_throttled", zap.String("user_id", user.ID))
		return nil
	}

	rawToken := randomToken(32)
	tokenHash := sha256Hex(rawToken)
	now := s.nowMs()
	expiry := s.emailTokenExpiry()

	if err := s.repo(ctx).CreateEmailVerificationToken(ctx, &EmailVerificationToken{
		TokenHash: tokenHash,
		UserID:    user.ID,
		Email:     user.Email,
		ExpiresAt: now + int64(expiry/time.Millisecond),
		CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("creating verification token: %w", err)
	}

	brand := resolveBranding(ctx, s.cfg, link.product)
	html, text, err := email.Render(email.TemplateEmailVerification, brand.templateData(map[string]any{
		"UserName":  displayNameOrEmail(user),
		"Link":      s.emailLinkURL(ctx, emailLinkPageVerifyEmail, rawToken, link),
		"ExpiresIn": formatExpiresIn(expiry),
	}))
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
	brand.applyTo(&msg)
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("email_verification_send_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	return nil
}

// ── VerifyEmail ────────────────────────────────────────────────────────

// VerifyEmail consumes a verification token and marks the user's
// email as verified, voiding what was added before it on an account a
// provider claimed (addressClaimedByProvider). Idempotent — re-verifying an already-verified
// user still consumes the supplied token but does not change state.
// The token proves only the address it was mailed to: once the account
// holds another address it is refused (and consumed). Returns the
// updated user.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidArgument)
	}
	tokenHash := sha256Hex(token)

	rec, err := s.repo(ctx).FindEmailVerificationTokenByHash(ctx, tokenHash)
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

	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	now := s.nowMs()
	proven := ProofCarriesTo(rec.Email, user.Email)
	if proven && !user.EmailVerified {
		proof := externalProof{address: rec.Email, method: "verification_link", keepsAssertingLinks: true}
		claimed, err := s.addressClaimedByProvider(ctx, user)
		if err != nil {
			return nil, s.externalProofSweepFailed(user.ID, proof, "list_provider_links", err)
		}
		if claimed {
			if err := s.markEmailVerifiedViaExternalProof(ctx, user, proof, now); err != nil {
				return nil, err
			}
			proven = user.EmailVerified
		} else if proven, err = s.repo(ctx).SetUserEmailVerified(ctx, user.ID, user.Email, now, false); err != nil {
			return nil, fmt.Errorf("setting email verified: %w", err)
		}
	}
	if !proven {
		if err := s.repo(ctx).MarkEmailVerificationTokenConsumed(ctx, rec.NodeID, now); err != nil {
			s.logger.Warn("email_verification_consume_failed",
				zap.String("user_id", user.ID), zap.Error(err))
		}
		s.logger.Info("email_verification_address_changed", zap.String("user_id", user.ID))
		return nil, fmt.Errorf("%w: verification token was sent to another address", ErrUnauthenticated)
	}
	if !user.EmailVerified {
		user.EmailVerified = true
		user.EmailVerifiedAt = now
	}

	if err := s.repo(ctx).MarkEmailVerificationTokenConsumed(ctx, rec.NodeID, now); err != nil {
		s.logger.Warn("email_verification_consume_failed",
			zap.String("user_id", user.ID), zap.Error(err))
	}
	return user, nil
}

// addressClaimedByProvider reports whether a provider link on the account
// asserted a spelling of its address that does not prove it: a +tag outside
// Gmail. Such an account is held unverified because its claim to the address
// came from that provider, so whoever holds it may not own the mailbox, and
// a verification link its owner redeems voids what was added before, as a
// sign-in proof does. Any other account keeps its credentials: the link
// completes the sign-up that set them.
func (s *AuthService) addressClaimedByProvider(ctx context.Context, user *User) (bool, error) {
	links, err := s.repo(ctx).ListOAuthIdentitiesForUser(ctx, user.ID)
	if err != nil {
		return false, err
	}
	for _, link := range links {
		asserted, _ := canonicalMailbox(link.EmailAtLinkTime)
		if string(asserted) == user.Email && !ProofCarriesTo(link.EmailAtLinkTime, user.Email) {
			return true, nil
		}
	}
	return false, nil
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
