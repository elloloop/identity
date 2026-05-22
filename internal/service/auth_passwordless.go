package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
)

// Passwordless email login: prove control of an email with no password,
// via a 6-digit OTP code or a magic link. Both arms resolve-or-create the
// single account keyed by that email (resolveOrCreateUserByEmail), so a
// passwordless login for an address that already has a password / OAuth
// account links to the SAME user — never a duplicate. Accounts are created
// only on verify / redeem, gated by GATEWAY_PASSWORDLESS_SIGNUP_ENABLED.

const (
	emailLoginCodeDigits   = 6
	defaultEmailCodeTTL    = 5 * time.Minute
	defaultMagicLinkTTL    = 15 * time.Minute
	defaultCodeMaxAttempts = 5
)

func (s *AuthService) emailCodeTTL() time.Duration {
	if s.cfg.PasswordlessCodeTTLSeconds > 0 {
		return time.Duration(s.cfg.PasswordlessCodeTTLSeconds) * time.Second
	}
	return defaultEmailCodeTTL
}

func (s *AuthService) emailCodeMaxAttempts() int64 {
	if s.cfg.PasswordlessCodeMaxAttempts > 0 {
		return int64(s.cfg.PasswordlessCodeMaxAttempts)
	}
	return defaultCodeMaxAttempts
}

func (s *AuthService) magicLinkTTL() time.Duration {
	if s.cfg.PasswordlessMagicLinkTTLSeconds > 0 {
		return time.Duration(s.cfg.PasswordlessMagicLinkTTLSeconds) * time.Second
	}
	return defaultMagicLinkTTL
}

// generateEmailLoginCode returns a zero-padded, cryptographically random
// 6-digit decimal code. Uniform across [000000, 999999].
func generateEmailLoginCode() string {
	const max = 1_000_000
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("%0*d", emailLoginCodeDigits, n.Int64())
}

// normalizeEmail lowercases and trims an email and reports whether it is
// minimally well-formed (contains an "@").
func normalizeEmail(raw string) (string, bool) {
	e := strings.TrimSpace(strings.ToLower(raw))
	return e, strings.Contains(e, "@")
}

// ── RequestEmailLoginCode ──────────────────────────────────────────────

// RequestEmailLoginCode mints a 6-digit OTP for the email and dispatches
// it. Anti-enumeration: it always returns nil with no observable
// difference between a known and an unknown address. The account is NOT
// created here — only VerifyEmailLoginCode resolves or creates the user.
func (s *AuthService) RequestEmailLoginCode(ctx context.Context, emailAddr string) error {
	emailAddr, ok := normalizeEmail(emailAddr)
	if !ok {
		// Silent: the proto guarantees no enumeration even for malformed
		// input. Log so operators can spot obvious client bugs.
		s.logger.Info("email_login_code_requested_invalid_email")
		return nil
	}

	// Per-email send cooldown — a single inbox can't be flooded. Reuses
	// the shared transactional-email throttle. A throttled request is
	// silent (same response as success) so the cooldown can't be probed.
	if !s.emailThrottle.allow(emailAddr, s.nowMs()) {
		s.logger.Info("email_login_code_throttled", zap.String("email", redactEmail(emailAddr)))
		return nil
	}

	code := generateEmailLoginCode()
	now := s.nowMs()
	ttl := s.emailCodeTTL()
	if _, err := s.repo(ctx).UpsertEmailLoginCode(ctx, &EmailLoginCodeRecord{
		Email:       emailAddr,
		CodeHash:    sha256Hex(code),
		ExpiresAt:   now + ttl.Milliseconds(),
		CreatedAt:   now,
		MaxAttempts: s.emailCodeMaxAttempts(),
	}); err != nil {
		s.logger.Warn("email_login_code_create_failed",
			zap.String("email", redactEmail(emailAddr)), zap.Error(err))
		return nil
	}

	html, text, err := email.Render(email.TemplateEmailLoginCode, map[string]any{
		"Code":      code,
		"ExpiresIn": formatExpiresIn(ttl),
	})
	if err != nil {
		s.logger.Warn("email_login_code_render_failed", zap.Error(err))
		return nil
	}
	if err := s.mailer.Send(ctx, email.Message{
		To:      emailAddr,
		From:    s.cfg.SMTPFrom,
		Subject: "Your login code",
		HTML:    html,
		Text:    text,
	}); err != nil {
		s.logger.Warn("email_login_code_send_failed",
			zap.String("email", redactEmail(emailAddr)), zap.Error(err))
	}
	s.logger.Info("email_login_code_requested", zap.String("email", redactEmail(emailAddr)))
	return nil
}

// ── VerifyEmailLoginCode ───────────────────────────────────────────────

// VerifyEmailLoginCode validates the OTP, resolves-or-creates the user
// keyed by email, and issues a token pair.
//
// Failure modes (missing/expired/consumed code, wrong code, exhausted
// attempts, and — when auto-create is disabled — an unknown email) all
// collapse to ErrEmailLoginCodeInvalid so the endpoint reveals nothing.
// A wrong guess bumps the per-code attempt counter; once it reaches the
// cap captured at mint time the code is consumed (invalidated) to stop a
// brute-force walk of the 6-digit space.
func (s *AuthService) VerifyEmailLoginCode(ctx context.Context, emailAddr, code string, ipAddr, userAgent string) (*LoginResult, error) {
	emailAddr, ok := normalizeEmail(emailAddr)
	if !ok || strings.TrimSpace(code) == "" {
		return nil, ErrEmailLoginCodeInvalid
	}

	rec, err := s.repo(ctx).FindEmailLoginCodeByEmail(ctx, emailAddr)
	if err != nil {
		return nil, fmt.Errorf("looking up email login code: %w", err)
	}
	if rec == nil || rec.ConsumedAt != 0 || rec.ExpiresAt <= s.nowMs() {
		return nil, ErrEmailLoginCodeInvalid
	}
	if rec.MaxAttempts > 0 && rec.AttemptCount >= rec.MaxAttempts {
		return nil, ErrEmailLoginCodeInvalid
	}

	// Constant-time compare so a timing oracle can't shortcut the guess.
	if subtle.ConstantTimeCompare([]byte(rec.CodeHash), []byte(sha256Hex(code))) != 1 {
		if err := s.repo(ctx).IncrementEmailLoginCodeAttempts(ctx, rec.NodeID); err != nil {
			s.logger.Warn("email_login_code_attempt_increment_failed",
				zap.String("email", redactEmail(emailAddr)), zap.Error(err))
		}
		// At the cap, consume the code so the (now-final) wrong guess
		// burns it — no further attempts against this code are possible.
		if rec.MaxAttempts > 0 && rec.AttemptCount+1 >= rec.MaxAttempts {
			if _, cErr := s.repo(ctx).ConsumeEmailLoginCode(ctx, emailAddr, s.nowMs()); cErr != nil &&
				!errors.Is(cErr, ErrEmailLoginCodeInvalid) {
				s.logger.Warn("email_login_code_lock_failed",
					zap.String("email", redactEmail(emailAddr)), zap.Error(cErr))
			}
		}
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithIP(ipAddr), audit.WithUserAgent(userAgent), audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"method": "email_code", "reason": "code_mismatch"}))
		return nil, ErrEmailLoginCodeInvalid
	}

	// Correct code: consume single-use (CAS) before resolving the user so
	// a replay racing this verify loses.
	if _, err := s.repo(ctx).ConsumeEmailLoginCode(ctx, emailAddr, s.nowMs()); err != nil {
		return nil, ErrEmailLoginCodeInvalid
	}

	return s.completePasswordlessLogin(ctx, emailAddr, "email_code", ipAddr, userAgent)
}

// ── RequestMagicLink ───────────────────────────────────────────────────

// RequestMagicLink mints a single-use magic-link token bound to the email
// and the allowlist-validated return_to, then emails the link. Anti-
// enumeration: identical response regardless of account existence.
//
// return_to is validated against GATEWAY_OAUTH_ALLOWED_RETURN_URLS (shared
// with hosted OAuth). A disallowed return_to is the one hard error the
// caller sees — it is a client misconfiguration, not an account probe, and
// failing closed here prevents an open redirect. An empty allowlist (the
// feature is unconfigured) rejects every return_to the same way.
func (s *AuthService) RequestMagicLink(ctx context.Context, emailAddr, returnTo string) error {
	if !s.returnAllow.Allows(returnTo) {
		s.logger.Info("magic_link_return_to_rejected")
		return fmt.Errorf("%w: return_to is not allowed", ErrInvalidArgument)
	}

	emailAddr, ok := normalizeEmail(emailAddr)
	if !ok {
		s.logger.Info("magic_link_requested_invalid_email")
		return nil
	}

	if !s.emailThrottle.allow(emailAddr, s.nowMs()) {
		s.logger.Info("magic_link_throttled", zap.String("email", redactEmail(emailAddr)))
		return nil
	}

	rawToken := randomToken(32)
	now := s.nowMs()
	ttl := s.magicLinkTTL()
	if _, err := s.repo(ctx).CreateMagicLinkToken(ctx, &MagicLinkTokenRecord{
		TokenHash: sha256Hex(rawToken),
		Email:     emailAddr,
		ReturnTo:  strings.TrimSpace(returnTo),
		ExpiresAt: now + ttl.Milliseconds(),
		CreatedAt: now,
	}); err != nil {
		s.logger.Warn("magic_link_create_failed",
			zap.String("email", redactEmail(emailAddr)), zap.Error(err))
		return nil
	}

	link := fmt.Sprintf("%s/auth/magic-link?token=%s", s.appBaseURL(), rawToken)
	html, text, err := email.Render(email.TemplateMagicLink, map[string]any{
		"Link":      link,
		"ExpiresIn": formatExpiresIn(ttl),
	})
	if err != nil {
		s.logger.Warn("magic_link_render_failed", zap.Error(err))
		return nil
	}
	if err := s.mailer.Send(ctx, email.Message{
		To:      emailAddr,
		From:    s.cfg.SMTPFrom,
		Subject: "Your sign-in link",
		HTML:    html,
		Text:    text,
	}); err != nil {
		s.logger.Warn("magic_link_send_failed",
			zap.String("email", redactEmail(emailAddr)), zap.Error(err))
	}
	s.logger.Info("magic_link_requested", zap.String("email", redactEmail(emailAddr)))
	return nil
}

// ── RedeemMagicLink ────────────────────────────────────────────────────

// MagicLinkResult is a LoginResult plus the allowlist-validated app URL
// the SPA should navigate to after a successful redeem.
type MagicLinkResult struct {
	*LoginResult
	ReturnTo string
}

// RedeemMagicLink consumes the single-use token, resolves-or-creates the
// user keyed by the bound email, and issues a token pair. A replay, an
// expired token, or an unknown token all return ErrMagicLinkInvalid.
func (s *AuthService) RedeemMagicLink(ctx context.Context, token, ipAddr, userAgent string) (*MagicLinkResult, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrMagicLinkInvalid
	}
	rec, err := s.repo(ctx).ConsumeMagicLinkToken(ctx, sha256Hex(token), s.nowMs())
	if err != nil {
		if errors.Is(err, ErrMagicLinkInvalid) {
			return nil, ErrMagicLinkInvalid
		}
		return nil, fmt.Errorf("consuming magic link token: %w", err)
	}

	result, err := s.completePasswordlessLogin(ctx, rec.Email, "magic_link", ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	return &MagicLinkResult{LoginResult: result, ReturnTo: rec.ReturnTo}, nil
}

// completePasswordlessLogin is the shared tail of both passwordless arms
// once email control is proven: gate on the auto-create policy, resolve
// or create the user by email (the unified-account guarantee), enforce
// account status, and issue tokens.
//
// When GATEWAY_PASSWORDLESS_SIGNUP_ENABLED is false and the email has no
// account, the request must look identical to a successful login from the
// outside (anti-enumeration) — but no account exists to authenticate, so
// we return ErrEmailLoginCodeInvalid / ErrMagicLinkInvalid, the same shape
// every other "this didn't work" path returns. The proof-of-control step
// already happened, so this leaks nothing an attacker who controls the
// inbox doesn't already know.
func (s *AuthService) completePasswordlessLogin(ctx context.Context, emailAddr, method, ipAddr, userAgent string) (*LoginResult, error) {
	invalidErr := ErrEmailLoginCodeInvalid
	if method == "magic_link" {
		invalidErr = ErrMagicLinkInvalid
	}

	if !s.cfg.PasswordlessSignupEnabled {
		existing, err := s.repo(ctx).FindUserByEmail(ctx, emailAddr)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			s.logger.Info("passwordless_signup_disabled_unknown_email",
				zap.String("email", redactEmail(emailAddr)), zap.String("method", method))
			return nil, invalidErr
		}
	}

	user, isNew, err := s.resolveOrCreateUserByEmail(ctx, emailAddr, resolveOrCreateOpts{
		emailVerified: true, // proving control of the inbox verifies the email
	})
	if err != nil {
		return nil, err
	}

	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("passwordless_login_success",
		zap.String("email", redactEmail(emailAddr)),
		zap.String("user_id", user.ID),
		zap.String("method", method),
		zap.Bool("new_user", isNew))

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.audit.Log(ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": method, "new_user": isNew}))

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
