package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passwords"
)

// tokenPurposePasswordChange is the JWT `purpose` claim value marking a
// required-password-change ticket. Its only use is
// CompleteRequiredPasswordChange for the ticket's subject; like every purpose
// token it never authenticates a request.
const tokenPurposePasswordChange = "password_change" // #nosec G101 -- a claim value naming the ticket's purpose, not a credential.

// passwordChangeTicketTTL bounds the step: long enough to choose and type a
// password, short enough that a leaked ticket expires within minutes.
const passwordChangeTicketTTL = 10 * time.Minute

// PasswordChangeRequiredError is the typed form of ErrPasswordChangeRequired.
// Ticket is the completion credential the Connect layer hands to the client as
// an error detail; SecondFactorRequired tells the client to ask for a code.
type PasswordChangeRequiredError struct {
	Ticket               string
	SecondFactorRequired bool
}

func (e *PasswordChangeRequiredError) Error() string { return ErrPasswordChangeRequired.Error() }
func (e *PasswordChangeRequiredError) Unwrap() error { return ErrPasswordChangeRequired }

// passwordBindingBytes is how much of the SHA-256 the binding keeps: 128
// bits, ample to tell two salted hashes apart, short enough for a claim.
const passwordBindingBytes = 16

// passwordBinding fingerprints the password a ticket was minted against. The
// hash is salted, so issuing a new password changes it and spends every
// ticket minted for the old one.
func passwordBinding(passwordHash string) string {
	sum := sha256.Sum256([]byte(passwordHash))
	return hex.EncodeToString(sum[:passwordBindingBytes])
}

// requirePasswordChange refuses the session a correct administrator-issued
// password would have opened and mints the ticket that lets the user replace
// it. It runs only after the whole credential check passed, so a caller
// without the issued password never learns the account is waiting for one.
// policyForced is whether the login policy requires a second factor; an
// account that must prove one it has not enrolled is refused here, as at any
// sign-in.
func (s *AuthService) requirePasswordChange(ctx context.Context, user *User, policyForced bool, ipAddr, userAgent string) error {
	if err := s.ensureSecondFactorEnrolled(ctx, user, policyForced); err != nil {
		return err
	}
	ticket, err := s.signPurposeTicket(ctx, jwt.Claims{
		Sub: user.ID, Purpose: tokenPurposePasswordChange, Binding: passwordBinding(user.PasswordHash),
		// The issued password was just proven: the sign-in the completion
		// continues.
		AuthTime: s.nowMs() / 1000,
	}, passwordChangeTicketTTL)
	if err != nil {
		return err
	}
	s.audit.Log(
		ctx, audit.EventLoginFailure,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"reason": "password_change_required"}),
	)
	return &PasswordChangeRequiredError{Ticket: ticket, SecondFactorRequired: user.TotpRequired || policyForced}
}

// CompleteRequiredPasswordChange replaces an administrator-issued password
// with the user's own and completes the sign-in the refusal interrupted. It is
// unauthenticated — the ticket is the credential, spent by any new password.
// Everything a password sign-in would ask is checked before anything
// changes: the account's status, the second factor when the account or the
// login policy requires one (secondFactorCode, a two-step or recovery code),
// and the password policy, with the new password differing from the issued
// one. Then the password is set, every existing session ends, and a new one
// is issued.
func (s *AuthService) CompleteRequiredPasswordChange(ctx context.Context, completionToken, newPassword, secondFactorCode, ipAddr, userAgent string) (*LoginResult, error) {
	claims, err := s.verifyPurposeTicket(ctx, completionToken, tokenPurposePasswordChange)
	if err != nil {
		return nil, err
	}
	if newPassword == "" {
		return nil, fmt.Errorf("%w: new password is required", ErrInvalidArgument)
	}
	user, err := s.repo(ctx).GetUser(ctx, claims.Sub)
	if err != nil {
		return nil, err
	}
	// A ticket is spent once the change is made, or once a new password is
	// issued: it was minted against one particular issued password.
	if user == nil || !user.PasswordChangeRequired || claims.Binding != passwordBinding(user.PasswordHash) {
		return nil, fmt.Errorf("%w: invalid or expired %s ticket", ErrUnauthenticated, tokenPurposePasswordChange)
	}
	// Up to passwordChangeTicketTTL may have passed since the sign-in that
	// minted the ticket: every gate that sign-in passed after the password is
	// checked again, so a change in that window wins over the ticket.
	decision, err := s.recheckSignInGates(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	secondFactor := user.TotpRequired || decision.RequireSecondFactor
	if secondFactor && secondFactorCode == "" {
		return nil, fmt.Errorf("%w: second_factor_code is required", ErrInvalidArgument)
	}
	// The checks with no side effect come before the second factor, whose
	// recovery codes are spent on use: a refused password must not cost one.
	// The email selects the owning tenant's password policy, as at sign-up.
	if err := s.validatePasswordStrengthForEmail(ctx, user.Email, newPassword); err != nil {
		return nil, err
	}
	if passwords.Verify(newPassword, user.PasswordHash) {
		return nil, fmt.Errorf("%w: choose a password different from the one you were given", ErrInvalidArgument)
	}
	if secondFactor {
		if err := s.ensureSecondFactorEnrolled(ctx, user, decision.RequireSecondFactor); err != nil {
			return nil, err
		}
		if _, err := s.verifySecondFactorCode(ctx, user.ID, secondFactorCode, ipAddr, userAgent); err != nil {
			// The ticket allows more than one attempt, so a wrong code counts
			// toward the account's lockout as a wrong password does.
			s.countFailedSecondFactor(ctx, user, ipAddr, userAgent)
			return nil, err
		}
	}
	pwHash, err := passwords.Hash(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	now := s.nowMs()
	if err := s.repo(ctx).UpdateUser(ctx, user.ID, map[string]any{
		"password_hash":            pwHash,
		"password_change_required": false,
		"updated_at":               now,
		// A completed sign-in clears the failed-attempt count, as
		// PasswordLogin does: wrong codes before it no longer count.
		"failed_login_count": 0,
		"locked_until":       int64(0),
	}); err != nil {
		return nil, fmt.Errorf("updating password: %w", err)
	}
	user.PasswordHash = pwHash
	user.PasswordChangeRequired = false
	user.UpdatedAt = msToTime(now)
	// A credential change ends every existing session, as a reset does: an
	// admin often issues a temporary password to recover an account someone
	// else was signed in to. The password is committed, so a revoke failure
	// is logged rather than failing the step; the session this step opens
	// is issued after it.
	sessionsRevoked := true
	if err := s.repo(ctx).DeleteRefreshTokensForUser(ctx, user.ID); err != nil {
		sessionsRevoked = false
		s.logger.Warn("password_change_session_revoke_failed", zap.String("user_id", user.ID), zap.Error(err))
	}
	s.revokeUserSessionsIfModeSession(ctx, user.ID, "password_change_required")
	s.audit.Log(
		ctx, audit.EventPasswordChanged,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"reason": "password_change_required", "sessions_revoked": sessionsRevoked}),
	)

	// The sign-in happened when the issued password was proven; the ticket
	// carries that moment as the session's auth_time.
	s.updateLastLogin(ctx, user.ID)
	s.cancelPendingDeletionOnLogin(ctx, user)
	accessToken, refreshToken, err := s.issueTokensWithSessionStart(ctx, user, ipAddr, userAgent, s.nowMs(), claims.AuthTime*1000)
	if err != nil {
		return nil, err
	}
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "password_change"}),
	)
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// recheckSignInGates repeats, for an account whose password was proven
// earlier, the gates a password sign-in applies after the password: the
// account's status and lockout, the access rule, the verified-email
// requirement and the login policy, whose decision it returns.
func (s *AuthService) recheckSignInGates(ctx context.Context, user *User, ipAddr, userAgent string) (loginPolicyDecision, error) {
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return loginPolicyDecision{}, err
	}
	if err := s.enforceAccountAccessLogin(ctx, user); err != nil {
		return loginPolicyDecision{}, err
	}
	if s.cfg.AuthRequireVerifiedEmail && user.Email != "" && !user.EmailVerified {
		return loginPolicyDecision{}, ErrEmailVerificationRequired
	}
	return s.enforceLoginPolicy(ctx, user.Email, LoginMethodPassword)
}

// countFailedSecondFactor records a wrong second-factor code against the
// account's failed-login count, locking it at the same threshold a wrong
// password does.
func (s *AuthService) countFailedSecondFactor(ctx context.Context, user *User, ipAddr, userAgent string) {
	_, lockedNow, err := s.recordFailedLogin(ctx, user)
	if err != nil {
		s.logger.Warn("second_factor_failure_count_failed", zap.String("user_id", user.ID), zap.Error(err))
		return
	}
	if lockedNow {
		s.audit.Log(
			ctx, audit.EventAccountLocked,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"lockout_seconds": s.cfg.LoginLockoutSeconds,
				"max_attempts":    s.cfg.LoginMaxFailedAttempts,
			}),
		)
	}
}
