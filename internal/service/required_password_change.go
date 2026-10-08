package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
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

// passwordBinding fingerprints the password a ticket was minted against. The
// hash is salted, so issuing a new password changes it and spends every
// ticket minted for the old one.
func passwordBinding(passwordHash string) string {
	sum := sha256.Sum256([]byte(passwordHash))
	return hex.EncodeToString(sum[:16])
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
	ticket, err := s.mintBoundPurposeTicket(ctx, user.ID, tokenPurposePasswordChange, passwordBinding(user.PasswordHash), passwordChangeTicketTTL)
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
	// minted the ticket; a status change in that window wins over it.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}
	decision, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodPassword)
	if err != nil {
		return nil, err
	}
	if user.TotpRequired || decision.RequireSecondFactor {
		if secondFactorCode == "" {
			return nil, fmt.Errorf("%w: second_factor_code is required", ErrInvalidArgument)
		}
		if err := s.ensureSecondFactorEnrolled(ctx, user, decision.RequireSecondFactor); err != nil {
			return nil, err
		}
		if _, err := s.verifySecondFactorCode(ctx, user.ID, secondFactorCode, ipAddr, userAgent); err != nil {
			return nil, err
		}
	}
	// A username account has no email; its username stands in for the
	// email in the policy's identifier-similarity check.
	identifier := user.Email
	if identifier == "" {
		identifier = user.Username
	}
	if err := s.validatePasswordStrengthForEmail(ctx, identifier, newPassword); err != nil {
		return nil, err
	}
	if passwords.Verify(newPassword, user.PasswordHash) {
		return nil, fmt.Errorf("%w: choose a password different from the one you were given", ErrInvalidArgument)
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

	s.updateLastLogin(ctx, user.ID)
	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
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
