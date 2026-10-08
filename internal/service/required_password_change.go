package service

import (
	"context"
	"fmt"
	"time"

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
// an error detail.
type PasswordChangeRequiredError struct {
	Ticket string
}

func (e *PasswordChangeRequiredError) Error() string { return ErrPasswordChangeRequired.Error() }
func (e *PasswordChangeRequiredError) Unwrap() error { return ErrPasswordChangeRequired }

// requirePasswordChange refuses the session a correct administrator-issued
// password would have opened and mints the ticket that lets the user replace
// it. It runs only after the whole credential check passed, so a caller
// without the issued password never learns the account is waiting for one.
func (s *AuthService) requirePasswordChange(ctx context.Context, user *User, ipAddr, userAgent string) error {
	ticket, err := s.mintPurposeTicket(ctx, user.ID, tokenPurposePasswordChange, passwordChangeTicketTTL)
	if err != nil {
		return err
	}
	s.audit.Log(
		ctx, audit.EventLoginFailure,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"reason": "password_change_required"}),
	)
	return &PasswordChangeRequiredError{Ticket: ticket}
}

// CompleteRequiredPasswordChange replaces an administrator-issued password
// with the user's own and completes the sign-in the refusal interrupted. It is
// unauthenticated — the ticket is the credential. The new password meets the
// account's password policy and differs from the issued one. The rest is a
// password sign-in's: a second factor, when the account or the login policy
// requires one, is asked for before any token is issued.
func (s *AuthService) CompleteRequiredPasswordChange(ctx context.Context, completionToken, newPassword, ipAddr, userAgent string) (*LoginResult, error) {
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
	// A ticket whose change is already made is spent: the account now signs
	// in with the password its user chose.
	if user == nil || !user.PasswordChangeRequired {
		return nil, fmt.Errorf("%w: invalid or expired %s ticket", ErrUnauthenticated, tokenPurposePasswordChange)
	}
	// Up to passwordChangeTicketTTL may have passed since the sign-in that
	// minted the ticket; a status change in that window wins over it.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}
	if err := s.validatePasswordStrengthForEmail(ctx, user.Email, newPassword); err != nil {
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
	s.audit.Log(
		ctx, audit.EventPasswordChanged,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"reason": "password_change_required"}),
	)

	decision, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodPassword)
	if err != nil {
		return nil, err
	}
	if user.TotpRequired || decision.RequireSecondFactor {
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor)
	}
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
