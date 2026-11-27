package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/passwords"
)

var (
	// ErrInvitationSignupUnavailable refuses SignUpWithTenantInvitation where
	// an invitation cannot create an account: the project has not opted in
	// (access.admit_tenant_invitations, with accounts.email_signup self), the
	// mailer does not deliver, or the token's invitation does not record that
	// its token went only into its email (TenantInvitation.TokenOnlyInEmail),
	// so the token may have gone to its inviter. Mapped to
	// CodeFailedPrecondition; the message leads with the stable
	// `invitation_signup_unavailable` token.
	ErrInvitationSignupUnavailable = errors.New("invitation_signup_unavailable: an invitation cannot create an account here")
	// ErrInvitationRevoked refuses an invitation that was revoked. Mapped to
	// CodeFailedPrecondition, as an accepted or expired one is.
	ErrInvitationRevoked = errors.New("invitation has been revoked")

	errInvitedAddressHasAccount = fmt.Errorf("%w: an account already uses this email address; sign in instead", ErrAlreadyExists)
)

// accountNameMaxRunes bounds the name a person gives their account when they
// sign up from an invitation.
const accountNameMaxRunes = 100

// WithMailDelivery records whether the mailer this service was built with
// delivers, and returns the service for chaining. Without it the service
// takes it that mail is not delivered.
func (s *AuthService) WithMailDelivery(delivers bool) *AuthService {
	s.mailDelivers = delivers
	return s
}

// SignUpWithTenantInvitation creates the account the pending tenant
// invitation rawToken names, with name and password, and signs it in. The
// emailed link proves the address, so the account is created verified, and
// active. It is admitted as a proven sign-up is (recordInvitedSignup), but by
// the token's own invitation (OpenInvitationReader.OpenInvitationForToken),
// and joins no tenant: it skips domain auto-formation, and the invitation
// stays pending for the account to accept with AcceptTenantInvitation.
//
// Holding the token proves the address only where the invitation was
// emailed, so a project that has not opted in (mode invite with
// access.admit_tenant_invitations and accounts.email_signup self), or a
// mailer that does not deliver, refuses with ErrInvitationSignupUnavailable
// before the token is looked up, and so does an invitation whose token did
// not go only into its email (TokenOnlyInEmail) once it is found, whatever
// the mailer does now. An unknown token is ErrNotFound; an
// accepted, expired or revoked invitation ErrInvitationUsed,
// ErrInvitationExpired or ErrInvitationRevoked; one that is not open, or an
// address the deny layer refuses, ErrPermissionDenied or ErrAccessNotAllowed;
// an address an account holds ErrAlreadyExists. The password is held to the
// rules of the address's tenant, and the sign-in to its login policy, before
// anything is written.
//
// Where the server enables managed accounts, a managed account's set-up link
// is redeemed first, before every check above but the local-auth switch
// (setUpManagedAccount).
func (s *AuthService) SignUpWithTenantInvitation(ctx context.Context, rawToken, name, password, ipAddr, userAgent string) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	if s.openInvitations == nil {
		return nil, ErrUnimplemented
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("%w: missing token", ErrInvalidArgument)
	}
	if s.cfg.ManagedAccountsEnabled && s.managedSetups != nil {
		res, handled, err := s.setUpManagedAccount(ctx, rawToken, password, ipAddr, userAgent)
		if handled {
			return res, err
		}
	}
	if !s.cfg.PasswordSignupEnabled {
		return nil, ErrSignupDisabled
	}
	name, err := normalizeText("name", name, accountNameMaxRunes)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if ctx, err = s.activeProjectPolicyContext(ctx); err != nil {
		return nil, err
	}
	scope := ProjectScopeFromContext(ctx)
	if err := s.invitationSignupAvailable(ctx, scope); err != nil {
		return nil, err
	}

	inv, err := s.openInvitations.GetInvitationByTokenHash(ctx, scope.ProjectID, sha256Hex(rawToken))
	if err != nil {
		return nil, err
	}
	if inv == nil {
		s.logInvitationSignupRefused(ctx, nil, "not_found")
		return nil, fmt.Errorf("%w: invitation", ErrNotFound)
	}
	if !inv.TokenOnlyInEmail {
		s.logInvitationSignupRefused(ctx, inv, "token_outside_email")
		return nil, ErrInvitationSignupUnavailable
	}
	status := invitationStatusAt(inv, s.nowMs())
	if err := invitationClosedError(status); err != nil {
		s.logInvitationSignupRefused(ctx, inv, "invitation_closed", zap.String("status", status))
		return nil, err
	}
	email := canonicalize(inv.Email)
	if scope.Access.denies(s.cfg, email) {
		s.logInvitationSignupRefused(ctx, inv, "deny_layer", zap.String("email_domain", emailDomain(inv.Email)))
		return nil, ErrAccessNotAllowed
	}
	admitted, err := s.openInvitations.OpenInvitationForToken(ctx, scope.ProjectID, inv.TokenHash, s.nowMs())
	if err != nil {
		return nil, err
	}
	if admitted == nil {
		s.logInvitationSignupRefused(ctx, inv, "invitation_not_open")
		return nil, fmt.Errorf("%w: this invitation cannot create an account; ask an owner or admin of the tenant for a new one", ErrPermissionDenied)
	}

	repo := s.repo(ctx)
	held, err := addressHasAccount(ctx, repo, string(email))
	if err != nil {
		return nil, err
	}
	if held {
		s.logInvitationSignupRefused(ctx, inv, "account_exists")
		return nil, errInvitedAddressHasAccount
	}
	decision, err := s.enforceLoginPolicy(ctx, string(email), LoginMethodPassword)
	if err == nil && decision.RequireSecondFactor {
		err = fmt.Errorf("%w: your organization requires two-factor authentication, which a new account has not set up", ErrTotpRequired)
	}
	if err != nil {
		s.logInvitationSignupRefused(ctx, inv, "login_policy")
		return nil, err
	}
	if err := s.validatePasswordStrengthForEmail(ctx, string(email), password); err != nil {
		s.logInvitationSignupRefused(ctx, inv, "password_rule")
		return nil, err
	}
	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	now := s.nowMs()
	user := &User{
		Email:           string(email),
		Name:            name,
		Role:            "member",
		Status:          StatusActive,
		PasswordHash:    pwHash,
		EmailVerified:   true,
		EmailVerifiedAt: now,
		CreatedAt:       msToTime(now),
		UpdatedAt:       msToTime(now),
	}
	id, err := repo.CreateUser(ctx, user)
	if err != nil {
		// Lost a race with another sign-up for the address.
		if held, lookupErr := addressHasAccount(ctx, repo, string(email)); lookupErr == nil && held {
			s.logInvitationSignupRefused(ctx, inv, "account_exists")
			return nil, errInvitedAddressHasAccount
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	user.ID = id
	user.PasswordHash = ""
	s.logger.Info("tenant_invitation_signup_created",
		append(invitationDecisionLogFields(ctx, s.projectID(ctx), inv), zap.String("user_id", id))...)
	s.recordInvitedSignup(ctx, user, admitted, ipAddr, userAgent)
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), events.EventUserCreated, user)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent, credentialEnrollment{Trusted: true})
	if err != nil {
		return nil, err
	}
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(id), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "tenant_invitation_signup"}),
	)
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// invitationSignupAvailable refuses a sign-up from an invitation where none
// can create an account: the request has no project, the project has not
// opted in, or the mailer does not deliver. It reads nothing but the
// project's policy, so it says nothing about any invitation.
func (s *AuthService) invitationSignupAvailable(ctx context.Context, scope *ProjectScope) error {
	if scope == nil || scope.ProjectID == "" {
		return fmt.Errorf("%w: no project in request scope", ErrPermissionDenied)
	}
	reason := ""
	switch {
	case scope.Access.mode() != AccessModeInvite || !scope.Access.AdmitTenantInvitations || scope.Accounts.emailSignup() != SignupSelf:
		reason = "not_opted_in"
	case !s.mailDelivers:
		reason = "mail_not_delivered"
	default:
		return nil
	}
	s.logInvitationSignupRefused(ctx, nil, reason)
	return ErrInvitationSignupUnavailable
}

// logInvitationSignupRefused records which rule refused a sign-up from an
// invitation: reason, with fields, about inv, or about none when the token
// was not looked up or named no invitation.
func (s *AuthService) logInvitationSignupRefused(ctx context.Context, inv *TenantInvitation, reason string, fields ...zap.Field) {
	line := append(invitationDecisionLogFields(ctx, s.projectID(ctx), inv), zap.String("reason", reason))
	s.logger.Info("tenant_invitation_signup_refused", append(line, fields...)...)
}

// invitationClosedError is the refusal of an invitation in status, or nil for
// a pending one.
func invitationClosedError(status string) error {
	switch status {
	case InvitationStatusPending:
		return nil
	case InvitationStatusAccepted:
		return ErrInvitationUsed
	case InvitationStatusExpired:
		return ErrInvitationExpired
	default:
		return ErrInvitationRevoked
	}
}
