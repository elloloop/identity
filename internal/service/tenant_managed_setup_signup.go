package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/passwords"
)

// WithManagedAccounts wires the stores a managed account is set up through:
// setups writes the set-up (the postgres control plane's ManagedSetupStore)
// and tenants answers whether the account's tenant admits managed accounts.
// Without both no managed account is set up.
func (s *AuthService) WithManagedAccounts(setups ManagedSetupStore, tenants TenantStore) *AuthService {
	s.managedSetups, s.managedTenants = setups, tenants
	return s
}

// setUpManagedAccount redeems rawToken when it names a managed account's
// set-up link: handled is false for any other token, which
// SignUpWithTenantInvitation then treats as an ordinary invitation. The
// person chooses only the password; the name is the one the tenant gave.
//
// The link must be pending and unexpired, and its token must have gone only
// into its email; the mailer must deliver; the server, project and tenant
// must admit managed accounts, and the project must hold the address and let
// the account sign in (enforceAccountAccessLogin); the account must still be
// invited, managed by the link's tenant, at the link's epoch; the password
// must meet the rules of the address's tenant and the sign-in its login
// policy. Everything is checked before anything is written, then
// CompleteManagedSetup activates the account, grants its membership and
// accepts the link in one transaction, rechecking the account, the epoch and
// the domain under its locks.
//
// A membership that was suspended before the set-up stays suspended: the
// account is set up but signs nothing in, and the person is told with
// ErrMemberSuspended. Otherwise the account signs in. Its first set-up
// announces user.created. Each refusal is logged as
// managed_account_setup_refused with its reason; a set-up as
// managed_account_set_up, and audited.
func (s *AuthService) setUpManagedAccount(ctx context.Context, rawToken, password, ipAddr, userAgent string) (res *LoginResult, handled bool, err error) {
	ctx, err = s.activeProjectPolicyContext(ctx)
	if err != nil {
		return nil, true, err
	}
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || scope.ProjectID == "" {
		return nil, false, nil
	}
	inv, err := s.openInvitations.GetInvitationByTokenHash(ctx, scope.ProjectID, sha256Hex(rawToken))
	if err != nil {
		return nil, true, err
	}
	if inv == nil || !inv.IsManagedSetup() {
		return nil, false, nil
	}
	res, err = s.completeManagedSetup(ctx, scope, inv, password, ipAddr, userAgent)
	return res, true, err
}

func (s *AuthService) completeManagedSetup(ctx context.Context, scope *ProjectScope, inv *TenantInvitation, password, ipAddr, userAgent string) (*LoginResult, error) {
	refuse := func(reason string, err error) (*LoginResult, error) {
		s.logger.Info("managed_account_setup_refused", append(invitationDecisionLogFields(ctx, scope.ProjectID, inv),
			zap.String("user_id", inv.UserID), zap.String("reason", reason), zap.Error(err))...)
		return nil, err
	}
	if password == "" {
		return refuse("invalid_argument", fmt.Errorf("%w: password is required", ErrInvalidArgument))
	}
	if !inv.TokenOnlyInEmail {
		return refuse("token_outside_email", ErrInvitationSignupUnavailable)
	}
	if !s.mailDelivers {
		return refuse("mail_not_delivered", ErrInvitationSignupUnavailable)
	}
	if err := invitationClosedError(invitationStatusAt(inv, s.nowMs())); err != nil {
		return refuse("invitation_closed", err)
	}
	if err := requireManagedAccountsAdmitted(ctx, s.cfg, s.managedTenants, scope, inv.TenantID); err != nil {
		return refuse("policy", err)
	}
	account, err := s.repo(ctx).GetUser(ctx, inv.UserID)
	if err != nil {
		return nil, err
	}
	if account == nil || account.Status != StatusInvited || account.ManagedByTenantID != inv.TenantID || account.SetupEpoch != inv.SetupEpoch {
		return refuse("stale", ErrManagedSetupStale)
	}
	if err := refuseProjectAddress(s.cfg, scope, account.Email, emailDomain(account.Email)); err != nil {
		return refuse("policy", err)
	}
	if err := s.enforceAccountAccessLogin(ctx, account); err != nil {
		return refuse("access", err)
	}
	decision, err := s.enforceLoginPolicy(ctx, account.Email, LoginMethodPassword)
	if err == nil && decision.RequireSecondFactor {
		err = fmt.Errorf("%w: your organization requires two-factor authentication, which a new account has not set up", ErrTotpRequired)
	}
	if err != nil {
		return refuse("login_policy", err)
	}
	if err := s.validatePasswordStrengthForEmail(ctx, account.Email, password); err != nil {
		return refuse("password_rule", err)
	}
	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	done, err := s.managedSetups.CompleteManagedSetup(ctx, ManagedSetupCompletion{
		ProjectID: scope.ProjectID, InvitationID: inv.ID, PasswordHash: pwHash, NowMs: s.nowMs(),
	})
	if err != nil {
		return refuse(managedSetupRefusalReason(err), err)
	}
	user := done.User
	user.PasswordHash = ""
	s.logger.Info("managed_account_set_up", append(invitationDecisionLogFields(ctx, scope.ProjectID, inv),
		zap.String("user_id", user.ID), zap.String("membership_status", done.Membership.Status),
		zap.Bool("first_set_up", done.FirstSetUp))...)
	s.audit.Log(ctx, audit.EventManagedAccountSetUp,
		audit.WithActor(user.ID), audit.WithTarget(user.ID),
		audit.WithIP(ipAddr), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"project_id": scope.ProjectID, "tenant_id": inv.TenantID, "invitation_id": inv.ID,
			"membership_status": done.Membership.Status, "first_set_up": done.FirstSetUp,
		}),
	)
	if done.FirstSetUp {
		EmitUserEvent(ctx, s.publisher, s.logger, scope.ProjectID, s.tenantID(ctx), events.EventUserCreated, user)
	}
	if done.Membership.Status != MembershipStatusActive {
		return nil, ErrMemberSuspended
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent, credentialEnrollment{Trusted: true})
	if err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "managed_account_setup"}),
	)
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// managedSetupRefusalReason names the rule CompleteManagedSetup refused with.
func managedSetupRefusalReason(err error) string {
	switch {
	case errors.Is(err, ErrManagedSetupStale):
		return "stale"
	case errors.Is(err, ErrManagedDomainUnverified):
		return "domain_unverified"
	case errors.Is(err, ErrInvitationUsed), errors.Is(err, ErrInvitationExpired), errors.Is(err, ErrNotFound):
		return "invitation_closed"
	default:
		return "store_error"
	}
}
