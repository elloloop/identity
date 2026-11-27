package service

import (
	"context"
	"fmt"
	"time"

	"github.com/elloloop/identity/internal/config"

	"go.uber.org/zap"
)

// errManagedSessionEnded refuses a managed account's credential or
// administrative change from a session that has ended, or that no session
// stands behind: a reset, suspension or removal ends the account's sessions
// in its own transaction, and an access token minted before it must not
// attach anything after it.
var errManagedSessionEnded = fmt.Errorf("%w: the session has ended", ErrUnauthenticated)

// fenceManagedSession refuses user, when a tenant manages it, unless it is
// active and the session behind signIn is one of its own that has not been
// revoked, read from repo rather than any session cache. It guards every
// change that attaches a way into the account (a passkey, two-step, a
// phone, a provider link, a password, an agent) and every
// tenant-admin call, so a token outliving a reset, suspension or removal
// does nothing. A personal account is never read for. Each refusal is
// logged with path.
func fenceManagedSession(ctx context.Context, repo Repository, logger *zap.Logger, user *User, signIn SessionSignIn, path string) error {
	if user == nil || user.ManagedByTenantID == "" {
		return nil
	}
	refuse := func(reason string, err error) error {
		logger.Info("managed_account_refused",
			zap.String("tenant_id", user.ManagedByTenantID), zap.String("user_id", user.ID),
			zap.String("path", path), zap.String("reason", reason))
		return err
	}
	if !isActiveStatus(user.Status) {
		return refuse("account_not_active", fmt.Errorf("%w: account is %s", ErrAccountNotActive, user.Status))
	}
	if signIn.SessionID == "" {
		return refuse("no_session", errManagedSessionEnded)
	}
	if repo == nil {
		return refuse("no_session_store", ErrServiceUnavailable)
	}
	session, err := repo.GetSessionBySid(ctx, signIn.SessionID)
	if err != nil {
		return fmt.Errorf("reading session: %w", err)
	}
	if session == nil || session.RevokedAtMs != 0 || session.UserID != user.ID {
		return refuse("session_ended", errManagedSessionEnded)
	}
	return nil
}

// fenceManagedCaller is fenceManagedSession on userID's account in the
// request's store, and, for an account a tenant manages, its standing in
// that tenant (refuseManagedAccount): set up, an active membership, a
// tenant that is not suspended.
func (s *AuthService) fenceManagedCaller(ctx context.Context, userID string, signIn SessionSignIn, path string) error {
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := fenceManagedSession(ctx, s.repo(ctx), s.logger, user, signIn, path); err != nil {
		return err
	}
	if user == nil {
		return nil
	}
	return s.refuseManagedAccount(ctx, user, path)
}

// accessTokenExpiry is how long an access token issued to user lasts: an
// account a tenant manages, and an agent such an account owns, get
// GATEWAY_MANAGED_ACCESS_TOKEN_EXPIRY_SECONDS, so a service that verifies
// tokens itself stops honouring one within a minute of a suspension, removal
// or reset; every other account GATEWAY_JWT_EXPIRY_SECONDS. An agent with
// no owner, or whose owner cannot be read, gets the short lifetime.
func (s *AuthService) accessTokenExpiry(ctx context.Context, user *User) time.Duration {
	if user.ManagedByTenantID != "" {
		return s.cfg.ManagedAccessTokenExpiry()
	}
	if user.IsAgent() {
		if user.OwnerUserID == "" {
			return s.cfg.ManagedAccessTokenExpiry()
		}
		owner, err := s.repo(ctx).GetUser(ctx, user.OwnerUserID)
		if err != nil || owner == nil || owner.ManagedByTenantID != "" {
			return s.cfg.ManagedAccessTokenExpiry()
		}
	}
	return s.cfg.JWTExpiry()
}

// accessTokenExpiresIn is how long, in whole seconds, the access token a
// sign-in issues to user, a person, lasts.
func (s *AuthService) accessTokenExpiresIn(user *User) int32 {
	expiry := s.cfg.JWTExpiry()
	if user.ManagedByTenantID != "" {
		expiry = s.cfg.ManagedAccessTokenExpiry()
	}
	return secondsToInt32(int(expiry / time.Second))
}

// managedTokenCapMs caps expiresAtMs, a delegated or machine token's expiry
// issued at nowMs for an agent whose owner is owner, at
// GATEWAY_MANAGED_ACCESS_TOKEN_EXPIRY_SECONDS when a tenant manages the
// owner, or when there is no owner to judge.
func managedTokenCapMs(cfg *config.Config, owner *User, nowMs, expiresAtMs int64) int64 {
	if owner != nil && owner.ManagedByTenantID == "" {
		return expiresAtMs
	}
	return min(expiresAtMs, nowMs+cfg.ManagedAccessTokenExpiry().Milliseconds())
}
