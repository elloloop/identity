package service

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// Sign-in by a recovery email. Where the project allows it
// (recovery_emails.sign_in), an emailed code or link sent to an account's
// recovery email signs in to that account: the way back in once the primary
// mailbox is gone. It is the passwordless sign-in with three differences. The
// account is the one that holds the address, never a new one. The proof is of
// the recovery address, so the primary email is not marked verified by it.
// And because a recovery mailbox may be the weakest one the person has, the
// sign-in is mailed to every other address of the account and starts a hold
// on its recovery settings (recoveryHoldUntil).

// recoveryEmailCodeSendAllowed reports whether a sign-in code or link may be
// mailed to addr because an account holds it as a recovery email. It is
// asked only after the project's access policy declined to send: a recovery
// email is rarely on an allowlist and is no account's primary email, so that
// policy alone would drop every such request. A closed project and the deny
// layer still refuse. The lookup runs for every address the policy declined,
// held or not, and the answer on the wire does not change either way.
func (s *AuthService) recoveryEmailCodeSendAllowed(ctx context.Context, addr canonicalEmail) bool {
	scope := ProjectScopeFromContext(ctx)
	if !recoveryEmailsConfig(scope).SignIn {
		return false
	}
	holder, err := s.repo(ctx).FindRecoveryEmailHolder(ctx, string(addr))
	if err != nil {
		s.logger.Warn("recovery_email_holder_lookup_failed", zap.Error(err))
		return false
	}
	switch scope.Access.mode() {
	case AccessModeOpen, AccessModeAllowlist, AccessModeInvite:
		return holder != nil && !scope.Access.denies(s.cfg, addr)
	default:
		return false
	}
}

// loginCodeSendAllowed is the send decision of both passwordless requests:
// the project's access policy, or failing that a recovery email that may
// sign in.
func (s *AuthService) loginCodeSendAllowed(ctx context.Context, addr canonicalEmail) bool {
	return s.accessAllowsCodeSend(ctx, addr) || s.recoveryEmailCodeSendAllowed(ctx, addr)
}

// completeRecoveryEmailLogin finishes a passwordless sign-in whose proved
// address is an account's recovery email. handled is false when no account
// holds the address, and the caller carries on with the primary-email path.
// Where the project does not let recovery emails sign in, the address signs
// in to nothing: invalidErr, the answer a wrong code gets, rather than a new
// account on an address another account holds.
func (s *AuthService) completeRecoveryEmailLogin(ctx context.Context, addr, method string, invalidErr error, ipAddr, userAgent string) (result *LoginResult, handled bool, err error) {
	holder, err := s.repo(ctx).FindRecoveryEmailHolder(ctx, addr)
	if err != nil {
		return nil, true, fmt.Errorf("looking up recovery email: %w", err)
	}
	if holder == nil {
		return nil, false, nil
	}
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	if !cfg.SignIn {
		s.logger.Info("recovery_email_sign_in_not_enabled", zap.String("email", redactEmail(addr)))
		return nil, true, invalidErr
	}
	user, err := s.repo(ctx).GetUser(ctx, holder.UserID)
	if err != nil {
		return nil, true, fmt.Errorf("looking up user: %w", err)
	}
	if user == nil {
		return nil, true, invalidErr
	}
	// The account is judged as it is at any sign-in: the project's access
	// policy and the login policy both go by its primary email, which is the
	// address they were written for.
	if err := s.enforceAccountAccessLogin(ctx, user); err != nil {
		return nil, true, err
	}
	decision, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodEmailOTP)
	if err != nil {
		return nil, true, err
	}
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent, sessionGateSignIn); err != nil {
		return nil, true, err
	}

	// The hold and the notice come before any token or second-factor
	// challenge: a sign-in that cannot start the hold must not happen.
	now := s.nowMs()
	if err := s.repo(ctx).MarkRecoveryEmailSignIn(ctx, user.ID, addr, now); err != nil {
		return nil, true, fmt.Errorf("recording recovery email sign-in: %w", err)
	}
	s.audit.Log(ctx, audit.EventRecoveryEmailSignIn,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": method, "email": redactEmail(addr)}))
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, user.ID)
	if err != nil {
		return nil, true, fmt.Errorf("listing recovery emails: %w", err)
	}
	holdEnds := time.UnixMilli(now + cfg.hold().Milliseconds()).UTC().Format("2 January 2006 at 15:04 UTC")
	s.notifyAccountAddresses(ctx, user, held, addr, accountNotice{
		op:       "recovery_email_sign_in_notice",
		headline: "Your account was signed in to with a recovery email",
		detail: fmt.Sprintf("Someone signed in to your account with the recovery email %s. "+
			"Until %s its recovery emails cannot be removed and its phone number cannot be changed.", addr, holdEnds),
	})

	if user.TotpRequired || decision.RequireSecondFactor {
		result, err := s.requireSecondFactor(ctx, user, decision.RequireSecondFactor, ipAddr, userAgent)
		return result, true, err
	}
	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, true, err
	}
	s.logger.Info("recovery_email_login_success",
		zap.String("email", redactEmail(addr)), zap.String("user_id", user.ID), zap.String("method", method))
	s.audit.Log(ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": method, "new_user": false, "recovery_email": true}))
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, true, nil
}
