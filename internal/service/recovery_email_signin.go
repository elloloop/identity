package service

import (
	"context"
	"errors"
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
// sign-in is mailed to every other address of the account, starts a recovery
// hold on the account (recoveryHoldUntil), and opens a session marked
// AMRRecoveryEmail: the hold keeps that session from account security
// changes, never one opened another way, and the session acts in no tenant
// through its email's domain.

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
//
// A code alone starts nothing: an account that owes a second factor gets a
// challenge that remembers the address, and the hold, the notice and the
// session's tie to the address come only once VerifyTotp proves the factor
// (startRecoveryEmailSession).
func (s *AuthService) completeRecoveryEmailLogin(ctx context.Context, addr, method string, invalidErr error, ipAddr, userAgent string) (result *LoginResult, handled bool, err error) {
	holder, err := s.repo(ctx).FindRecoveryEmailHolder(ctx, addr)
	if err != nil {
		return nil, true, fmt.Errorf("looking up recovery email: %w", err)
	}
	if holder == nil {
		return nil, false, nil
	}
	if !recoveryEmailsConfig(ProjectScopeFromContext(ctx)).SignIn {
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
	if user.TotpRequired || decision.RequireSecondFactor {
		result, err := s.requireSecondFactor(ctx, user, decision.RequireSecondFactor, holder.ID, ipAddr, userAgent)
		return result, true, err
	}
	accessToken, refreshToken, err := s.startRecoveryEmailSession(ctx, user, holder.ID, method, ipAddr, userAgent)
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

// startRecoveryEmailSession opens the session of a sign-in by the recovery
// email whose RecoveryEmail.ID is recoveryEmailID once every factor it owed
// is proved (method names the last proof: the emailed code or link, or
// "totp"). It starts the account's recovery hold, unless one this address
// started is still in force, tells every other address of the account, and
// issues the session marked AMRRecoveryEmail and tied to the address. The
// hold comes before the tokens: a sign-in that cannot start the hold must
// not happen. A verified-email refusal comes before both, so a sign-in that
// could yield no session starts nothing, and an address removed meanwhile
// (while its second factor was asked for, say) opens nothing.
func (s *AuthService) startRecoveryEmailSession(ctx context.Context, user *User, recoveryEmailID, method, ipAddr, userAgent string) (string, string, error) {
	if err := s.enforceVerifiedEmail(ctx, user, ipAddr, userAgent, sessionGateSignIn); err != nil {
		return "", "", err
	}
	hold := recoveryEmailsConfig(ProjectScopeFromContext(ctx)).hold()
	now := s.nowMs()
	if err := s.repo(ctx).MarkRecoveryEmailSignIn(ctx, user.ID, recoveryEmailID, now, hold.Milliseconds()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", "", errRecoveryEmailGone
		}
		return "", "", fmt.Errorf("recording recovery email sign-in: %w", err)
	}
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, user.ID)
	if err != nil {
		return "", "", fmt.Errorf("listing recovery emails: %w", err)
	}
	signedIn := heldRecoveryEmail(held, recoveryEmailID)
	if signedIn == nil {
		return "", "", errRecoveryEmailGone
	}
	addr := signedIn.Email
	s.audit.Log(ctx, audit.EventRecoveryEmailSignIn,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": method, "email": redactEmail(addr)}))
	until := recoveryHoldUntil(held, hold, now)
	s.notifyAccountAddresses(ctx, user, held, addr, accountNotice{
		op:       "recovery_email_sign_in_notice",
		headline: "Your account was signed in to with a recovery email",
		detail: fmt.Sprintf("Someone signed in to your account with the recovery email %s. "+
			"Until %s that session cannot make security changes to your account: "+
			"it cannot add or remove an email address, phone number, second factor, passkey or linked provider, "+
			"change your password or primary email, sign out your other sessions or delete the account. "+
			"If it was not you, sign in another way (your primary email, your password, a passkey or a linked provider) "+
			"and remove the address.",
			addr, time.UnixMilli(until).UTC().Format("2 January 2006 at 15:04 UTC")),
	})
	return s.issueSignInTokens(ctx, user, ipAddr, userAgent, now, now, recoveryEmailID)
}
