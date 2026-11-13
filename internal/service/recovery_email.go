package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
)

// Recovery emails: additional addresses a signed-in user proves they control
// and keeps on their account. An address is stored only after the code
// mailed to it is confirmed, so nothing unproved is ever held; within a
// project it belongs to one account (Repository.AddRecoveryEmail). Adding
// and removing need a recent sign-in, so a stolen or long-lived session
// cannot plant an address or strip the real ones, and every change is
// mailed to the account's other addresses. While a recovery hold is in
// force, a session a recovery email opened can do neither.

// recoveryEmailCaller loads the caller for a change to their recovery
// emails and refuses the accounts that may hold none (anonymous accounts and
// agents), a session whose sign-in is older than the project's window, and
// a session a recovery hold binds.
func (s *AuthService) recoveryEmailCaller(ctx context.Context, userID string, signIn SessionSignIn, cfg ProjectRecoveryEmailsConfig) (*User, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: missing user id", ErrUnauthenticated)
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if user.IsAgent() {
		return nil, ErrAgentCredential
	}
	if user.IsAnonymous {
		return nil, fmt.Errorf("%w: an anonymous account keeps no recovery email", ErrAnonymousMustUpgrade)
	}
	if !s.signedInWithin(signIn.AuthTimeSec, cfg.reauthMaxAge()) {
		return nil, ErrRecoveryReauthenticationRequired
	}
	if err := s.refuseHeldSession(ctx, userID, signIn); err != nil {
		return nil, err
	}
	return user, nil
}

// RequestRecoveryEmail mails a 6-digit code to emailAddr for the caller to
// confirm with VerifyRecoveryEmail. Its answer does not depend on whether
// another account holds the address: that is never looked up here, and is
// told only to a caller who proves the address. The refusals it does return
// are about the caller's own account: the feature being off, a stale
// sign-in, a recovery hold on the session, the caller's own address, and a
// full list.
func (s *AuthService) RequestRecoveryEmail(ctx context.Context, userID string, signIn SessionSignIn, emailAddr string) error {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	if !cfg.Enabled {
		return ErrRecoveryEmailsDisabled
	}
	user, err := s.recoveryEmailCaller(ctx, userID, signIn, cfg)
	if err != nil {
		return err
	}
	addr, ok := canonicalMailbox(emailAddr)
	if !ok {
		return fmt.Errorf("%w: email is not a usable address", ErrInvalidArgument)
	}
	if s.minorData.BlocksChildFor(ctx, user) {
		s.logger.Info("recovery_email_blocked_minor", zap.String("user_id", userID))
		return ErrMinorDataMinimized
	}
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	if err != nil {
		return fmt.Errorf("listing recovery emails: %w", err)
	}
	if holdsAddress(user, held, string(addr)) {
		return ErrRecoveryEmailTaken
	}
	if len(held) >= cfg.max() {
		return ErrRecoveryEmailLimit
	}
	s.dispatchEmailSend(ctx, "recovery_email_code", func(ctx context.Context) {
		s.sendRecoveryEmailCodeNow(ctx, userID, string(addr))
	})
	return nil
}

// holdsAddress reports whether addr is the account's primary email or one of
// its recovery emails, under FoldEmail.
func holdsAddress(user *User, held []*RecoveryEmail, addr string) bool {
	fold := FoldEmail(addr)
	if user.Email != "" && FoldEmail(user.Email) == fold {
		return true
	}
	for _, e := range held {
		if FoldEmail(e.Email) == fold {
			return true
		}
	}
	return false
}

// recoveryEmailSenderKey is the send-cooldown key of an account's own
// requests. No address holds it: an address always has an '@'.
func recoveryEmailSenderKey(userID string) string { return "recovery-email-sender:" + userID }

// sendRecoveryEmailCodeNow is the body of RequestRecoveryEmail's dispatch.
// Two cooldowns bound it: one per account, so a session cannot mail a
// stream of strangers, and the shared per-address one. Silent: a throttled,
// unrendered or undelivered code is logged, never surfaced.
func (s *AuthService) sendRecoveryEmailCodeNow(ctx context.Context, userID, addr string) {
	now := s.nowMs()
	if !s.emailThrottle.allow(recoveryEmailSenderKey(userID), now) || !s.emailThrottle.allow(addr, now) {
		s.logger.Info("recovery_email_code_throttled", zap.String("user_id", userID))
		return
	}
	code := generateEmailLoginCode()
	ttl := s.emailCodeTTL()
	if _, err := s.repo(ctx).UpsertRecoveryEmailCode(ctx, &RecoveryEmailCodeRecord{
		UserID:      userID,
		Email:       addr,
		CodeHash:    sha256Hex(code),
		ExpiresAt:   now + ttl.Milliseconds(),
		CreatedAt:   now,
		MaxAttempts: s.emailCodeMaxAttempts(),
	}); err != nil {
		s.logger.Warn("recovery_email_code_create_failed", zap.String("user_id", userID), zap.Error(err))
		return
	}
	brand := resolveBranding(ctx, s.cfg, "")
	html, text, err := email.Render(email.TemplateRecoveryEmailCode, brand.templateData(map[string]any{
		"Code":      code,
		"ExpiresIn": formatExpiresIn(ttl),
	}))
	if err != nil {
		s.logger.Warn("recovery_email_code_render_failed", zap.Error(err))
		return
	}
	msg := email.Message{To: addr, From: s.cfg.SMTPFrom, Subject: "Confirm your recovery email", HTML: html, Text: text}
	brand.applyTo(&msg)
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("recovery_email_code_send_failed", zap.String("user_id", userID), zap.Error(err))
	}
	s.logger.Info("recovery_email_code_requested",
		zap.String("user_id", userID), zap.String("email", redactEmail(addr)))
}

// VerifyRecoveryEmail confirms the code mailed to emailAddr and stores the
// address on the caller's account, returning the account's recovery emails.
// Every failure of the code (missing, expired, consumed, wrong, sent to
// another address, out of attempts) is ErrRecoveryEmailCodeInvalid. Only
// once the code is right can the caller learn that another account holds the
// address (ErrRecoveryEmailTaken): they have proved it is theirs to ask
// about.
func (s *AuthService) VerifyRecoveryEmail(ctx context.Context, userID string, signIn SessionSignIn, emailAddr, code string) ([]*RecoveryEmail, error) {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	if !cfg.Enabled {
		return nil, ErrRecoveryEmailsDisabled
	}
	user, err := s.recoveryEmailCaller(ctx, userID, signIn, cfg)
	if err != nil {
		return nil, err
	}
	addr, ok := canonicalMailbox(emailAddr)
	if !ok || strings.TrimSpace(code) == "" {
		return nil, ErrRecoveryEmailCodeInvalid
	}
	if err := s.verifyAndConsumeRecoveryEmailCode(ctx, userID, string(addr), code); err != nil {
		return nil, err
	}
	now := s.nowMs()
	if err := s.repo(ctx).AddRecoveryEmail(ctx, &RecoveryEmail{UserID: userID, Email: string(addr), VerifiedAt: now}, cfg.max()); err != nil {
		if errors.Is(err, ErrRecoveryEmailTaken) || errors.Is(err, ErrRecoveryEmailLimit) {
			return nil, err
		}
		return nil, fmt.Errorf("storing recovery email: %w", err)
	}
	s.audit.Log(ctx, audit.EventRecoveryEmailAdded,
		audit.WithActor(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"email": redactEmail(string(addr))}))
	s.logger.Info("recovery_email_added",
		zap.String("user_id", userID), zap.String("email", redactEmail(string(addr))))
	held, listErr := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	// The address is stored whether or not the list can be read, so the
	// account is told either way: at every address, or at least at the
	// primary one.
	s.notifyAccountAddresses(ctx, user, held, string(addr), accountNotice{
		op:       "recovery_email_added_notice",
		headline: "A recovery email was added to your account",
		detail:   fmt.Sprintf("The address %s was added to your account as a recovery email.", addr),
	})
	if listErr != nil {
		return nil, fmt.Errorf("listing recovery emails: %w", listErr)
	}
	return held, nil
}

// verifyAndConsumeRecoveryEmailCode checks a guess at the code mailed to
// addr. The guess is counted against the code's attempt cap in the same
// write that reads the code, so concurrent guesses never pass the cap, then
// settled like every one-time code (settleGuess).
func (s *AuthService) verifyAndConsumeRecoveryEmailCode(ctx context.Context, userID, addr, code string) error {
	rec, err := s.repo(ctx).CountRecoveryEmailCodeAttempt(ctx, userID, s.nowMs())
	if err != nil {
		return fmt.Errorf("looking up recovery email code: %w", err)
	}
	if rec == nil || FoldEmail(rec.Email) != FoldEmail(addr) {
		return ErrRecoveryEmailCodeInvalid
	}
	_, err = s.settleGuess(ctx, oneTimeCode{
		kind: "recovery_email_code", hash: rec.CodeHash,
		attempts: rec.AttemptCount, maxAttempts: rec.MaxAttempts,
		invalid: ErrRecoveryEmailCodeInvalid,
		consume: func(ctx context.Context) error {
			_, err := s.repo(ctx).ConsumeRecoveryEmailCode(ctx, userID, s.nowMs())
			return err
		},
	}, code, zap.String("user_id", userID))
	return err
}

// ListRecoveryEmails returns the caller's recovery emails, oldest first, and
// when the account's recovery hold ends (epoch ms; 0 when none is in
// force). It does not depend on the project's switch: an address
// kept while the feature was on stays visible to its owner.
func (s *AuthService) ListRecoveryEmails(ctx context.Context, userID string) ([]*RecoveryEmail, int64, error) {
	if userID == "" {
		return nil, 0, fmt.Errorf("%w: missing user id", ErrUnauthenticated)
	}
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("listing recovery emails: %w", err)
	}
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	return held, recoveryHoldUntil(held, cfg.hold(), s.nowMs()), nil
}

// recoveryHoldUntil is when an account's recovery hold ends (epoch ms), or 0
// when none is in force. A sign-in by a recovery email starts one: whoever
// got into a recovery mailbox must not be able to strip the account's other
// addresses, ways in and sessions, move its phone, add a way in of their own
// or delete the account before the owner has had the notice. It is measured
// from the latest HoldStartedAt among the account's addresses, so removing
// addresses ends it early only once none whose hold is in force is left.
func recoveryHoldUntil(held []*RecoveryEmail, hold time.Duration, nowMs int64) int64 {
	var latest int64
	for _, e := range held {
		latest = max(latest, e.HoldStartedAt)
	}
	if latest == 0 {
		return 0
	}
	if until := latest + hold.Milliseconds(); until > nowMs {
		return until
	}
	return 0
}

// recoveryHoldOn returns a RecoveryHoldError while a hold is in force on
// userID's account at nowMs, and nil when none is.
func recoveryHoldOn(ctx context.Context, repo Repository, userID string, nowMs int64) error {
	held, err := repo.ListRecoveryEmails(ctx, userID)
	if err != nil {
		return fmt.Errorf("listing recovery emails: %w", err)
	}
	if until := recoveryHoldUntil(held, recoveryEmailsConfig(ProjectScopeFromContext(ctx)).hold(), nowMs); until != 0 {
		return &RecoveryHoldError{UntilMs: until}
	}
	return nil
}

// refuseHeldSession refuses an account security change (one that adds or
// removes a way into the account or a way to recover it, ends its other
// sessions, or merges or deletes it) asked for by a session which may have
// been opened by a recovery email (SessionSignIn.mayBeRecoverySession):
//
//   - with ErrUnauthenticated once the recovery email that opened it is no
//     longer one of userID's, or once the session store says it has ended;
//   - with ErrRecoverySession when it is treated as a recovery session
//     (SessionSignIn.treatedAsRecoverySession) but names no recovery email,
//     so nothing can show that its address is still the account's;
//   - with a RecoveryHoldError while a hold is in force on the account at
//     nowMs.
//
// Every other session is free: the owner, signed in with the primary email,
// a password, a passkey or an identity provider, can always remove an
// address they do not recognise.
//
// Removing the address ends the sessions it opened in the same write, but an
// access token outlives that write: for the rest of its lifetime under
// GATEWAY_REVOCATION_MODE=ttl, and for up to another replica's session-cache
// TTL under session. With the address gone no hold would stop such a token,
// so its recovery_email_id does, in either mode and over any transport that
// forwards it.
func refuseHeldSession(ctx context.Context, repo Repository, logger *zap.Logger, userID string, signIn SessionSignIn, nowMs int64) error {
	if !signIn.mayBeRecoverySession() {
		return nil
	}
	if repo == nil {
		return ErrServiceUnavailable
	}
	held, err := repo.ListRecoveryEmails(ctx, userID)
	if err != nil {
		return fmt.Errorf("listing recovery emails: %w", err)
	}
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	if signIn.treatedAsRecoverySession(cfg) {
		if signIn.RecoveryEmailID == "" {
			logger.Info("account_security_change_refused_unnamed_recovery_session", zap.String("user_id", userID))
			return fmt.Errorf("%w: it cannot show that the recovery email behind it is still the account's", ErrRecoverySession)
		}
		if heldRecoveryEmail(held, signIn.RecoveryEmailID) == nil {
			logger.Info("account_security_change_refused_address_removed",
				zap.String("user_id", userID), zap.String("recovery_email_id", signIn.RecoveryEmailID))
			return errRecoveryEmailGone
		}
	}
	if until := recoveryHoldUntil(held, cfg.hold(), nowMs); until != 0 {
		logger.Info("account_security_change_refused_by_hold", zap.String("user_id", userID))
		return &RecoveryHoldError{UntilMs: until}
	}
	if signIn.SessionID == "" {
		return nil
	}
	session, err := repo.GetSessionBySid(ctx, signIn.SessionID)
	if err != nil {
		return fmt.Errorf("reading session: %w", err)
	}
	if session == nil || session.RevokedAtMs != 0 {
		logger.Info("account_security_change_refused_ended_session", zap.String("user_id", userID))
		return fmt.Errorf("%w: the session has ended", ErrUnauthenticated)
	}
	return nil
}

// errRecoveryEmailGone refuses a recovery session, or the sign-in that would
// open one, whose recovery email the account no longer holds.
var errRecoveryEmailGone = fmt.Errorf("%w: the recovery email that opened the session no longer belongs to the account", ErrUnauthenticated)

// heldRecoveryEmail returns the address among held whose ID is id, or nil.
func heldRecoveryEmail(held []*RecoveryEmail, id string) *RecoveryEmail {
	for _, e := range held {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// refuseHeldSession is the package's refuseHeldSession on the request's
// store and the service's clock.
func (s *AuthService) refuseHeldSession(ctx context.Context, userID string, signIn SessionSignIn) error {
	return refuseHeldSession(ctx, s.repo(ctx), s.logger, userID, signIn, s.nowMs())
}

// refuseHeldSession is the package's refuseHeldSession on the request's
// store and the service's clock.
func (s *ProfileService) refuseHeldSession(ctx context.Context, userID string, signIn SessionSignIn) error {
	return refuseHeldSession(ctx, s.repo(ctx), s.logger, userID, signIn, s.nowMs())
}

// RemoveRecoveryEmail removes one of the caller's recovery emails and
// returns what is left. Every session the address opened ends with it, in
// the same write: their refresh tokens are deleted and, under
// GATEWAY_REVOCATION_MODE=session, their access tokens stop working, the
// caller's own included when the address opened it; under either mode no
// access token left over makes an account security change
// (refuseHeldSession). The ended sessions are audited as session_revoked. A notice goes to the removed address and to
// every other address of the account. An address the
// account does not hold is ErrNotFound. While a hold is in force, a session a
// recovery email opened is refused (RecoveryHoldError) and any other session
// may remove any address. Like ListRecoveryEmails it does not depend on the
// project's switch.
func (s *AuthService) RemoveRecoveryEmail(ctx context.Context, userID string, signIn SessionSignIn, emailAddr string) ([]*RecoveryEmail, error) {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	user, err := s.recoveryEmailCaller(ctx, userID, signIn, cfg)
	if err != nil {
		return nil, err
	}
	addr, ok := canonicalMailbox(emailAddr)
	if !ok {
		return nil, fmt.Errorf("%w: email is not a usable address", ErrInvalidArgument)
	}
	ended, err := s.repo(ctx).RemoveRecoveryEmail(ctx, userID, string(addr), s.nowMs())
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: the account holds no such recovery email", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("removing recovery email: %w", err)
	}
	s.audit.Log(ctx, audit.EventRecoveryEmailRemoved,
		audit.WithActor(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"email": redactEmail(string(addr))}))
	if ended > 0 {
		s.audit.Log(ctx, audit.EventSessionRevoked,
			audit.WithActor(userID), audit.WithTarget(userID), audit.WithSuccess(true),
			audit.WithDetails(map[string]any{
				"scope": "recovery_email", "email": redactEmail(string(addr)), "revoked_count": ended,
			}))
	}
	s.logger.Info("recovery_email_removed",
		zap.String("user_id", userID), zap.String("email", redactEmail(string(addr))), zap.Int("sessions_ended", ended))
	held, listErr := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	notice := accountNotice{
		op:       "recovery_email_removed_notice",
		headline: "A recovery email was removed from your account",
		detail:   fmt.Sprintf("The address %s was removed from your account's recovery emails.", addr),
	}
	s.notifyAccountAddresses(ctx, user, append(held, &RecoveryEmail{Email: string(addr)}), "", notice)
	if listErr != nil {
		return nil, fmt.Errorf("listing recovery emails: %w", listErr)
	}
	return held, nil
}

// accountNotice is a security notice to an account's addresses: the
// dispatch's op label, the subject, and one sentence saying what happened.
type accountNotice struct {
	op, headline, detail string
}

// notifyAccountAddresses mails notice to the account's primary email and to
// each address in recovery, skipping except (the address the change was
// made with, which needs no telling). Best-effort and off the request: a
// notice that cannot be rendered or sent is logged, and the change stands.
func (s *AuthService) notifyAccountAddresses(ctx context.Context, user *User, recovery []*RecoveryEmail, except string, notice accountNotice) {
	to := make([]string, 0, len(recovery)+1)
	skip := FoldEmail(except)
	if user.Email != "" && (except == "" || FoldEmail(user.Email) != skip) {
		to = append(to, user.Email)
	}
	for _, e := range recovery {
		if except == "" || FoldEmail(e.Email) != skip {
			to = append(to, e.Email)
		}
	}
	if len(to) == 0 {
		return
	}
	s.dispatchEmailSend(ctx, notice.op, func(ctx context.Context) {
		brand := resolveBranding(ctx, s.cfg, "")
		html, text, err := email.Render(email.TemplateAccountNotice, brand.templateData(map[string]any{
			"UserName": displayNameOrEmail(user),
			"Headline": notice.headline,
			"Detail":   notice.detail,
		}))
		if err != nil {
			s.logger.Warn("account_notice_render_failed", zap.String("op", notice.op), zap.Error(err))
			return
		}
		for _, addr := range to {
			msg := email.Message{To: addr, From: s.cfg.SMTPFrom, Subject: notice.headline, HTML: html, Text: text}
			brand.applyTo(&msg)
			if err := s.mailer.Send(ctx, msg); err != nil {
				s.logger.Warn("account_notice_send_failed",
					zap.String("op", notice.op), zap.String("user_id", user.ID), zap.Error(err))
			}
		}
	})
}
