package service

import (
	"context"
	"crypto/subtle"
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
// mailed to the account's other addresses.

// recoveryEmailCaller loads the caller for a change to their recovery
// emails and refuses the accounts that may hold none (anonymous accounts and
// agents) and a session whose sign-in is older than the project's window.
func (s *AuthService) recoveryEmailCaller(ctx context.Context, userID string, authTimeSec int64, cfg ProjectRecoveryEmailsConfig) (*User, error) {
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
	if !s.signedInWithin(authTimeSec, cfg.reauthMaxAge()) {
		return nil, ErrRecoveryReauthenticationRequired
	}
	return user, nil
}

// RequestRecoveryEmail mails a 6-digit code to emailAddr for the caller to
// confirm with VerifyRecoveryEmail. Its answer does not depend on whether
// another account holds the address: that is never looked up here, and is
// told only to a caller who proves the address. The refusals it does return
// are about the caller's own account: the feature being off, a stale
// sign-in, the caller's own address, and a full list.
func (s *AuthService) RequestRecoveryEmail(ctx context.Context, userID string, authTimeSec int64, emailAddr string) error {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	if !cfg.Enabled {
		return ErrRecoveryEmailsDisabled
	}
	user, err := s.recoveryEmailCaller(ctx, userID, authTimeSec, cfg)
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
func (s *AuthService) VerifyRecoveryEmail(ctx context.Context, userID string, authTimeSec int64, emailAddr, code string) ([]*RecoveryEmail, error) {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	if !cfg.Enabled {
		return nil, ErrRecoveryEmailsDisabled
	}
	user, err := s.recoveryEmailCaller(ctx, userID, authTimeSec, cfg)
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
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing recovery emails: %w", err)
	}
	s.audit.Log(ctx, audit.EventRecoveryEmailAdded,
		audit.WithActor(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"email": redactEmail(string(addr))}))
	s.logger.Info("recovery_email_added",
		zap.String("user_id", userID), zap.String("email", redactEmail(string(addr))))
	s.notifyAccountAddresses(ctx, user, held, string(addr), accountNotice{
		op:       "recovery_email_added_notice",
		headline: "A recovery email was added to your account",
		detail:   fmt.Sprintf("The address %s was added to your account as a recovery email.", addr),
	})
	return held, nil
}

// verifyAndConsumeRecoveryEmailCode is the phone code's check for a recovery
// address: a constant-time compare, an attempt counted per wrong guess, the
// code burnt at the cap, and a single-use consume before the caller acts.
func (s *AuthService) verifyAndConsumeRecoveryEmailCode(ctx context.Context, userID, addr, code string) error {
	rec, err := s.repo(ctx).FindRecoveryEmailCodeByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("looking up recovery email code: %w", err)
	}
	if rec == nil || rec.ConsumedAt != 0 || rec.ExpiresAt <= s.nowMs() || FoldEmail(rec.Email) != FoldEmail(addr) {
		return ErrRecoveryEmailCodeInvalid
	}
	if rec.MaxAttempts > 0 && rec.AttemptCount >= rec.MaxAttempts {
		return ErrRecoveryEmailCodeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(rec.CodeHash), []byte(sha256Hex(code))) != 1 {
		if err := s.repo(ctx).IncrementRecoveryEmailCodeAttempts(ctx, rec.NodeID); err != nil {
			s.logger.Warn("recovery_email_code_attempt_increment_failed",
				zap.String("user_id", userID), zap.Error(err))
		}
		if rec.MaxAttempts > 0 && rec.AttemptCount+1 >= rec.MaxAttempts {
			if _, cErr := s.repo(ctx).ConsumeRecoveryEmailCode(ctx, userID, s.nowMs()); cErr != nil &&
				!errors.Is(cErr, ErrRecoveryEmailCodeInvalid) {
				s.logger.Warn("recovery_email_code_lock_failed",
					zap.String("user_id", userID), zap.Error(cErr))
			}
		}
		return ErrRecoveryEmailCodeInvalid
	}
	if _, err := s.repo(ctx).ConsumeRecoveryEmailCode(ctx, userID, s.nowMs()); err != nil {
		return ErrRecoveryEmailCodeInvalid
	}
	return nil
}

// ListRecoveryEmails returns the caller's recovery emails, oldest first, and
// when the hold on the account's recovery settings ends (epoch ms; 0 when
// none is in force). It does not depend on the project's switch: an address
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

// recoveryHoldUntil is when the hold on an account's recovery settings ends
// (epoch ms), or 0 when none is in force. A sign-in by a recovery email
// starts one: whoever got into a recovery mailbox must not be able to strip
// the account's other addresses or move its phone before the owner has had
// the notice.
func recoveryHoldUntil(held []*RecoveryEmail, hold time.Duration, nowMs int64) int64 {
	var last int64
	for _, e := range held {
		if e.LastSignInAt > last {
			last = e.LastSignInAt
		}
	}
	if last == 0 {
		return 0
	}
	if until := last + hold.Milliseconds(); until > nowMs {
		return until
	}
	return 0
}

// checkRecoveryHold refuses, with a RecoveryHoldError, a change to the
// recovery settings of an account a hold is in force on.
func (s *AuthService) checkRecoveryHold(ctx context.Context, userID string) error {
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	if err != nil {
		return fmt.Errorf("listing recovery emails: %w", err)
	}
	return s.refuseDuringRecoveryHold(ctx, userID, held)
}

func (s *AuthService) refuseDuringRecoveryHold(ctx context.Context, userID string, held []*RecoveryEmail) error {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	until := recoveryHoldUntil(held, cfg.hold(), s.nowMs())
	if until == 0 {
		return nil
	}
	s.logger.Info("recovery_settings_change_refused_by_hold", zap.String("user_id", userID))
	return &RecoveryHoldError{UntilMs: until}
}

// RemoveRecoveryEmail removes one of the caller's recovery emails and
// returns what is left. A notice goes to the removed address and to every
// other address of the account. An address the account does not hold is
// ErrNotFound, and any removal while a hold is in force is a
// RecoveryHoldError. Like ListRecoveryEmails it does not depend on the
// project's switch.
func (s *AuthService) RemoveRecoveryEmail(ctx context.Context, userID string, authTimeSec int64, emailAddr string) ([]*RecoveryEmail, error) {
	cfg := recoveryEmailsConfig(ProjectScopeFromContext(ctx))
	user, err := s.recoveryEmailCaller(ctx, userID, authTimeSec, cfg)
	if err != nil {
		return nil, err
	}
	addr, ok := canonicalMailbox(emailAddr)
	if !ok {
		return nil, fmt.Errorf("%w: email is not a usable address", ErrInvalidArgument)
	}
	if err := s.checkRecoveryHold(ctx, userID); err != nil {
		return nil, err
	}
	removed, err := s.repo(ctx).RemoveRecoveryEmail(ctx, userID, string(addr))
	if err != nil {
		return nil, fmt.Errorf("removing recovery email: %w", err)
	}
	if !removed {
		return nil, fmt.Errorf("%w: the account holds no such recovery email", ErrNotFound)
	}
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing recovery emails: %w", err)
	}
	s.audit.Log(ctx, audit.EventRecoveryEmailRemoved,
		audit.WithActor(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"email": redactEmail(string(addr))}))
	s.logger.Info("recovery_email_removed",
		zap.String("user_id", userID), zap.String("email", redactEmail(string(addr))))
	notice := accountNotice{
		op:       "recovery_email_removed_notice",
		headline: "A recovery email was removed from your account",
		detail:   fmt.Sprintf("The address %s was removed from your account's recovery emails.", addr),
	}
	s.notifyAccountAddresses(ctx, user, append(held, &RecoveryEmail{Email: string(addr)}), "", notice)
	return held, nil
}

// accountNotice is a security notice about a change to an account's
// recovery settings: the dispatch's op label, the subject, and one sentence
// saying what changed.
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
