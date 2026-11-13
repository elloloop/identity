package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/sms"
	"github.com/elloloop/identity/pkg/templatemsg"
)

// One-time-code phone-ownership verification. The caller is an
// already-authenticated user (proven via JWT, like other authenticated
// RPCs); RequestPhoneVerification sends a 6-digit code to the supplied
// number and VerifyPhoneCode confirms it and marks the user's phone
// verified. This is a standalone ownership proof — NOT a login/MFA
// factor. It reuses the email-OTP code path's shape: crypto/rand 6-digit
// code, sha256 hash at rest, constant-time compare, TTL, max-attempts,
// and a per-user send cooldown.
//
// The deployment decides which senders exist (an SMS provider, and a
// template-message sender an embedder wires); the request's project decides
// the rest (ProjectPhoneConfig): whether it verifies phones at all, the
// order the channels are tried in, the countries it accepts, and whether a
// number belongs to one account.

// WithTemplateMessages wires the sender of the message delivery channel
// (PhoneChannelMessage) and returns the service for chaining. Without one
// the channel is skipped wherever a project lists it.
func (s *AuthService) WithTemplateMessages(sender templatemsg.Sender) *AuthService {
	s.templateSender = sender
	return s
}

// phoneChannelUsable reports whether the deployment has a sender for ch.
func (s *AuthService) phoneChannelUsable(ch string) bool {
	switch ch {
	case PhoneChannelSMS:
		return s.cfg.SMSEnabled
	case PhoneChannelMessage:
		return s.templateSender != nil
	default:
		return false
	}
}

// phoneVerificationOn reports whether the project verifies phones: it has
// not switched the feature off, and the deployment has a sender for at
// least one of the channels it uses.
func (s *AuthService) phoneVerificationOn(cfg ProjectPhoneConfig) bool {
	if cfg.off() {
		return false
	}
	for _, ch := range cfg.channels() {
		if s.phoneChannelUsable(ch) {
			return true
		}
	}
	return false
}

// deliverPhoneCode sends code to phone over the project's channels in
// order, stopping at the first that accepts it. A channel the deployment
// has no sender for is skipped; one that fails is logged and the next is
// tried. The error is the last channel's.
func (s *AuthService) deliverPhoneCode(ctx context.Context, cfg ProjectPhoneConfig, userID, phone, code string, ttl time.Duration) error {
	err := ErrSMSDisabled
	for _, ch := range cfg.channels() {
		if !s.phoneChannelUsable(ch) {
			continue
		}
		var sendErr error
		if ch == PhoneChannelMessage {
			sendErr = s.templateSender.Send(ctx, templatemsg.Message{
				To: phone, Template: cfg.MessageTemplate, Language: cfg.MessageLanguage, Params: []string{code},
			})
		} else {
			body := fmt.Sprintf("Your verification code is %s. It expires in %s.", code, formatExpiresIn(ttl))
			sendErr = s.smsSender.Send(ctx, sms.Message{To: phone, Body: body})
		}
		if sendErr == nil {
			return nil
		}
		s.logger.Warn("phone_verification_send_failed",
			zap.String("user_id", userID), zap.String("phone", sms.Redact(phone)),
			zap.String("channel", ch), zap.Error(sendErr))
		err = fmt.Errorf("%w: %w", ErrSMSDisabled, sendErr)
	}
	return err
}

const (
	defaultPhoneCodeTTL = 5 * time.Minute
)

func (s *AuthService) phoneCodeTTL() time.Duration {
	if s.cfg.PhoneCodeTTLSeconds > 0 {
		return time.Duration(s.cfg.PhoneCodeTTLSeconds) * time.Second
	}
	return defaultPhoneCodeTTL
}

func (s *AuthService) phoneCodeMaxAttempts() int64 {
	if s.cfg.PhoneCodeMaxAttempts > 0 {
		return int64(s.cfg.PhoneCodeMaxAttempts)
	}
	return defaultCodeMaxAttempts
}

// normalizePhone trims whitespace from a phone number and reports
// whether it is minimally well-formed (a leading '+' and at least one
// digit). The authoritative validation is the provider's; this guards
// the obviously-malformed inputs and is the canonical at-rest form.
func normalizePhone(raw string) (string, bool) {
	p := strings.TrimSpace(raw)
	if len(p) < 2 || p[0] != '+' {
		return p, false
	}
	for _, r := range p[1:] {
		if r < '0' || r > '9' {
			return p, false
		}
	}
	return p, true
}

// ── RequestPhoneVerification ───────────────────────────────────────────

// RequestPhoneVerification mints a 6-digit OTP for the user's phone and
// sends it. The caller must be authenticated (userID is the verified
// `sub`). Returns ErrSMSDisabled when the project cannot verify phones or
// no channel delivered the code, ErrPhoneAlreadyVerified when the
// user has already verified the same number, ErrInvalidArgument for a
// malformed number and ErrPhoneCountryNotAllowed for one outside the
// project's countries. A per-user send cooldown bounds inbox/cost abuse.
// While a recovery hold is in force, a session a recovery email opened is
// refused (RecoveryHoldError).
//
// A number another account holds is sent a code like any other: whether a
// number is taken is told only by VerifyPhoneCode, to whoever proves it.
func (s *AuthService) RequestPhoneVerification(ctx context.Context, userID string, signIn SessionSignIn, phoneNumber string) error {
	phoneCfg := phoneConfig(ProjectScopeFromContext(ctx))
	if !s.phoneVerificationOn(phoneCfg) {
		return ErrSMSDisabled
	}
	if userID == "" {
		return fmt.Errorf("%w: missing user id", ErrUnauthenticated)
	}
	// Refuse BEFORE the send, not just at redemption. This is the call that
	// costs money, and phone is not a shipped upgrade credential, so every
	// message an anonymous caller triggers is guaranteed waste. It also
	// restores the abuse control: phoneThrottle is keyed on user id, and a
	// fresh user id costs one unauthenticated SignInAnonymously — so
	// guarding only VerifyPhoneCode leaves the per-user cooldown collapsed
	// and nothing but the per-IP limit between an attacker and a victim's
	// number.
	if err := s.refuseCredentialAttach(ctx, userID); err != nil {
		return err
	}
	phone, ok := normalizePhone(phoneNumber)
	if !ok {
		return fmt.Errorf("%w: phone number must be E.164 (e.g. +14155550123)", ErrInvalidArgument)
	}
	if !hasCallingCode(phone, phoneCfg.AllowedCallingCodes) {
		return ErrPhoneCountryNotAllowed
	}

	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("looking up user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}
	// COPPA data-minimization: a CHILD-band account must not be pushed
	// through phone collection when minimization is enabled. Adults, teens,
	// and minimization-off deployments are unaffected. No SMS is sent.
	if s.minorData.BlocksChildFor(ctx, user) {
		s.logger.Info("phone_verification_blocked_minor", zap.String("user_id", userID))
		return ErrMinorDataMinimized
	}
	if user.PhoneVerified && user.PhoneNumber == phone {
		return ErrPhoneAlreadyVerified
	}
	// Before the send, like every other refusal here: a number that cannot
	// be stored yet should not cost a message.
	if err := s.refuseHeldSession(ctx, userID, signIn); err != nil {
		return err
	}

	// Per-user send cooldown so a single account cannot pump SMS at a
	// victim number or burn the provider budget.
	if !s.phoneThrottle.allow(userID, s.nowMs()) {
		s.logger.Info("phone_verification_throttled", zap.String("user_id", userID))
		return nil
	}

	code := generateEmailLoginCode() // shared 6-digit crypto/rand generator
	now := s.nowMs()
	ttl := s.phoneCodeTTL()
	if _, err := s.repo(ctx).UpsertPhoneVerificationCode(ctx, &PhoneVerificationCodeRecord{
		UserID:      userID,
		PhoneNumber: phone,
		CodeHash:    sha256Hex(code),
		ExpiresAt:   now + ttl.Milliseconds(),
		CreatedAt:   now,
		MaxAttempts: s.phoneCodeMaxAttempts(),
	}); err != nil {
		return fmt.Errorf("storing phone verification code: %w", err)
	}

	// The code is already stored; a delivery failure is surfaced so the
	// caller knows it did not arrive (unlike the anti-enumeration email
	// path, the caller here is authenticated and owns the flow).
	if err := s.deliverPhoneCode(ctx, phoneCfg, userID, phone, code, ttl); err != nil {
		return err
	}

	s.audit.Log(ctx, audit.EventPhoneVerificationRequested,
		audit.WithActor(userID),
		audit.WithDetails(map[string]any{"phone": sms.Redact(phone)}))
	s.logger.Info("phone_verification_requested",
		zap.String("user_id", userID), zap.String("phone", sms.Redact(phone)))
	return nil
}

// ── VerifyPhoneCode ────────────────────────────────────────────────────

// VerifyPhoneCode validates the OTP and, on success, records the
// verified number on the user. The caller must be authenticated. All
// failure modes (missing/expired/consumed code, wrong code, exhausted
// attempts, or a number that does not match the one the code was minted
// for) collapse to ErrPhoneCodeInvalid. Every guess, one for another number
// included, is counted against the code's attempt cap in the same write that
// reads the code, so concurrent guesses never pass it, and a wrong one at the
// cap consumes the code, so the brute-force window over the 6-digit space is
// bounded.
//
// Where the project keeps numbers unique, a right code for a number another
// account holds is ErrPhoneNumberTaken, unless that account's claim is old
// enough to move (phone.reassign_after_seconds): then the number moves and
// its previous holder is told. Refused like RequestPhoneVerification during
// a recovery hold.
func (s *AuthService) VerifyPhoneCode(ctx context.Context, userID string, signIn SessionSignIn, phoneNumber, code string) (*User, error) {
	phoneCfg := phoneConfig(ProjectScopeFromContext(ctx))
	if !s.phoneVerificationOn(phoneCfg) {
		return nil, ErrSMSDisabled
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: missing user id", ErrUnauthenticated)
	}
	// A verified phone is a permanent credential (it backs SMS login); an
	// anonymous caller must go through UpgradeAnonymousAccount instead.
	if err := s.refuseCredentialAttach(ctx, userID); err != nil {
		return nil, err
	}
	phone, ok := normalizePhone(phoneNumber)
	if !ok || strings.TrimSpace(code) == "" {
		return nil, ErrPhoneCodeInvalid
	}
	if !hasCallingCode(phone, phoneCfg.AllowedCallingCodes) {
		return nil, ErrPhoneCountryNotAllowed
	}
	// A code requested before a hold began must not move the number during it.
	if err := s.refuseHeldSession(ctx, userID, signIn); err != nil {
		return nil, err
	}

	rec, err := s.repo(ctx).CountPhoneVerificationCodeAttempt(ctx, userID, s.nowMs())
	if err != nil {
		return nil, fmt.Errorf("looking up phone verification code: %w", err)
	}
	if rec == nil || rec.PhoneNumber != phone {
		return nil, ErrPhoneCodeInvalid
	}
	if _, err := s.settleGuess(ctx, oneTimeCode{
		kind: "phone_code", hash: rec.CodeHash,
		attempts: rec.AttemptCount, maxAttempts: rec.MaxAttempts,
		invalid: ErrPhoneCodeInvalid,
		consume: func(ctx context.Context) error {
			_, err := s.repo(ctx).ConsumePhoneVerificationCode(ctx, userID, s.nowMs())
			return err
		},
	}, code, zap.String("user_id", userID)); err != nil {
		return nil, err
	}

	now := s.nowMs()
	if phoneCfg.Unique {
		previous, err := s.repo(ctx).ClaimPhoneNumber(ctx, userID, phone, now, phoneCfg.takeOverBefore(now))
		if errors.Is(err, ErrPhoneNumberTaken) {
			s.logger.Info("phone_verification_refused_number_taken",
				zap.String("user_id", userID), zap.String("phone", sms.Redact(phone)))
			return nil, ErrPhoneNumberTaken
		}
		if err != nil {
			return nil, fmt.Errorf("claiming phone number: %w", err)
		}
		if previous != "" {
			s.announcePhoneMoved(ctx, previous, phone)
		}
	} else if err := s.repo(ctx).SetUserPhoneVerified(ctx, userID, phone, now); err != nil {
		return nil, fmt.Errorf("marking phone verified: %w", err)
	}

	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	s.audit.Log(ctx, audit.EventPhoneVerified,
		audit.WithActor(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"phone": sms.Redact(phone)}))
	s.logger.Info("phone_verified",
		zap.String("user_id", userID), zap.String("phone", sms.Redact(phone)))
	return user, nil
}

// announcePhoneMoved records that previousID lost phone to another account
// that proved it, and tells previousID's addresses. Best-effort: the move
// has already happened.
func (s *AuthService) announcePhoneMoved(ctx context.Context, previousID, phone string) {
	s.audit.Log(ctx, audit.EventPhoneRemoved,
		audit.WithActor(previousID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"phone": sms.Redact(phone), "reason": "verified_by_another_account"}))
	s.logger.Info("phone_moved_to_another_account",
		zap.String("user_id", previousID), zap.String("phone", sms.Redact(phone)))
	previous, err := s.repo(ctx).GetUser(ctx, previousID)
	if err != nil || previous == nil {
		s.logger.Warn("phone_moved_notice_lookup_failed", zap.String("user_id", previousID), zap.Error(err))
		return
	}
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, previousID)
	if err != nil {
		s.logger.Warn("phone_moved_notice_lookup_failed", zap.String("user_id", previousID), zap.Error(err))
	}
	s.notifyAccountAddresses(ctx, previous, held, "", accountNotice{
		op:       "phone_moved_notice",
		headline: "Your phone number was removed from your account",
		detail: fmt.Sprintf("The phone number %s was verified by another account, so it is no longer on yours. "+
			"If the number is still yours, verify it again.", sms.Redact(phone)),
	})
}

// ── RemovePhone ────────────────────────────────────────────────────────

// RemovePhone clears the caller's phone number, freeing it for another
// account where the project keeps numbers unique, and returns the updated
// user. It does not depend on the project's switch or on a sender: a number
// stored while verification was on stays its owner's to remove. A caller
// with no number gets their user back unchanged. Refused, like a change of
// number, to a session a recovery hold binds (RecoveryHoldError).
func (s *AuthService) RemovePhone(ctx context.Context, userID string, signIn SessionSignIn) (*User, error) {
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
	if user.PhoneNumber == "" {
		return user, nil
	}
	if err := s.refuseHeldSession(ctx, userID, signIn); err != nil {
		return nil, err
	}
	held, err := s.repo(ctx).ListRecoveryEmails(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing recovery emails: %w", err)
	}
	phone := user.PhoneNumber
	if err := s.repo(ctx).ReleasePhoneNumber(ctx, userID, s.nowMs()); err != nil {
		return nil, fmt.Errorf("removing phone number: %w", err)
	}
	s.audit.Log(ctx, audit.EventPhoneRemoved,
		audit.WithActor(userID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"phone": sms.Redact(phone), "reason": "removed_by_user"}))
	s.logger.Info("phone_removed", zap.String("user_id", userID), zap.String("phone", sms.Redact(phone)))
	s.notifyAccountAddresses(ctx, user, held, "", accountNotice{
		op:       "phone_removed_notice",
		headline: "The phone number was removed from your account",
		detail:   fmt.Sprintf("The phone number %s was removed from your account.", sms.Redact(phone)),
	})
	updated, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	if updated == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	return updated, nil
}
