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
	"github.com/elloloop/identity/pkg/sms"
)

// SMS-OTP phone-ownership verification. The caller is an
// already-authenticated user (proven via JWT, like other authenticated
// RPCs); RequestPhoneVerification texts a 6-digit code to the supplied
// number and VerifyPhoneCode confirms it and marks the user's phone
// verified. This is a standalone ownership proof — NOT a login/MFA
// factor. It reuses the email-OTP code path's shape: crypto/rand 6-digit
// code, sha256 hash at rest, constant-time compare, TTL, max-attempts,
// and a per-user send cooldown.

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

// redactPhone keeps the country prefix and last two digits, masking the
// middle, so logs never carry a full number.
func redactPhone(p string) string {
	if len(p) <= 4 {
		return "***"
	}
	return p[:2] + strings.Repeat("*", len(p)-4) + p[len(p)-2:]
}

// ── RequestPhoneVerification ───────────────────────────────────────────

// RequestPhoneVerification mints a 6-digit OTP for the user's phone and
// texts it. The caller must be authenticated (userID is the verified
// `sub`). Returns ErrSMSDisabled when phone verification is not
// configured, ErrPhoneAlreadyVerified when the user has already verified
// the same number, and ErrInvalidArgument for a malformed number. A
// per-user send cooldown bounds inbox/cost abuse.
func (s *AuthService) RequestPhoneVerification(ctx context.Context, userID, phoneNumber string) error {
	if !s.cfg.SMSEnabled {
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
	if err := s.refuseAnonymousCredentialAttach(ctx, userID); err != nil {
		return err
	}
	phone, ok := normalizePhone(phoneNumber)
	if !ok {
		return fmt.Errorf("%w: phone number must be E.164 (e.g. +14155550123)", ErrInvalidArgument)
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
	if s.minorData.BlocksChild(user.DateOfBirthMs) {
		s.logger.Info("phone_verification_blocked_minor", zap.String("user_id", userID))
		return ErrMinorDataMinimized
	}
	if user.PhoneVerified && user.PhoneNumber == phone {
		return ErrPhoneAlreadyVerified
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

	body := fmt.Sprintf("Your verification code is %s. It expires in %s.", code, formatExpiresIn(ttl))
	if err := s.smsSender.Send(ctx, sms.Message{To: phone, Body: body}); err != nil {
		// The code is already stored; an SMS-side failure is surfaced so
		// the caller knows delivery failed (unlike the anti-enumeration
		// email path, the caller here is authenticated and owns the flow).
		s.logger.Warn("phone_verification_send_failed",
			zap.String("user_id", userID), zap.String("phone", redactPhone(phone)), zap.Error(err))
		return fmt.Errorf("%w: %w", ErrSMSDisabled, err)
	}

	s.audit.Log(ctx, audit.EventPhoneVerificationRequested,
		audit.WithActor(userID),
		audit.WithDetails(map[string]any{"phone": redactPhone(phone)}))
	s.logger.Info("phone_verification_requested",
		zap.String("user_id", userID), zap.String("phone", redactPhone(phone)))
	return nil
}

// ── VerifyPhoneCode ────────────────────────────────────────────────────

// VerifyPhoneCode validates the OTP and, on success, records the
// verified number on the user. The caller must be authenticated. All
// failure modes (missing/expired/consumed code, wrong code, exhausted
// attempts, or a number that does not match the one the code was minted
// for) collapse to ErrPhoneCodeInvalid. A wrong guess bumps the per-code
// attempt counter; at the cap the code is consumed so the brute-force
// window over the 6-digit space is bounded.
func (s *AuthService) VerifyPhoneCode(ctx context.Context, userID, phoneNumber, code string) (*User, error) {
	if !s.cfg.SMSEnabled {
		return nil, ErrSMSDisabled
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: missing user id", ErrUnauthenticated)
	}
	// A verified phone is a permanent credential (it backs SMS login); an
	// anonymous caller must go through UpgradeAnonymousAccount instead.
	if err := s.refuseAnonymousCredentialAttach(ctx, userID); err != nil {
		return nil, err
	}
	phone, ok := normalizePhone(phoneNumber)
	if !ok || strings.TrimSpace(code) == "" {
		return nil, ErrPhoneCodeInvalid
	}

	rec, err := s.repo(ctx).FindPhoneVerificationCodeByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("looking up phone verification code: %w", err)
	}
	if rec == nil || rec.ConsumedAt != 0 || rec.ExpiresAt <= s.nowMs() || rec.PhoneNumber != phone {
		return nil, ErrPhoneCodeInvalid
	}
	if rec.MaxAttempts > 0 && rec.AttemptCount >= rec.MaxAttempts {
		return nil, ErrPhoneCodeInvalid
	}

	// Constant-time compare so a timing oracle can't shortcut the guess.
	if subtle.ConstantTimeCompare([]byte(rec.CodeHash), []byte(sha256Hex(code))) != 1 {
		if err := s.repo(ctx).IncrementPhoneVerificationCodeAttempts(ctx, rec.NodeID); err != nil {
			s.logger.Warn("phone_code_attempt_increment_failed",
				zap.String("user_id", userID), zap.Error(err))
		}
		// At the cap, consume the code so the final wrong guess burns it.
		if rec.MaxAttempts > 0 && rec.AttemptCount+1 >= rec.MaxAttempts {
			if _, cErr := s.repo(ctx).ConsumePhoneVerificationCode(ctx, userID, s.nowMs()); cErr != nil &&
				!errors.Is(cErr, ErrPhoneCodeInvalid) {
				s.logger.Warn("phone_code_lock_failed",
					zap.String("user_id", userID), zap.Error(cErr))
			}
		}
		return nil, ErrPhoneCodeInvalid
	}

	// Correct code: consume single-use (CAS) before flipping the user so
	// a replay racing this verify loses.
	if _, err := s.repo(ctx).ConsumePhoneVerificationCode(ctx, userID, s.nowMs()); err != nil {
		return nil, ErrPhoneCodeInvalid
	}

	now := s.nowMs()
	if err := s.repo(ctx).SetUserPhoneVerified(ctx, userID, phone, now); err != nil {
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
		audit.WithDetails(map[string]any{"phone": redactPhone(phone)}))
	s.logger.Info("phone_verified",
		zap.String("user_id", userID), zap.String("phone", redactPhone(phone)))
	return user, nil
}
