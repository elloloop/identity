package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// Passkey-first signup: UNAUTHENTICATED account creation via a passkey.
//
// BeginPasskeyRegistration (auth_passkey.go) adds a passkey to an already
// authenticated account. This pair instead creates a brand-new account whose
// first credential is a passkey — no password, no prior session.
//
// The security-critical invariant is the WebAuthn user-handle binding: the
// user id minted in BeginPasskeySignup is put into the creation options as
// user.id, so the authenticator stores it as the credential's user handle. We
// then create the User under that exact id at CompletePasskeySignup, because
// CompletePasskeyLogin verifies the assertion's user handle equals the stored
// user's id. If the created id diverged from the handle, every future passkey
// login for the account would fail (the #283-class binding bug).

// newPasskeySignupUserID mints the id used both as the WebAuthn user handle in
// BeginPasskeySignup and as the created User's id in CompletePasskeySignup. The
// format (32 hex chars from 16 random bytes) matches the repo drivers' newID,
// so a caller-provided id is indistinguishable from a driver-minted one.
func (s *AuthService) newPasskeySignupUserID() string {
	return randomToken(16)
}

// ── BeginPasskeySignup ─────────────────────────────────────────────────

// BeginPasskeySignup generates WebAuthn registration options for creating a
// NEW account from a passkey. It mints the new user id now and binds it both as
// the WebAuthn user handle (so the credential can log in later) and to the
// email on the stored challenge. Returns (optionsJSON, challengeID, error).
//
// Enumeration-safe: options are produced and returned regardless of whether the
// email already has an account; the duplicate decision is deferred to
// CompletePasskeySignup, where it is handled without disclosing existence.
func (s *AuthService) BeginPasskeySignup(ctx context.Context, email, deviceName string) (string, string, error) {
	if s.cfg != nil && !s.cfg.PasskeySignupEnabled {
		return "", "", ErrPasskeySignupDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if err := validateEmailFormat(email); err != nil {
		return "", "", fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	// Canonicalize for dedup + storage, exactly as PasswordSignup does, so one
	// human maps to one account regardless of gmail dot/+tag variants.
	email = canonicalizeEmail(email)

	newUserID := s.newPasskeySignupUserID()

	optionsJSON, challengeB64, err := s.passkeysFor(ctx).BeginRegistration(
		newUserID, email, email, nil,
	)
	if err != nil {
		return "", "", fmt.Errorf("building signup registration options: %w", err)
	}

	now := s.nowMs()
	challengeID, err := s.repo(ctx).CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{
		Challenge:     challengeB64,
		UserID:        newUserID,
		ChallengeType: "registration",
		Email:         email,
		ExpiresAt:     now + int64(s.cfg.PasskeyChallengeExpirySeconds)*1000,
		CreatedAt:     now,
	})
	if err != nil {
		return "", "", fmt.Errorf("storing challenge: %w", err)
	}

	s.logger.Info(
		"passkey_signup_begin",
		zap.String("email", redactEmail(email)),
		zap.String("challenge_id", challengeID),
	)
	return optionsJSON, challengeID, nil
}

// ── CompletePasskeySignup ──────────────────────────────────────────────

// CompletePasskeySignup verifies the attestation produced for a
// BeginPasskeySignup challenge and finalizes account creation.
//
//   - New email: creates the User under the id bound as the WebAuthn handle
//     (email unverified, role member, status active), stores the passkey
//     credential, sends the verification email, and issues a session (subject
//     to the email-verification gate, mirroring PasswordSignup).
//   - Existing email: does NOT attach the passkey (anti-takeover) and does NOT
//     reveal that the address exists (enumeration-safe) — it returns the same
//     success-shaped decoy as a duplicate PasswordSignup and sends the
//     existing-account notice.
//
// It is unauthenticated: no session is required to call it.
func (s *AuthService) CompletePasskeySignup(
	ctx context.Context,
	challengeID, credentialJSON, email, deviceName, ipAddr, userAgent string,
) (*LoginResult, error) {
	if s.cfg != nil && !s.cfg.PasskeySignupEnabled {
		return nil, ErrPasskeySignupDisabled
	}
	if challengeID == "" || credentialJSON == "" {
		return nil, fmt.Errorf("%w: challenge_id and credential_json are required", ErrInvalidArgument)
	}

	challenge, err := s.repo(ctx).GetPasskeyChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if challenge == nil {
		return nil, fmt.Errorf("%w: challenge not found or already consumed", ErrNotFound)
	}
	// A signup challenge is a registration challenge that carries a bound email.
	// (Add-a-passkey registration challenges leave Email empty and belong to an
	// existing authenticated user, so they can never be redeemed here.)
	if challenge.ChallengeType != "registration" || challenge.Email == "" {
		return nil, fmt.Errorf("%w: challenge is not a signup challenge", ErrInvalidArgument)
	}
	if challenge.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
		return nil, fmt.Errorf("%w: challenge expired", ErrTokenExpired)
	}

	// The account is created under the email bound at Begin (the one shown to
	// the user during the ceremony), never the request-supplied value. If the
	// client did pass an email it must match, so a client cannot complete under
	// a different address than the user consented to.
	boundEmail := challenge.Email
	if reqEmail := canonicalizeEmail(strings.TrimSpace(strings.ToLower(email))); reqEmail != "" && reqEmail != boundEmail {
		return nil, fmt.Errorf("%w: email does not match the signup challenge", ErrInvalidArgument)
	}

	// Verify the attestation BEFORE any account lookup or mutation. This runs
	// identically whether or not the email exists, so a verification failure
	// cannot be used as an existence oracle.
	result, err := s.passkeysFor(ctx).CompleteRegistration(credentialJSON, challenge.Challenge)
	if err != nil {
		s.logger.Warn(
			"passkey_signup_verify_failed",
			zap.String("email", redactEmail(boundEmail)), zap.Error(err),
		)
		return nil, fmt.Errorf("%w: attestation verification failed", ErrInvalidArgument)
	}

	// Single-use challenge — consume it now that the attestation is proven.
	_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)

	// Anti-takeover + enumeration-safety: an existing account is never given a
	// new passkey by an unauthenticated caller, and its existence is never
	// disclosed. Mirror the duplicate-PasswordSignup decoy exactly.
	existing, err := s.repo(ctx).FindUserByEmail(ctx, boundEmail)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		s.logger.Info("passkey_signup_existing_email", zap.String("email", redactEmail(boundEmail)))
		return s.handleDuplicatePasswordSignup(ctx, existing, boundEmail, "")
	}

	now := s.nowMs()
	user := &User{
		ID:        challenge.UserID, // == WebAuthn handle minted at Begin
		Email:     boundEmail,
		Name:      fallbackDisplayName(boundEmail, ""),
		Role:      "member",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	}
	userID, err := s.repo(ctx).CreateUser(ctx, user)
	if err != nil {
		// Lost a create race (a concurrent caller registered the email between
		// our lookup and insert). Treat as duplicate: enumeration-safe, and the
		// passkey is NOT attached to the winner's account.
		if raced, lookupErr := s.repo(ctx).FindUserByEmail(ctx, boundEmail); lookupErr == nil && raced != nil {
			return s.handleDuplicatePasswordSignup(ctx, raced, boundEmail, "")
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	// The whole flow rests on created id == WebAuthn handle. Every driver
	// honours a caller-provided id, but assert it rather than ship a silently
	// broken binding (a #283-class regression would otherwise only surface on
	// the user's NEXT login, long after signup "succeeded").
	if userID != challenge.UserID {
		return nil, fmt.Errorf("passkey signup: created user id %q != bound webauthn handle %q", userID, challenge.UserID)
	}

	if _, err := s.repo(ctx).CreatePasskeyCredential(ctx, &PasskeyCredRecord{
		CredentialID:   result.CredentialID,
		UserID:         userID,
		PublicKey:      result.PublicKey,
		SignCount:      int64(result.SignCount),
		DeviceName:     deviceName,
		AAGUID:         result.AAGUID,
		Transports:     result.Transports,
		BackupEligible: result.BackupEligible,
		BackupState:    result.BackupState,
		CreatedAt:      now,
		LastUsedAt:     now,
	}); err != nil {
		return nil, fmt.Errorf("storing credential: %w", err)
	}

	s.logger.Info(
		"passkey_signup_success",
		zap.String("email", redactEmail(boundEmail)),
		zap.String("user_id", userID),
		zap.String("credential_id", result.CredentialID),
	)
	s.audit.Log(
		ctx, audit.EventPasskeyAdded,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"credential_id": result.CredentialID, "via": "passkey_signup"}),
	)

	// Best-effort: auto-form a company tenant from the email domain.
	s.maybeAutoFormTenant(ctx, user)

	// Best-effort: fire a verification email. Failures are logged, never fatal.
	if err := s.SendEmailVerification(ctx, userID); err != nil {
		s.logger.Warn("passkey_signup_verification_email_failed",
			zap.String("user_id", userID), zap.Error(err))
	}

	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "passkey_signup"}),
	)

	// Email-verification gate (mirrors PasswordSignup): when verified email is
	// required, a freshly-created unverified account receives NO live session.
	// The duplicate-email decoy above is also session-less under this same
	// condition, so empty-vs-non-empty tokens never disclose whether the
	// address already existed.
	if s.cfg != nil && s.cfg.AuthRequireVerifiedEmail && !user.EmailVerified {
		return &LoginResult{User: user}, nil
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
