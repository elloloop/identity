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
// NEW account from a passkey AND emails a 6-digit OTP to the address. It mints
// the new user id now and binds it both as the WebAuthn user handle (so the
// credential can log in later) and to the email on the stored challenge.
// Returns (optionsJSON, challengeID, error).
//
// The OTP is the in-flow proof of email control: CompletePasskeySignup will not
// create the account until it is presented, so the account is created already
// verified and an attacker can never leave a planted passkey on an unverified
// address (account pre-hijacking). The OTP reuses the passwordless email-code
// infra (same mint/store/TTL/attempt-limit/send path) via sendEmailLoginCode.
//
// Enumeration-safe: options are returned and an OTP is sent regardless of
// whether the email already has an account (the existence check is deferred to
// CompletePasskeySignup, after the OTP is verified, and never disclosed). The
// per-email send cooldown is honoured exactly as RequestEmailLoginCode does.
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

	// Email the in-flow proof-of-control OTP. Enumeration-safe and silent
	// (throttle/send failures are logged, never surfaced), exactly like
	// RequestEmailLoginCode — keyed by the same canonical email the challenge
	// is bound to, so CompletePasskeySignup verifies against the matching code.
	s.sendEmailLoginCode(ctx, email)

	s.logger.Info(
		"passkey_signup_begin",
		zap.String("email", redactEmail(email)),
		zap.String("challenge_id", challengeID),
	)
	return optionsJSON, challengeID, nil
}

// ── CompletePasskeySignup ──────────────────────────────────────────────

// CompletePasskeySignup verifies the attestation produced for a
// BeginPasskeySignup challenge, verifies the emailed OTP, and finalizes account
// creation.
//
// Checks run in a fixed, enumeration-safe order — none of them look up the
// account, so neither a passkey nor an OTP failure can be turned into an
// existence oracle:
//
//  1. Verify the WebAuthn attestation against the challenge.
//  2. Verify+consume the OTP against the bound email. Any failure
//     (wrong/expired/exhausted) returns one generic error, identical for new
//     and existing addresses.
//  3. Only after a VALID OTP, resolve the email:
//     - New email: creates the User under the id bound as the WebAuthn handle,
//     already EmailVerified (the OTP proved control — there is no unverified-
//     passkey state, so the pre-hijacking scenario cannot arise), stores the
//     passkey credential, and issues a session.
//     - Existing email: does NOT attach the passkey (anti-takeover) and does
//     NOT reveal that the address exists — it returns a success-shaped decoy
//     whose token presence is identical to the new-account path (which always
//     issues a session here) regardless of GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL,
//     and sends the existing-account notice. (Only an inbox-controller has a
//     valid OTP, so this discloses nothing they don't already know.)
//
// It is unauthenticated: no session is required to call it.
func (s *AuthService) CompletePasskeySignup(
	ctx context.Context,
	challengeID, credentialJSON, email, otpCode, deviceName, ipAddr, userAgent string,
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

	// Prove control of the email IN-FLOW before any account decision. This runs
	// before the existence lookup, so a wrong/expired OTP returns one generic
	// error identical for new and existing addresses (no existence oracle), and
	// — crucially — no account is ever created without proven inbox control, so
	// there is no unverified-passkey state to pre-hijack. Reuses the passwordless
	// email-code verify+consume path against the bound (canonical) email.
	//
	// CRITICAL ORDERING: the OTP is verified BEFORE the single-use challenge is
	// consumed. CompleteRegistration above is a stateless re-verification that
	// does not need the challenge deleted, so a wrong/expired OTP can return the
	// generic error while LEAVING THE CHALLENGE INTACT — the client re-submits
	// the SAME credentialJSON with a corrected code and the attempt is retryable
	// (the OTP's own MaxAttempts cap and expiry still govern). Consuming the
	// challenge before the OTP would burn it on the first mistyped code, forcing
	// a fresh BeginPasskeySignup + a second navigator.credentials.create ceremony
	// (orphaning the first credential) on the most error-prone step.
	if err := s.verifyAndConsumeEmailLoginCode(ctx, boundEmail, otpCode, "passkey_signup", ipAddr, userAgent); err != nil {
		s.logger.Warn("passkey_signup_otp_failed", zap.String("email", redactEmail(boundEmail)))
		return nil, err
	}

	// Both the attestation and the OTP are now proven. Consume the single-use
	// challenge before resolving the account so a replay racing this completion
	// loses.
	_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)

	// Project access mode (self-signup context): refuse to provision a non-member.
	// Placed before the existence check so a denied address returns the same
	// generic error whether or not it already has an account — no existence
	// oracle — and the guard runs on the canonical bound email the account would
	// be created under. Invite/closed modes deny; an existing invite-only user
	// keeps signing in via CompletePasskeyLogin (a login-context check).
	if err := s.enforceProjectAccessSignup(ctx, boundEmail); err != nil {
		return nil, err
	}

	// Anti-takeover + enumeration-safety: an existing account is never given a
	// new passkey by an unauthenticated caller, and its existence is never
	// disclosed. Mirror the duplicate-PasswordSignup decoy exactly.
	existing, err := s.repo(ctx).FindUserByEmail(ctx, boundEmail)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return s.handleDuplicatePasskeySignup(ctx, existing, boundEmail)
	}

	now := s.nowMs()
	user := &User{
		ID:     challenge.UserID, // == WebAuthn handle minted at Begin
		Email:  boundEmail,
		Name:   fallbackDisplayName(boundEmail, ""),
		Role:   "member",
		Status: "active",
		// The consumed OTP proved control of this inbox, so the account is
		// created already verified — there is never an unverified account
		// carrying a passkey, which is what closes the pre-hijacking surface.
		EmailVerified:   true,
		EmailVerifiedAt: now,
		CreatedAt:       msToTime(now),
		UpdatedAt:       msToTime(now),
	}
	userID, err := s.repo(ctx).CreateUser(ctx, user)
	if err != nil {
		// Lost a create race (a concurrent caller registered the email between
		// our lookup and insert). Treat as duplicate: enumeration-safe, and the
		// passkey is NOT attached to the winner's account.
		if raced, lookupErr := s.repo(ctx).FindUserByEmail(ctx, boundEmail); lookupErr == nil && raced != nil {
			return s.handleDuplicatePasskeySignup(ctx, raced, boundEmail)
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

	// No verification email is sent: the consumed OTP already proved control of
	// the address, so the account is created verified.

	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "passkey_signup"}),
	)

	// No email-verification gate applies here: the OTP proved control of the
	// inbox, so the account is created verified and a live session always
	// issues. (PasswordSignup gates because it creates an UNVERIFIED account;
	// this flow has no such state.) A non-inbox-controller can never reach this
	// point — an invalid OTP fails above with a generic error — so issuing a
	// session reveals nothing to an attacker who lacks the emailed code.
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
