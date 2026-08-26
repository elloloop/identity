package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

// ── BeginPasskeyRegistration ───────────────────────────────────────────

// BeginPasskeyRegistration generates WebAuthn registration options for the
// authenticated user. Returns (optionsJSON, challengeID, error).
func (s *AuthService) BeginPasskeyRegistration(ctx context.Context, userID, deviceName string) (string, string, error) {
	// Refused at BEGIN, not only at completion: this call persists a
	// challenge row, and the anonymous retention sweep does not reach the
	// challenge tables (no FK to users), so an anonymous caller could
	// accumulate rows the sweep never reclaims. Completion is guarded too.
	if err := s.refuseAnonymousCredentialAttach(ctx, userID); err != nil {
		return "", "", err
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if user == nil {
		return "", "", fmt.Errorf("%w: user not found", ErrNotFound)
	}

	existing, err := s.repo(ctx).ListPasskeyCredentials(ctx, userID)
	if err != nil {
		return "", "", err
	}
	existingIDs := make([]string, 0, len(existing))
	for _, c := range existing {
		if c.CredentialID != "" {
			existingIDs = append(existingIDs, c.CredentialID)
		}
	}

	optionsJSON, challengeB64, err := s.passkeysFor(ctx).BeginRegistration(
		userID, user.Email, coalesce(user.Name, user.Email), existingIDs,
	)
	if err != nil {
		return "", "", fmt.Errorf("building registration options: %w", err)
	}

	now := s.nowMs()
	nodeID, err := s.repo(ctx).CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{
		Challenge:     challengeB64,
		UserID:        userID,
		ChallengeType: "registration",
		ExpiresAt:     now + int64(s.cfg.PasskeyChallengeExpirySeconds)*1000,
		CreatedAt:     now,
	})
	if err != nil {
		return "", "", fmt.Errorf("storing challenge: %w", err)
	}

	s.logger.Info(
		"passkey_registration_begin",
		zap.String("user_id", userID),
		zap.String("challenge_id", nodeID),
		zap.Int("existing_credentials", len(existingIDs)),
	)
	return optionsJSON, nodeID, nil
}

// ── CompletePasskeyRegistration ────────────────────────────────────────

// VerifyPasskeyEnrolmentTicket verifies a managed-child passkey-enrolment
// ticket (purpose `passkey_enrolment`, minted by CreateManagedChildAccount)
// and returns the child account id the ceremony enrols. The Connect layer
// calls it to resolve the account a session-less ceremony runs for; the
// ticket rides in the request BODY because a purpose JWT is never a session
// credential (the auth middleware refuses to authenticate one).
//
// The ticket is single-purpose but NOT single-use within its TTL: enrolling
// passkeys on two of the child's devices inside the window is legitimate.
func (s *AuthService) VerifyPasskeyEnrolmentTicket(ctx context.Context, ticket string) (string, error) {
	if ticket == "" {
		return "", fmt.Errorf("%w: enrolment ticket is required", ErrInvalidArgument)
	}
	claims, err := s.verifyPurposeTicket(ctx, ticket, tokenPurposePasskeyEnrolment)
	if err != nil {
		return "", err
	}
	return claims.Sub, nil
}

// CompletePasskeyRegistration verifies the attestation response and stores the
// new credential. When issueSession is true — the managed-child enrolment
// path, where the ceremony redeemed an enrolment ticket and the child has no
// session yet — it also issues the account's first token pair through the
// normal issuance chokepoint; the returned LoginResult is nil otherwise and
// the response shape is exactly what a session-authenticated completion
// returns today.
func (s *AuthService) CompletePasskeyRegistration(ctx context.Context, userID, challengeID, credentialJSON, deviceName string, issueSession bool, ipAddr, userAgent string) (*PasskeyInfo, *LoginResult, error) {
	if challengeID == "" || credentialJSON == "" {
		return nil, nil, fmt.Errorf("%w: challenge_id and credential_json are required", ErrInvalidArgument)
	}
	// A passkey is a permanent credential; an anonymous caller must go
	// through UpgradeAnonymousAccount so the flag is cleared with it.
	if err := s.refuseAnonymousCredentialAttach(ctx, userID); err != nil {
		return nil, nil, err
	}

	challenge, err := s.repo(ctx).GetPasskeyChallenge(ctx, challengeID)
	if err != nil {
		return nil, nil, err
	}
	if challenge == nil {
		return nil, nil, fmt.Errorf("%w: challenge not found or already consumed", ErrNotFound)
	}
	if challenge.ChallengeType != "registration" {
		return nil, nil, fmt.Errorf("%w: challenge is not a registration challenge", ErrInvalidArgument)
	}
	if challenge.UserID != userID {
		return nil, nil, fmt.Errorf("%w: challenge does not belong to this user", ErrPermissionDenied)
	}
	if challenge.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
		return nil, nil, fmt.Errorf("%w: challenge expired", ErrTokenExpired)
	}

	result, err := s.passkeysFor(ctx).CompleteRegistration(credentialJSON, challenge.Challenge)
	if err != nil {
		s.logger.Warn(
			"passkey_registration_verify_failed",
			zap.String("user_id", userID), zap.Error(err),
		)
		return nil, nil, fmt.Errorf("%w: attestation verification failed", ErrInvalidArgument)
	}

	now := s.nowMs()
	_, err = s.repo(ctx).CreatePasskeyCredential(ctx, &PasskeyCredRecord{
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
	})
	if err != nil {
		return nil, nil, fmt.Errorf("storing credential: %w", err)
	}

	// Single-use challenge -- delete it.
	_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)

	s.logger.Info(
		"passkey_registered",
		zap.String("user_id", userID),
		zap.String("credential_id", result.CredentialID),
		zap.String("device_name", deviceName),
	)

	s.audit.Log(
		ctx, audit.EventPasskeyAdded,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"credential_id": result.CredentialID}),
	)

	info := &PasskeyInfo{
		CredentialID: result.CredentialID,
		DeviceName:   deviceName,
		CreatedAt:    msToTime(now),
		LastUsedAt:   msToTime(now),
	}
	if !issueSession {
		return info, nil, nil
	}

	// Managed-child enrolment path: the ticket took the place of a session,
	// so completion issues the account's first one. The account status gate
	// runs first — a child deactivated between ticket mint and redemption must
	// not gain a session. Token issuance goes through the normal chokepoint
	// (issueTokens), so the product age gate and the required-DOB gate apply
	// here exactly as on any login.
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, nil, err
	}
	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, nil, err
	}
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "passkey_enrolment"}),
	)
	return info, &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ── BeginPasskeyLogin ──────────────────────────────────────────────────

// BeginPasskeyLogin generates WebAuthn authentication options.
// If email is provided, scopes to that user's credentials. Otherwise allows
// discoverable credentials (usernameless flow).
func (s *AuthService) BeginPasskeyLogin(ctx context.Context, email string) (string, string, error) {
	var allowedIDs []string
	if email != "" {
		email = trimEmail(email)
		user, err := s.repo(ctx).FindUserByEmail(ctx, email)
		if err != nil {
			return "", "", err
		}
		if user != nil {
			creds, err := s.repo(ctx).ListPasskeyCredentials(ctx, user.ID)
			if err != nil {
				return "", "", err
			}
			for _, c := range creds {
				if c.CredentialID != "" {
					allowedIDs = append(allowedIDs, c.CredentialID)
				}
			}
		}
		// If user doesn't exist or has no passkeys, fall through with empty
		// allow list to prevent email enumeration.
	}

	optionsJSON, challengeB64, err := s.passkeysFor(ctx).BeginAuthentication(allowedIDs)
	if err != nil {
		return "", "", fmt.Errorf("building authentication options: %w", err)
	}

	now := s.nowMs()
	nodeID, err := s.repo(ctx).CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{
		Challenge:     challengeB64,
		ChallengeType: "authentication",
		ExpiresAt:     now + int64(s.cfg.PasskeyChallengeExpirySeconds)*1000,
		CreatedAt:     now,
	})
	if err != nil {
		return "", "", fmt.Errorf("storing challenge: %w", err)
	}

	s.logger.Info(
		"passkey_login_begin",
		zap.String("challenge_id", nodeID),
		zap.Int("allowed_credentials", len(allowedIDs)),
	)
	return optionsJSON, nodeID, nil
}

// ── CompletePasskeyLogin ───────────────────────────────────────────────

// CompletePasskeyLogin verifies the assertion response and issues tokens.
func (s *AuthService) CompletePasskeyLogin(ctx context.Context, challengeID, credentialJSON, ipAddr, userAgent string) (*LoginResult, error) {
	if challengeID == "" || credentialJSON == "" {
		return nil, fmt.Errorf("%w: challenge_id and credential_json are required", ErrInvalidArgument)
	}

	challenge, err := s.repo(ctx).GetPasskeyChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if challenge == nil {
		return nil, fmt.Errorf("%w: invalid or expired challenge", ErrUnauthenticated)
	}
	if challenge.ChallengeType != "authentication" {
		return nil, fmt.Errorf("%w: challenge is not an authentication challenge", ErrInvalidArgument)
	}
	if challenge.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
		return nil, fmt.Errorf("%w: challenge expired", ErrUnauthenticated)
	}

	credID, err := passkeys.ExtractCredentialID(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid credential_json: %w", ErrInvalidArgument, err)
	}

	cred, err := s.repo(ctx).GetPasskeyCredentialByCredID(ctx, credID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("%w: unknown credential", ErrUnauthenticated)
	}
	if cred.UserID == "" {
		return nil, errors.New("credential missing user_id")
	}
	if cred.SignCount > int64(math.MaxUint32) {
		return nil, errors.New("credential sign_count overflows WebAuthn counter")
	}

	newSignCount, err := s.passkeysFor(ctx).CompleteAuthentication(
		credentialJSON,
		challenge.Challenge,
		cred.PublicKey,
		uint32(cred.SignCount), // #nosec G115 -- bounds checked above.
		cred.CredentialID,
		cred.UserID,
		cred.BackupEligible,
		cred.BackupState,
	)
	if err != nil {
		s.logger.Warn(
			"passkey_login_verify_failed",
			zap.String("user_id", cred.UserID),
			zap.String("credential_id", credID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("%w: passkey verification failed", ErrUnauthenticated)
	}

	// Update sign count.
	now := s.nowMs()
	_ = s.repo(ctx).UpdatePasskeyCredential(ctx, cred.NodeID, map[string]any{
		"sign_count":   int64(newSignCount),
		"last_used_at": now,
	})

	// Single-use challenge.
	_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)

	user, err := s.repo(ctx).GetUser(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	// Enforce account status + lockout before issuing tokens. Without
	// this, an account locked by failed-password attempts would still
	// be loginable via passkey, defeating the lockout entirely.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	// A valid assertion proves credential possession, but a closed/allowlist
	// project must still refuse a non-member — otherwise a passkey enrolled
	// before the project was restricted would keep working. user.Email is the
	// DB-persisted (canonical) account email; wrap once (idempotent, self-heals).
	if err := s.enforceProjectAccessLogin(ctx, canonicalize(user.Email)); err != nil {
		return nil, err
	}

	// Consult the tenant's LoginPolicy before issuing tokens. A passkey is a
	// distinct authentication method, so a tenant that disallows it via its
	// AllowedMethods allow-list — or one that requires SSO — must be honoured
	// here too, otherwise the policy could be bypassed by enrolling and using
	// a passkey. A passkey is itself a strong factor, so it satisfies a
	// Require2FA policy on its own and never yields a second-factor decision.
	if _, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodPasskey); err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info(
		"passkey_login_success",
		zap.String("user_id", user.ID),
		zap.String("credential_id", credID),
	)

	s.audit.Log(
		ctx, audit.EventPasskeyUsed,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"credential_id": credID}),
	)
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "passkey"}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ���─ helpers ────────────────────────────────────────────────────────────

func trimEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// passkeysFor returns the WebAuthn relying-party instance to use for the
// request in ctx. When the resolved project's config_json sets a passkey
// block, a per-project instance bound to that RP-ID/RPName/Origin is used (and
// memoised) so a passkey registered under one product's domain validates under
// that product's RP-ID. A project that sets only some fields inherits the rest
// from the global GATEWAY_PASSKEY_* values. When nothing is overridden — the
// zero-config case — the global s.passkeys is returned unchanged, keeping
// today's behaviour byte-for-byte.
//
// Building a per-project instance can fail only on an invalid override (e.g. a
// malformed origin), which the project-config write path already rejects; if it
// somehow fails here we fall back to the global instance rather than break the
// ceremony.
func (s *AuthService) passkeysFor(ctx context.Context) *passkeys.WebAuthnService {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return s.passkeys
	}
	p := scope.Passkey
	if p.RPID == "" && p.RPName == "" && p.Origin == "" {
		return s.passkeys
	}
	cfg := passkeys.Config{
		RPID:   coalesce(p.RPID, s.cfg.PasskeyRPID),
		RPName: coalesce(p.RPName, s.cfg.PasskeyRPName),
		Origin: coalesce(p.Origin, s.cfg.PasskeyOrigin),
	}
	key := cfg.RPID + "\x00" + cfg.RPName + "\x00" + cfg.Origin

	s.passkeyRPCacheMu.RLock()
	wa := s.passkeyRPCache[key]
	s.passkeyRPCacheMu.RUnlock()
	if wa != nil {
		return wa
	}

	built, err := passkeys.NewWebAuthnService(cfg)
	if err != nil {
		s.logger.Warn("passkey_rp_override_invalid",
			zap.String("project_id", scope.ProjectID), zap.Error(err))
		return s.passkeys
	}

	s.passkeyRPCacheMu.Lock()
	if s.passkeyRPCache == nil {
		s.passkeyRPCache = map[string]*passkeys.WebAuthnService{}
	}
	if existing := s.passkeyRPCache[key]; existing != nil {
		built = existing
	} else {
		s.passkeyRPCache[key] = built
	}
	s.passkeyRPCacheMu.Unlock()
	return built
}
