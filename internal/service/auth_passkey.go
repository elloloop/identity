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

	optionsJSON, challengeB64, err := s.passkeys.BeginRegistration(
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

// CompletePasskeyRegistration verifies the attestation response and stores the
// new credential. Returns (credentialInfo, error).
func (s *AuthService) CompletePasskeyRegistration(ctx context.Context, userID, challengeID, credentialJSON, deviceName string) (*PasskeyInfo, error) {
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
	if challenge.ChallengeType != "registration" {
		return nil, fmt.Errorf("%w: challenge is not a registration challenge", ErrInvalidArgument)
	}
	if challenge.UserID != userID {
		return nil, fmt.Errorf("%w: challenge does not belong to this user", ErrPermissionDenied)
	}
	if challenge.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
		return nil, fmt.Errorf("%w: challenge expired", ErrTokenExpired)
	}

	result, err := s.passkeys.CompleteRegistration(credentialJSON, challenge.Challenge)
	if err != nil {
		s.logger.Warn(
			"passkey_registration_verify_failed",
			zap.String("user_id", userID), zap.Error(err),
		)
		return nil, fmt.Errorf("%w: attestation verification failed", ErrInvalidArgument)
	}

	now := s.nowMs()
	_, err = s.repo(ctx).CreatePasskeyCredential(ctx, &PasskeyCredRecord{
		CredentialID: result.CredentialID,
		UserID:       userID,
		PublicKey:    result.PublicKey,
		SignCount:    int64(result.SignCount),
		DeviceName:   deviceName,
		AAGUID:       result.AAGUID,
		Transports:   result.Transports,
		CreatedAt:    now,
		LastUsedAt:   now,
	})
	if err != nil {
		return nil, fmt.Errorf("storing credential: %w", err)
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

	return &PasskeyInfo{
		CredentialID: result.CredentialID,
		DeviceName:   deviceName,
		CreatedAt:    msToTime(now),
		LastUsedAt:   msToTime(now),
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

	optionsJSON, challengeB64, err := s.passkeys.BeginAuthentication(allowedIDs)
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

	newSignCount, err := s.passkeys.CompleteAuthentication(
		credentialJSON,
		challenge.Challenge,
		cred.PublicKey,
		uint32(cred.SignCount), // #nosec G115 -- bounds checked above.
		cred.CredentialID,
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

	// Consult the tenant's LoginPolicy before issuing tokens. A passkey is a
	// distinct authentication method, so a tenant that disallows it via its
	// AllowedMethods allow-list must be honoured here too — otherwise the
	// allow-list could be bypassed by enrolling and using a passkey.
	if err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodPasskey); err != nil {
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
