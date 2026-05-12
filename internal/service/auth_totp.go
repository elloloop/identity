package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
	"github.com/elloloop/identity/pkg/totp"
)

// ── BeginTotpSetup ─────────────────────────────────────────────────────

// BeginTotpSetup starts TOTP enrollment for the authenticated user.
// Returns (secret, qrURI, recoveryCodes, error).
func (s *AuthService) BeginTotpSetup(ctx context.Context, userID string) (string, string, []string, error) {
	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return "", "", nil, err
	}
	if user == nil {
		return "", "", nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	// Clean up any previously-started (unverified) enrollment.
	existing, err := s.repo.GetTotpCredential(ctx, userID)
	if err != nil {
		return "", "", nil, err
	}
	if existing != nil && !existing.Verified {
		_ = s.repo.DeleteTotpCredential(ctx, existing.NodeID)
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		return "", "", nil, fmt.Errorf("generating TOTP secret: %w", err)
	}

	encrypted, err := totp.EncryptSecret(secret, s.totpKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("encrypting TOTP secret: %w", err)
	}

	now := s.nowMs()
	_, err = s.repo.CreateTotpCredential(ctx, &TotpCredRecord{
		UserID:          userID,
		SecretEncrypted: encrypted,
		Verified:        false,
		CreatedAt:       now,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("storing TOTP credential: %w", err)
	}

	email := user.Email
	if email == "" {
		email = userID
	}
	qrURI := totp.GenerateQRURI(secret, email, s.cfg.TOTPIssuer)

	recoveryCodes := totp.GenerateRecoveryCodes(10)
	if err := s.storeRecoveryCodes(ctx, userID, recoveryCodes); err != nil {
		return "", "", nil, err
	}

	s.logger.Info("totp_setup_begin", zap.String("user_id", userID))
	return secret, qrURI, recoveryCodes, nil
}

// ── VerifyTotpSetup ────────────────────────────────────────────────────

// VerifyTotpSetup completes TOTP enrollment by verifying a code. Returns (verified, error).
func (s *AuthService) VerifyTotpSetup(ctx context.Context, userID, code string) (bool, error) {
	if code == "" {
		return false, fmt.Errorf("%w: code is required", ErrInvalidArgument)
	}

	cred, err := s.repo.GetTotpCredential(ctx, userID)
	if err != nil {
		return false, err
	}
	if cred == nil {
		return false, fmt.Errorf("%w: no TOTP setup in progress", ErrNotFound)
	}

	secret, err := totp.DecryptSecret(cred.SecretEncrypted, s.totpKey)
	if err != nil {
		s.logger.Error("totp_decrypt_failed", zap.String("user_id", userID), zap.Error(err))
		return false, errors.New("could not decrypt TOTP secret")
	}

	if !totp.VerifyCode(secret, code) {
		s.audit.Log(
			ctx, audit.EventTotpEnabled,
			audit.WithActor(userID),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "invalid_code"}),
		)
		return false, fmt.Errorf("%w: invalid verification code", ErrInvalidTotpCode)
	}

	now := s.nowMs()
	_ = s.repo.UpdateTotpCredential(ctx, cred.NodeID, map[string]any{
		"verified":     true,
		"last_used_at": now,
	})
	_ = s.repo.UpdateUser(ctx, userID, map[string]any{
		"totp_required": true,
		"updated_at":    now,
	})

	s.audit.Log(
		ctx, audit.EventTotpEnabled,
		audit.WithActor(userID),
		audit.WithSuccess(true),
	)
	s.logger.Info("totp_setup_verified", zap.String("user_id", userID))
	return true, nil
}

// ── VerifyTotp ────────────────────────────────────────────────────────���

// VerifyTotp completes a pending login by verifying a TOTP or recovery code.
// Returns (user, accessToken, refreshToken, error).
func (s *AuthService) VerifyTotp(ctx context.Context, challengeID, code, ipAddr, userAgent string) (*LoginResult, error) {
	if challengeID == "" {
		return nil, fmt.Errorf("%w: login_challenge_id is required", ErrInvalidArgument)
	}
	if code == "" {
		return nil, fmt.Errorf("%w: code is required", ErrInvalidArgument)
	}

	record, err := s.consumeLoginChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	userID := record.UserID

	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	cred, err := s.repo.GetTotpCredential(ctx, userID)
	if err != nil {
		return nil, err
	}
	if cred == nil || !cred.Verified {
		return nil, fmt.Errorf("%w: TOTP is not enabled for this user", ErrNotFound)
	}

	totpOK := false
	recoveryUsed := false

	secret, err := totp.DecryptSecret(cred.SecretEncrypted, s.totpKey)
	if err != nil {
		s.logger.Error("totp_decrypt_failed", zap.String("user_id", userID), zap.Error(err))
		secret = ""
	}

	if secret != "" && totp.VerifyCode(secret, code) {
		totpOK = true
	} else {
		// Try recovery code.
		codeHash := totp.HashRecoveryCode(code, s.totpRecoveryPepper)
		if codeHash != "" {
			rc, rcErr := s.repo.FindRecoveryCodeByHash(ctx, userID, codeHash)
			if rcErr == nil && rc != nil && !rc.Used {
				_ = s.repo.UpdateRecoveryCode(ctx, rc.NodeID, map[string]any{
					"used":    true,
					"used_at": s.nowMs(),
				})
				recoveryUsed = true
			}
		}
	}

	if !totpOK && !recoveryUsed {
		s.audit.Log(
			ctx, audit.EventTotpVerified,
			audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "invalid_code"}),
		)
		return nil, fmt.Errorf("%w: invalid code", ErrInvalidTotpCode)
	}

	now := s.nowMs()
	_ = s.repo.UpdateTotpCredential(ctx, cred.NodeID, map[string]any{"last_used_at": now})
	s.updateLastLogin(ctx, userID)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	method := "totp"
	if recoveryUsed {
		method = "recovery_code"
	}
	s.audit.Log(
		ctx, audit.EventTotpVerified,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": method}),
	)
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "password+totp"}),
	)

	s.logger.Info(
		"totp_login_success",
		zap.String("user_id", userID),
		zap.Bool("recovery", recoveryUsed),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ── DisableTotp ────────────────────────────────────────────────────────

// DisableTotp disables 2FA for the authenticated user. Requires password confirmation.
func (s *AuthService) DisableTotp(ctx context.Context, userID, password string) error {
	if password == "" {
		return fmt.Errorf("%w: password confirmation required", ErrInvalidArgument)
	}

	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}

	if user.PasswordHash == "" || !passwords.Verify(password, user.PasswordHash) {
		return fmt.Errorf("%w: invalid password", ErrUnauthenticated)
	}

	_ = s.repo.DeleteTotpCredentialsForUser(ctx, userID)
	_ = s.repo.DeleteRecoveryCodesForUser(ctx, userID)
	_ = s.repo.UpdateUser(ctx, userID, map[string]any{
		"totp_required": false,
		"updated_at":    s.nowMs(),
	})

	s.audit.Log(
		ctx, audit.EventTotpDisabled,
		audit.WithActor(userID),
		audit.WithSuccess(true),
	)
	s.logger.Info("totp_disabled", zap.String("user_id", userID))
	return nil
}

// ── RegenerateRecoveryCodes ────────────────────────────────────────────

// RegenerateRecoveryCodes issues a fresh batch of recovery codes.
// Requires password confirmation and TOTP to be enabled.
func (s *AuthService) RegenerateRecoveryCodes(ctx context.Context, userID, password string) ([]string, error) {
	if password == "" {
		return nil, fmt.Errorf("%w: password confirmation required", ErrInvalidArgument)
	}

	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	if user.PasswordHash == "" || !passwords.Verify(password, user.PasswordHash) {
		return nil, fmt.Errorf("%w: invalid password", ErrUnauthenticated)
	}

	if !user.TotpRequired {
		return nil, fmt.Errorf("%w: TOTP is not enabled", ErrNotFound)
	}

	codes := totp.GenerateRecoveryCodes(10)
	if err := s.storeRecoveryCodes(ctx, userID, codes); err != nil {
		return nil, err
	}

	s.logger.Info("recovery_codes_regenerated", zap.String("user_id", userID))
	return codes, nil
}
