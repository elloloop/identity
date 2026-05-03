package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// dummyPasswordHash is a precomputed bcrypt hash used to equalize the
// timing of PasswordLogin when the email is not found. Without it,
// the user-not-found path returns immediately while the wrong-password
// path runs bcrypt (~250ms at cost 12) — a textbook email-enumeration
// timing oracle. We bcrypt the dummy hash exactly once per process.
var (
	dummyPasswordHash     string
	dummyPasswordHashOnce sync.Once
)

func getDummyPasswordHash() string {
	dummyPasswordHashOnce.Do(func() {
		h, err := passwords.Hash("dummy-fixed-password-for-timing-equalization")
		if err != nil {
			// Fallback: a static, well-formed bcrypt hash. Verify will still
			// run constant-time bcrypt against this value.
			dummyPasswordHash = "$2a$12$0000000000000000000000000000000000000000000000000000O"
			return
		}
		dummyPasswordHash = h
	})
	return dummyPasswordHash
}

// ── PasswordSignup ─────────────────────────────────────────────────────

// PasswordSignup creates a new user with email + password and issues tokens.
func (s *AuthService) PasswordSignup(ctx context.Context, email, password, name, recoveryEmail string) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: invalid email", ErrInvalidArgument)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	existing, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("%w: user already exists", ErrAlreadyExists)
	}

	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	displayName := name
	if displayName == "" {
		displayName = strings.Split(email, "@")[0]
	}
	now := s.nowMs()
	recEmail := strings.TrimSpace(strings.ToLower(recoveryEmail))

	userID, err := s.repo.CreateUser(ctx, &User{
		Email:         email,
		Name:          displayName,
		Role:          "member",
		Status:        "active",
		PasswordHash:  pwHash,
		RecoveryEmail: recEmail,
		CreatedAt:     msToTime(now),
		UpdatedAt:     msToTime(now),
	})
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	user := &User{
		ID:        userID,
		Email:     email,
		Name:      displayName,
		Role:      "member",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	}
	s.logger.Info("local_signup_success", zap.String("email", email), zap.String("user_id", userID))
	s.ensureMailbox(ctx, userID, email, displayName)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, "", "")
	if err != nil {
		return nil, err
	}

	s.audit.Log(ctx, audit.EventLoginSuccess,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "signup"}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ── PasswordLogin ──────────────────────────────────────────────────────

// PasswordLogin authenticates a user with email + password.
// If TOTP is enabled, returns TotpRequired=true with a LoginChallengeID.
func (s *AuthService) PasswordLogin(ctx context.Context, email, password, ipAddr, userAgent string) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: invalid email", ErrInvalidArgument)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}

	user, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// Run a dummy bcrypt verification so the response time for an
		// unknown email is comparable to the wrong-password path. This
		// closes the email-enumeration timing oracle (the bcrypt cost
		// dominates wall time; without this, the no-user path returns in
		// microseconds while the wrong-password path takes ~250ms).
		_ = passwords.Verify(password, getDummyPasswordHash())
		s.logger.Info("local_login_failed", zap.String("reason", "user_not_found"))
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "user_not_found", "email": email}),
		)
		return nil, fmt.Errorf("%w: invalid email or password", ErrUnauthenticated)
	}

	// Lockout check.
	if user.LockedUntil > 0 && user.LockedUntil > s.nowMs() {
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "account_locked"}),
		)
		return nil, fmt.Errorf("%w: account temporarily locked due to too many failed attempts", ErrAccountLocked)
	}

	// No password set (OAuth-only user).
	if user.PasswordHash == "" {
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "no_password_set"}),
		)
		return nil, fmt.Errorf("%w: no password set for this account", ErrNoPasswordSet)
	}

	if !passwords.Verify(password, user.PasswordHash) {
		s.recordFailedLogin(ctx, user)
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "password_mismatch"}),
		)
		return nil, fmt.Errorf("%w: invalid email or password", ErrUnauthenticated)
	}

	// Enforce account status.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	// Password verified -- reset failed-attempt counters.
	s.resetFailedLogin(ctx, user)

	// 2FA branch: TOTP required.
	if user.TotpRequired {
		challengeID, err := s.issueLoginChallenge(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			User:             user,
			TotpRequired:     true,
			LoginChallengeID: challengeID,
		}, nil
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("local_login_success", zap.String("email", email), zap.String("user_id", user.ID))
	s.audit.Log(ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "password"}),
	)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ── OAuthLogin ─────────────────────────────────────────────────────────

// OAuthLogin is a placeholder for the OAuth code exchange flow.
// The actual OIDC token exchange and validation would be injected as a
// dependency; this method handles the post-validation user upsert + token issuance.
func (s *AuthService) OAuthLogin(ctx context.Context, email, displayName, avatarURL, provider, ipAddr, userAgent string) (*LoginResult, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required from OAuth provider", ErrInvalidArgument)
	}
	email = strings.TrimSpace(strings.ToLower(email))

	user, isNew, err := s.upsertUser(ctx, email, displayName, avatarURL)
	if err != nil {
		return nil, err
	}

	// Enforce account status.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("oauth_login_success",
		zap.String("email", email), zap.String("provider", provider), zap.String("user_id", user.ID),
	)

	if isNew {
		s.ensureMailbox(ctx, user.ID, email, displayName)
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.audit.Log(ctx, audit.EventOAuthLogin,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"provider": provider}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int32(s.cfg.JWTExpirySeconds),
	}, nil
}

// upsertUser finds a user by email or creates one. Returns (user, isNew, error).
func (s *AuthService) upsertUser(ctx context.Context, email, displayName, avatarURL string) (*User, bool, error) {
	existing, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		changed := make(map[string]any)
		if displayName != "" && displayName != existing.Name {
			changed["name"] = displayName
		}
		if avatarURL != "" && avatarURL != existing.AvatarURL {
			changed["avatar_url"] = avatarURL
		}
		if len(changed) > 0 {
			changed["updated_at"] = s.nowMs()
			if err := s.repo.UpdateUser(ctx, existing.ID, changed); err != nil {
				s.logger.Warn("upsert_user_update_failed", zap.Error(err))
			}
		}
		return existing, false, nil
	}

	now := s.nowMs()
	if displayName == "" {
		displayName = strings.Split(email, "@")[0]
	}
	userID, err := s.repo.CreateUser(ctx, &User{
		Email:     email,
		Name:      displayName,
		AvatarURL: avatarURL,
		Role:      "member",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	})
	if err != nil {
		return nil, false, fmt.Errorf("creating user: %w", err)
	}
	user := &User{
		ID:        userID,
		Email:     email,
		Name:      displayName,
		AvatarURL: avatarURL,
		Role:      "member",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	}
	s.logger.Info("user_auto_provisioned", zap.String("email", email), zap.String("user_id", userID))
	return user, true, nil
}

// checkAccountStatus verifies the user's status allows login.
func (s *AuthService) checkAccountStatus(_ context.Context, user *User, _, _ string) error {
	status := strings.ToLower(user.Status)
	if status == "" || status == "active" {
		return nil
	}
	if status == "invited" {
		return fmt.Errorf("%w: accept your invitation first", ErrInvitationPending)
	}
	return fmt.Errorf("%w: account is %s", ErrAccountNotActive, status)
}

// ── AcceptInvitation ───────────────────────────────────────────────────

// AcceptInvitation completes an admin-issued invitation.
func (s *AuthService) AcceptInvitation(ctx context.Context, invitationToken, password, name, ipAddr, userAgent string) (*LoginResult, error) {
	if invitationToken == "" {
		return nil, fmt.Errorf("%w: invitation token is required", ErrInvalidArgument)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	tokenHash := hashInvitationToken(invitationToken)
	inv, err := s.repo.FindInvitationByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, fmt.Errorf("%w: invalid invitation token", ErrUnauthenticated)
	}
	if inv.AcceptedAt > 0 {
		return nil, ErrInvitationUsed
	}
	if inv.ExpiresAt > 0 && inv.ExpiresAt < s.nowMs() {
		return nil, ErrInvitationExpired
	}

	// Find the user associated with the invitation.
	var user *User
	if inv.UserID != "" {
		user, err = s.repo.GetUser(ctx, inv.UserID)
		if err != nil {
			return nil, err
		}
	}
	if user == nil && inv.Email != "" {
		user, err = s.repo.FindUserByEmail(ctx, inv.Email)
		if err != nil {
			return nil, err
		}
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user for invitation not found", ErrNotFound)
	}

	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	now := s.nowMs()
	patch := map[string]any{
		"password_hash": pwHash,
		"status":        "active",
		"updated_at":    now,
	}
	if name != "" {
		patch["name"] = strings.TrimSpace(name)
		user.Name = strings.TrimSpace(name)
	}
	if err := s.repo.UpdateUser(ctx, user.ID, patch); err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}

	// Mark invitation as accepted.
	_ = s.repo.UpdateInvitation(ctx, inv.NodeID, map[string]any{"accepted_at": now})

	user.Status = "active"
	user.UpdatedAt = msToTime(now)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("invitation_accepted", zap.String("user_id", user.ID))
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int32(s.cfg.JWTExpirySeconds),
	}, nil
}

// msToTime converts epoch milliseconds to time.Time.
func msToTime(ms int64) time.Time {
	return time.UnixMilli(ms)
}
