package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
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

const (
	passwordSignupMinDuration = 250 * time.Millisecond
	oauthStateTokenExpiry     = 5 * time.Minute
	maxInt32                  = int32(1<<31 - 1)
)

func secondsToInt32(seconds int) int32 {
	switch {
	case seconds <= 0:
		return 0
	case seconds > int(maxInt32):
		return maxInt32
	default:
		return int32(seconds)
	}
}

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

func finishPasswordSignupFloor(start time.Time) {
	if wait := time.Until(start.Add(passwordSignupMinDuration)); wait > 0 {
		time.Sleep(wait)
	}
}

func fallbackDisplayName(email, preferred string) string {
	if name := strings.TrimSpace(preferred); name != "" {
		return name
	}
	if local, _, ok := strings.Cut(email, "@"); ok && local != "" {
		return local
	}
	return "there"
}

// ── PasswordSignup ─────────────────────────────────────────────────────

// PasswordSignup creates a new user with email + password and issues tokens.
func (s *AuthService) PasswordSignup(ctx context.Context, email, password, name, recoveryEmail string) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	if !s.cfg.PasswordSignupEnabled {
		return nil, ErrSignupDisabled
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
	start := time.Now()
	defer finishPasswordSignupFloor(start)

	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	existing, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return s.handleDuplicatePasswordSignup(ctx, existing, email, name)
	}

	displayName := fallbackDisplayName(email, name)
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
		existing, lookupErr := s.repo.FindUserByEmail(ctx, email)
		if lookupErr == nil && existing != nil {
			return s.handleDuplicatePasswordSignup(ctx, existing, email, name)
		}
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

	// Best-effort: fire a verification email. Failures are logged but
	// must never fail signup itself.
	if err := s.SendEmailVerification(ctx, userID); err != nil {
		s.logger.Warn("signup_verification_email_failed",
			zap.String("user_id", userID), zap.Error(err))
	}

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
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

func (s *AuthService) handleDuplicatePasswordSignup(ctx context.Context, user *User, email, name string) (*LoginResult, error) {
	if err := s.sendExistingSignupNotice(ctx, user); err != nil {
		s.logger.Warn("duplicate_signup_notice_failed",
			zap.String("user_id", user.ID),
			zap.String("email", email),
			zap.Error(err),
		)
	}
	s.logger.Info("local_signup_existing_email", zap.String("email", email), zap.String("user_id", user.ID))
	return s.newDuplicateSignupResult(email, fallbackDisplayName(email, name))
}

func (s *AuthService) sendExistingSignupNotice(ctx context.Context, user *User) error {
	loginURL := s.appBaseURL()
	text := strings.Join([]string{
		fmt.Sprintf("Hi %s,", displayNameOrEmail(user)),
		"",
		"Someone tried to sign up with this email address.",
		"",
		"If this was you, sign in to your existing account here:",
		loginURL,
		"",
		"If this wasn't you, you can ignore this email.",
	}, "\n")
	return s.mailer.Send(ctx, email.Message{
		To:      user.Email,
		From:    s.cfg.SMTPFrom,
		Subject: "Someone tried to sign up with your email",
		Text:    text,
	})
}

func (s *AuthService) newDuplicateSignupResult(email, displayName string) (*LoginResult, error) {
	now := s.nowMs()
	user := &User{
		ID:        "signup-pending-" + randomToken(8),
		Email:     email,
		Name:      displayName,
		Role:      "member",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	}
	// Duplicate signup must not authenticate the caller, but it also
	// must not disclose whether the address already exists. We return a
	// success-shaped payload with an unstored refresh token and a JWT for
	// a synthetic subject that is absent from the repository.
	accessToken, err := jwt.CreateAccessToken(jwt.Claims{
		Sub:    user.ID,
		Email:  user.Email,
		Name:   user.Name,
		Role:   user.Role,
		Tenant: s.tenantID,
	}, s.keyRing, s.cfg.JWTExpiry())
	if err != nil {
		return nil, fmt.Errorf("creating duplicate-signup decoy token: %w", err)
	}
	refreshToken, _ := generateRefreshToken()
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
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

	// Lockout check. While locked, the account is blocked regardless of
	// password correctness — emit a dedicated `login_locked` audit event
	// so operators can distinguish "tried during lockout" from
	// "threshold tripped".
	if user.LockedUntil > 0 && user.LockedUntil > s.nowMs() {
		s.audit.Log(ctx, audit.EventLoginLocked,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"reason":       "account_locked",
				"locked_until": user.LockedUntil,
			}),
		)
		return nil, fmt.Errorf("%w: account temporarily locked due to too many failed attempts", ErrAccountLocked)
	}

	// Lockout window has passed. Reset count + LockedUntil before
	// proceeding so any subsequent failure starts a fresh count from 0.
	if user.LockedUntil > 0 && user.LockedUntil <= s.nowMs() {
		if err := s.repo.ResetFailedLoginCount(ctx, user.ID); err != nil {
			s.logger.Warn("failed_login_reset_post_lockout_failed",
				zap.String("user_id", user.ID), zap.Error(err))
		}
		user.FailedLoginCount = 0
		user.LockedUntil = 0
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
		// Record the failure. Errors propagate as ErrUnauthenticated so
		// a DB outage during the increment cannot be used to bypass the
		// lockout (fail-closed).
		_, lockedNow, recErr := s.recordFailedLogin(ctx, user)
		if recErr != nil {
			return nil, fmt.Errorf("%w: invalid email or password", ErrUnauthenticated)
		}
		if lockedNow {
			s.audit.Log(ctx, audit.EventAccountLocked,
				audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
				audit.WithSuccess(false),
				audit.WithDetails(map[string]any{
					"lockout_seconds": s.cfg.LoginLockoutSeconds,
					"max_attempts":    s.cfg.LoginMaxFailedAttempts,
				}),
			)
		}
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "password_mismatch"}),
		)
		return nil, fmt.Errorf("%w: invalid email or password", ErrUnauthenticated)
	}

	// Local password accounts may sign in before verifying email; only
	// account status is a hard gate here.
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
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ── OAuthLogin ─────────────────────────────────────────────────────────

// BeginOAuthLogin returns a provider authorization URL plus the
// server-minted state artifacts needed to complete the callback safely.
func (s *AuthService) BeginOAuthLogin(
	ctx context.Context,
	provider, redirectURI string,
) (*OAuthBeginResult, error) {
	if s.oauthRegistry == nil || s.oauthRegistry.Len() == 0 {
		return nil, ErrOAuthDisabled
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	redirectURI = strings.TrimSpace(redirectURI)
	if provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidArgument)
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("%w: redirect uri is required", ErrInvalidArgument)
	}

	exchanger, ok := s.oauthRegistry.Get(provider)
	if !ok {
		return nil, fmt.Errorf("%w: unknown oauth provider %q", ErrInvalidArgument, provider)
	}
	authorizer, ok := exchanger.(oauth.Authorizer)
	if !ok {
		return nil, fmt.Errorf("%w: oauth provider %q cannot start authorization", ErrInvalidArgument, provider)
	}

	state, err := oauth.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("generating oauth state: %w", err)
	}
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating oauth code verifier: %w", err)
	}
	stateToken, err := oauth.IssueStateToken(
		s.keyRing,
		provider,
		redirectURI,
		state,
		codeVerifier,
		oauthStateTokenExpiry,
		s.nowFunc().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	authorizationURL, err := authorizer.AuthorizationURL(
		ctx,
		redirectURI,
		state,
		oauth.CodeChallengeS256(codeVerifier),
	)
	if err != nil {
		_, mappedErr := s.mapOAuthError(err)
		return nil, mappedErr
	}

	return &OAuthBeginResult{
		AuthorizationURL: authorizationURL,
		State:            state,
		StateToken:       stateToken,
		CodeVerifier:     codeVerifier,
		ExpiresIn:        int32(oauthStateTokenExpiry / time.Second),
	}, nil
}

// OAuthLogin performs the full OAuth code-exchange flow: it looks up
// the registered Exchanger for the provider, swaps the code for a
// verified Identity, then upserts the local user and issues tokens.
//
// The frontend / gateway is NOT trusted to validate the user's
// identity; identity does the exchange itself. Provider access /
// refresh tokens are discarded — they are not persisted.
func (s *AuthService) OAuthLogin(
	ctx context.Context,
	code, provider, redirectURI, codeVerifier, state, stateToken, ipAddr, userAgent string,
) (*LoginResult, error) {
	if s.oauthRegistry == nil || s.oauthRegistry.Len() == 0 {
		return nil, ErrOAuthDisabled
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	redirectURI = strings.TrimSpace(redirectURI)
	if provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: code is required", ErrInvalidArgument)
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("%w: redirect uri is required", ErrInvalidArgument)
	}

	exchanger, ok := s.oauthRegistry.Get(provider)
	if !ok {
		return nil, fmt.Errorf("%w: unknown oauth provider %q", ErrInvalidArgument, provider)
	}

	if strings.TrimSpace(stateToken) != "" {
		claims, err := oauth.VerifyStateToken(
			stateToken,
			s.keyRing,
			provider,
			redirectURI,
			state,
			codeVerifier,
			s.nowFunc().UTC(),
		)
		if err != nil {
			s.logger.Info("oauth_state_validation_failed",
				zap.String("provider", provider),
				zap.Error(err),
			)
			return nil, fmt.Errorf("%w: invalid oauth state", ErrUnauthenticated)
		}
		codeVerifier = claims.CodeVerifier
	}

	if strings.TrimSpace(codeVerifier) != "" {
		ctx = oauth.WithCodeVerifier(ctx, codeVerifier)
	}

	identity, err := exchanger.Exchange(ctx, code, redirectURI)
	if err != nil {
		s.logger.Info("oauth_login_failed",
			zap.String("provider", provider), zap.Error(err),
		)
		s.audit.Log(ctx, audit.EventOAuthLogin,
			audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"provider": provider,
				"reason":   "code_exchange_failed",
			}),
		)
		return s.mapOAuthError(err)
	}

	email := strings.TrimSpace(strings.ToLower(identity.Email))
	if email == "" {
		return nil, fmt.Errorf("%w: provider returned no email", ErrUnauthenticated)
	}

	user, isNew, err := s.upsertOAuthUser(ctx, identity, email)
	if err != nil {
		return nil, err
	}

	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("oauth_login_success",
		zap.String("email", email),
		zap.String("provider", provider),
		zap.String("user_id", user.ID),
	)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.audit.Log(ctx, audit.EventOAuthLogin,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider": provider,
			"email":    email,
			"new_user": isNew,
		}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// mapOAuthError translates pkg/oauth sentinel errors into AuthService
// sentinels so the connect handler emits the right RPC code.
func (s *AuthService) mapOAuthError(err error) (*LoginResult, error) {
	switch {
	case errors.Is(err, oauth.ErrEmailNotVerified):
		return nil, fmt.Errorf("%w: provider email is not verified", ErrUnauthenticated)
	case errors.Is(err, oauth.ErrIdentityVerification):
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	case errors.Is(err, oauth.ErrCodeExchangeFailed):
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	default:
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
}

// upsertOAuthUser resolves the local User using a (provider,
// provider_user_id) lookup first so that a returning user keeps the same
// local account even when the provider's email has changed since their
// last login. If no link exists yet it falls back to the email-based
// lookup and finally creates a new user. In either non-replay branch it
// persists an OAuthIdentity row so the next login hits the fast path.
//
// Returns (user, isNewUser, error). isNewUser is true only when a new
// User row was created (not when an existing user got a fresh provider
// link).
func (s *AuthService) upsertOAuthUser(ctx context.Context, identity *oauth.Identity, email string) (*User, bool, error) {
	now := s.nowMs()

	// 1. (provider, sub) lookup — survives provider-side email change.
	if identity.ProviderUserID != "" {
		linked, err := s.repo.FindUserByProviderID(ctx, identity.Provider, identity.ProviderUserID)
		if err != nil {
			return nil, false, err
		}
		if linked != nil {
			s.applyOAuthProfileUpdates(ctx, linked, identity, email, now)
			return linked, false, nil
		}
	}

	// 2. Email-based lookup — first-time link of this provider to an
	// existing local user (may have signed up via password or another
	// provider).
	existing, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		s.applyOAuthProfileUpdates(ctx, existing, identity, email, now)
		s.linkOAuthIdentity(ctx, existing.ID, identity, email, now)
		return existing, false, nil
	}

	// 3. New user.
	displayName := fallbackDisplayName(email, identity.Name)
	userID, err := s.repo.CreateUser(ctx, &User{
		Email:           email,
		Name:            displayName,
		AvatarURL:       identity.AvatarURL,
		Role:            "member",
		Status:          "active",
		EmailVerified:   true,
		EmailVerifiedAt: now,
		CreatedAt:       msToTime(now),
		UpdatedAt:       msToTime(now),
	})
	if err != nil {
		return nil, false, fmt.Errorf("creating user: %w", err)
	}
	user := &User{
		ID:              userID,
		Email:           email,
		Name:            displayName,
		AvatarURL:       identity.AvatarURL,
		Role:            "member",
		Status:          "active",
		EmailVerified:   true,
		EmailVerifiedAt: now,
		CreatedAt:       msToTime(now),
		UpdatedAt:       msToTime(now),
	}
	s.linkOAuthIdentity(ctx, userID, identity, email, now)
	s.logger.Info("oauth_user_provisioned",
		zap.String("email", email),
		zap.String("user_id", userID),
		zap.String("provider", identity.Provider),
	)
	return user, true, nil
}

// applyOAuthProfileUpdates patches the local user record with any new
// fields from the provider (name, avatar, email-verified flag, and the
// email itself when the provider's email has changed since the link was
// first created). Failures are logged but don't fail the login — we
// already authenticated the user.
func (s *AuthService) applyOAuthProfileUpdates(ctx context.Context, u *User, identity *oauth.Identity, email string, nowMs int64) {
	patch := make(map[string]any)
	if identity.Name != "" && identity.Name != u.Name {
		patch["name"] = identity.Name
		u.Name = identity.Name
	}
	if identity.AvatarURL != "" && identity.AvatarURL != u.AvatarURL {
		patch["avatar_url"] = identity.AvatarURL
		u.AvatarURL = identity.AvatarURL
	}
	if !u.EmailVerified {
		patch["email_verified"] = true
		patch["email_verified_at"] = nowMs
		u.EmailVerified = true
		u.EmailVerifiedAt = nowMs
	}
	// If the provider asserts a new (verified) email and we found this
	// user via (provider, sub) — propagate the email change locally.
	// We deliberately do NOT change email when the local user was
	// resolved by FindUserByEmail (no change there by definition).
	if email != "" && email != u.Email {
		patch["email"] = email
		patch["email_verified"] = true
		patch["email_verified_at"] = nowMs
		u.Email = email
		u.EmailVerified = true
		u.EmailVerifiedAt = nowMs
	}
	if len(patch) == 0 {
		return
	}
	patch["updated_at"] = nowMs
	if err := s.repo.UpdateUser(ctx, u.ID, patch); err != nil {
		s.logger.Warn("oauth_upsert_update_failed", zap.Error(err))
	}
}

// linkOAuthIdentity persists the (provider, sub) → user_id linkage and
// emits an audit event. Best-effort: a failure is logged but does not
// fail the login since the user has already been authenticated. On a
// duplicate-link race the duplicate is treated as success — the next
// login will simply hit the fast path.
func (s *AuthService) linkOAuthIdentity(ctx context.Context, userID string, identity *oauth.Identity, email string, nowMs int64) {
	if identity.ProviderUserID == "" || identity.Provider == "" {
		return
	}
	oi := &OAuthIdentity{
		UserID:          userID,
		Provider:        identity.Provider,
		ProviderUserID:  identity.ProviderUserID,
		EmailAtLinkTime: email,
		CreatedAt:       nowMs,
	}
	if err := s.repo.CreateOAuthIdentity(ctx, oi); err != nil {
		s.logger.Warn("oauth_identity_link_failed",
			zap.String("user_id", userID),
			zap.String("provider", identity.Provider),
			zap.Error(err),
		)
		return
	}
	s.audit.Log(ctx, audit.EventType("oauth_identity_linked"),
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider":           identity.Provider,
			"provider_user_id":   identity.ProviderUserID,
			"email_at_link_time": email,
		}),
	)
}

// checkAccountStatus verifies the user's status allows login. When the
// deployment requires identity verification (cfg.IDVRequired), unverified
// users are blocked with ErrIDVRequired so the client can route them to
// the BeginIdentityVerification flow.
func (s *AuthService) checkAccountStatus(_ context.Context, user *User, _, _ string) error {
	status := strings.ToLower(user.Status)
	switch status {
	case "", "active":
		// fall through
	case "invited":
		return fmt.Errorf("%w: accept your invitation first", ErrInvitationPending)
	default:
		return fmt.Errorf("%w: account is %s", ErrAccountNotActive, status)
	}

	if s.cfg != nil && s.cfg.IDVRequired && !user.IDVVerified {
		return ErrIDVRequired
	}
	return nil
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
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// msToTime converts epoch milliseconds to time.Time.
func msToTime(ms int64) time.Time {
	return time.UnixMilli(ms)
}
