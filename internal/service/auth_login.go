package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/events"
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
func (s *AuthService) PasswordSignup(ctx context.Context, email, password, name, recoveryEmail string, dateOfBirthMs int64) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	if !s.cfg.PasswordSignupEnabled {
		return nil, ErrSignupDisabled
	}
	if s.ageGate.Enabled() && s.cfg.AgeGateRequireDOB && dateOfBirthMs <= 0 {
		return nil, fmt.Errorf("%w: date of birth is required", ErrInvalidArgument)
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if err := validateEmailFormat(email); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	// Canonicalize for dedup + storage: dot-stripping for @gmail.com /
	// @googlemail.com local parts, universal '+' tag stripping,
	// googlemail.com → gmail.com. One human ↔ one account. Canonicalized ONCE
	// here and reused for both the access gate (cemail) and every DB op (email).
	cemail := canonicalize(email)
	email = string(cemail)
	// Before any password work, so a restricted project never mints a disallowed
	// account. Placed before the duplicate-email handling so the denial is
	// uniform for new and existing addresses (anti-enumeration).
	if err := s.enforceProjectAccessSignup(ctx, cemail); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if err := s.validatePasswordStrengthForEmail(ctx, email, password); err != nil {
		return nil, err
	}
	start := time.Now()
	defer finishPasswordSignupFloor(start)

	// Per-email signup throttle. Throttled requests return the same
	// anti-enumeration decoy as duplicate-email signups so the endpoint
	// cannot be used to probe which addresses have been recently
	// targeted. Complements the per-IP rate limit at the middleware
	// layer (which is keyed on resolved client IP).
	if !s.signupThrottle.allow(email, s.nowMs()) {
		s.logger.Info("signup_throttled", zap.String("email", redactEmail(email)))
		return s.newDuplicateSignupResult(ctx, email, fallbackDisplayName(email, name))
	}

	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	existing, err := s.repo(ctx).FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return s.handleDuplicatePasswordSignup(ctx, existing, email, name)
	}

	displayName := fallbackDisplayName(email, name)
	now := s.nowMs()
	recEmail := strings.TrimSpace(strings.ToLower(recoveryEmail))

	// Derive the age band from the supplied DOB. A child-band account under
	// age-gating is created in PENDING_PARENTAL_CONSENT and is not issued
	// tokens until verifiable parental consent is granted; every other band
	// (and a disabled gate) creates an active account exactly as before.
	ageDec := s.ageGate.Determine(dateOfBirthMs, s.nowFunc())
	status := "active"
	if s.ageGate.Enabled() && ageDec.Band == agegate.BandChild {
		status = StatusPendingParentalConsent
	}

	// COPPA data-minimization: never persist a recovery_email for a child
	// account. The recovery-email flow is a non-essential PII collection the
	// server declines to perform for a minor; the account row is still created
	// (in pending_parental_consent) so the parental-consent flow can proceed.
	if s.minorData.BlocksChild(dateOfBirthMs) && recEmail != "" {
		s.logger.Info("signup_recovery_email_dropped_minor", zap.String("user_id_email", redactEmail(email)))
		recEmail = ""
	}

	userID, err := s.repo(ctx).CreateUser(ctx, &User{
		Email:         email,
		Name:          displayName,
		Role:          "member",
		Status:        status,
		PasswordHash:  pwHash,
		RecoveryEmail: recEmail,
		DateOfBirthMs: dateOfBirthMs,
		CreatedAt:     msToTime(now),
		UpdatedAt:     msToTime(now),
	})
	if err != nil {
		existing, lookupErr := s.repo(ctx).FindUserByEmail(ctx, email)
		if lookupErr == nil && existing != nil {
			return s.handleDuplicatePasswordSignup(ctx, existing, email, name)
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}

	user := &User{
		ID:            userID,
		Email:         email,
		Name:          displayName,
		Role:          "member",
		Status:        status,
		DateOfBirthMs: dateOfBirthMs,
		CreatedAt:     msToTime(now),
		UpdatedAt:     msToTime(now),
	}
	s.stampAgeBand(user)
	s.logger.Info("local_signup_success", zap.String("email", redactEmail(email)), zap.String("user_id", userID))

	// A child-band account pending parental consent exists but cannot be
	// logged in: return the user (so the client can drive the consent flow)
	// with no tokens. The verification email is intentionally skipped — a
	// child account is not an email-owner we can solicit.
	if status == StatusPendingParentalConsent {
		s.audit.Log(
			ctx, audit.EventLoginSuccess,
			audit.WithActor(userID),
			audit.WithSuccess(true),
			audit.WithDetails(map[string]any{"method": "signup", "pending_parental_consent": true, "age_band": user.AgeBand}),
		)
		return &LoginResult{User: user}, nil
	}

	// Best-effort: auto-form a company tenant from the email domain.
	s.maybeAutoFormTenant(ctx, user)

	// Best-effort: emit a user.created lifecycle event for downstream
	// provisioning. No-op when eventing is disabled.
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), events.EventUserCreated, user)

	// Best-effort: fire a verification email. Failures are logged but
	// must never fail signup itself.
	if err := s.SendEmailVerification(ctx, userID); err != nil {
		s.logger.Warn("signup_verification_email_failed",
			zap.String("user_id", userID), zap.Error(err))
	}

	// When email verification is required, a freshly-created account is
	// unverified and must NOT receive a live session — otherwise signup would
	// auto-login past the very gate PasswordLogin enforces. Return the user
	// (so the client can drive "check your email") with no tokens; the proto
	// response shape is preserved, the tokens are simply empty.
	if s.cfg != nil && s.cfg.AuthRequireVerifiedEmail && !user.EmailVerified {
		s.audit.Log(
			ctx, audit.EventLoginSuccess,
			audit.WithActor(userID),
			audit.WithSuccess(true),
			audit.WithDetails(map[string]any{"method": "signup", "email_verification_required": true}),
		)
		return &LoginResult{User: user}, nil
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, "", "")
	if err != nil {
		return nil, err
	}

	s.audit.Log(
		ctx, audit.EventLoginSuccess,
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
		s.logger.Warn(
			"duplicate_signup_notice_failed",
			zap.String("user_id", user.ID),
			zap.String("email", redactEmail(email)),
			zap.Error(err),
		)
	}
	s.logger.Info("local_signup_existing_email", zap.String("email", redactEmail(email)), zap.String("user_id", user.ID))
	return s.newDuplicateSignupResult(ctx, email, fallbackDisplayName(email, name))
}

// handleDuplicatePasskeySignup is the existing-email decoy for passkey-first
// signup. It mirrors handleDuplicatePasswordSignup (sends the existing-account
// notice, never attaches a passkey, never discloses existence) but ALWAYS
// returns a fabricated-token decoy regardless of GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL.
//
// Why unconditional tokens: the passkey-signup new-account path always issues a
// live session (the in-flow OTP proved email control, so the account is created
// verified). If this decoy went through the verified-email-gated
// newDuplicateSignupResult it would be session-less when the flag is on, making
// new-vs-existing distinguishable by token presence — the exact enumeration
// oracle the decoy exists to prevent. duplicateSignupDecoyResult keeps the two
// responses token-shape identical with the flag both off and on.
func (s *AuthService) handleDuplicatePasskeySignup(ctx context.Context, user *User, email string) (*LoginResult, error) {
	if err := s.sendExistingSignupNotice(ctx, user); err != nil {
		s.logger.Warn(
			"duplicate_signup_notice_failed",
			zap.String("user_id", user.ID),
			zap.String("email", redactEmail(email)),
			zap.Error(err),
		)
	}
	s.logger.Info("passkey_signup_existing_email", zap.String("email", redactEmail(email)), zap.String("user_id", user.ID))
	return s.duplicateSignupDecoyResult(ctx, s.newDuplicateSignupUser(email, fallbackDisplayName(email, "")))
}

func (s *AuthService) sendExistingSignupNotice(ctx context.Context, user *User) error {
	loginURL := s.appBaseURL(ctx)
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

// newDuplicateSignupUser builds the synthetic, repository-absent user returned
// by every duplicate-signup decoy. Its id is deliberately a "signup-pending-"
// placeholder that never collides with a real account id.
func (s *AuthService) newDuplicateSignupUser(email, displayName string) *User {
	now := s.nowMs()
	return &User{
		ID:        "signup-pending-" + randomToken(8),
		Email:     email,
		Name:      displayName,
		Role:      "member",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	}
}

func (s *AuthService) newDuplicateSignupResult(ctx context.Context, email, displayName string) (*LoginResult, error) {
	user := s.newDuplicateSignupUser(email, displayName)
	// When email verification is required, a genuine new password signup returns
	// no live session (empty tokens — see PasswordSignup). The duplicate-signup
	// decoy MUST mirror that exactly: otherwise empty-vs-non-empty tokens
	// would disclose whether the address is already registered — the precise
	// account-enumeration oracle this decoy exists to prevent.
	if s.cfg != nil && s.cfg.AuthRequireVerifiedEmail {
		return &LoginResult{User: user}, nil
	}
	return s.duplicateSignupDecoyResult(ctx, user)
}

// duplicateSignupDecoyResult returns a success-shaped payload with an unstored
// refresh token and a JWT for a synthetic subject that is absent from the
// repository. It authenticates nobody (the subject does not exist) yet is
// token-shape identical to a real new-signup session, so token presence cannot
// disclose whether the address already exists. Callers whose genuine new-account
// path ALWAYS issues a session (e.g. passkey signup, where the OTP proves email
// control and the account is created verified) must use this directly — never
// the verified-email-gated newDuplicateSignupResult, which can be session-less.
func (s *AuthService) duplicateSignupDecoyResult(ctx context.Context, user *User) (*LoginResult, error) {
	decoyClaims := jwt.Claims{
		Sub:    user.ID,
		Email:  user.Email,
		Name:   user.Name,
		Role:   user.Role,
		Tenant: s.tenantID(ctx),
	}
	if s.cfg.JWTAudience != "" {
		decoyClaims.Audience = []string{s.cfg.JWTAudience}
	}
	accessToken, err := s.signer.SignAccessToken(ctx, decoyClaims, s.cfg.JWTExpiry())
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
	if err := validateEmailFormat(email); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	// Canonicalize the lookup key so alice.smith@gmail.com and
	// alicesmith@gmail.com both resolve to the one User row stored
	// under the canonical form. PasswordSignup writes the canonical
	// form, so lookup must use the same. Canonicalized ONCE here and reused for
	// both the access gate (cemail) and the DB lookup (email).
	cemail := canonicalize(email)
	email = string(cemail)

	// Enforce the project access mode (login context) BEFORE the user lookup and
	// bcrypt: the check is DB-free (email + config), so failing fast on a
	// closed/off-list project avoids a bcrypt CPU-DoS on disallowed addresses and
	// keeps the denial identical regardless of password correctness (no
	// password-guessing oracle). It reveals only allowlist membership — a project
	// property, not account existence — matching PasswordSignup's fail-fast.
	if err := s.enforceProjectAccessLogin(ctx, cemail); err != nil {
		return nil, err
	}

	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}

	user, err := s.repo(ctx).FindUserByEmail(ctx, email)
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
		s.audit.Log(
			ctx, audit.EventLoginFailure,
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
		s.audit.Log(
			ctx, audit.EventLoginLocked,
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
		if err := s.repo(ctx).ResetFailedLoginCount(ctx, user.ID); err != nil {
			s.logger.Warn("failed_login_reset_post_lockout_failed",
				zap.String("user_id", user.ID), zap.Error(err))
		}
		user.FailedLoginCount = 0
		user.LockedUntil = 0
	}

	// No password set (OAuth-only user).
	if user.PasswordHash == "" {
		s.audit.Log(
			ctx, audit.EventLoginFailure,
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
			s.audit.Log(
				ctx, audit.EventAccountLocked,
				audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
				audit.WithSuccess(false),
				audit.WithDetails(map[string]any{
					"lockout_seconds": s.cfg.LoginLockoutSeconds,
					"max_attempts":    s.cfg.LoginMaxFailedAttempts,
				}),
			)
		}
		s.audit.Log(
			ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "password_mismatch"}),
		)
		return nil, fmt.Errorf("%w: invalid email or password", ErrUnauthenticated)
	}

	// Account status (lockout / suspended / invited / IDV) is a hard gate.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	// Email-verification gate. The password is correct at this point, so this
	// is the one place the gate can fire without creating an enumeration oracle
	// (an unknown email or a wrong password already returned above with the
	// generic ErrUnauthenticated). When required, an unverified account cannot
	// authenticate — this closes the pre-hijacking vector where an attacker
	// plants a password on an unverified address and waits for the real owner
	// to verify it via OAuth/passwordless.
	if s.cfg != nil && s.cfg.AuthRequireVerifiedEmail && !user.EmailVerified {
		s.audit.Log(
			ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "email_not_verified"}),
		)
		// Best-effort: resend the verification email so the user can complete
		// verification and retry. Failures (throttle, transport) must not change
		// the response — the gate result is the same either way.
		if sendErr := s.SendEmailVerification(ctx, user.ID); sendErr != nil {
			s.logger.Warn("login_verification_resend_failed",
				zap.String("user_id", user.ID), zap.Error(sendErr))
		}
		return nil, ErrEmailVerificationRequired
	}

	// Credentials are proven; consult the tenant's LoginPolicy. This runs
	// only after authentication so a denial never reveals account existence,
	// and before tokens are issued so a disallowed method yields no session.
	decision, err := s.enforceLoginPolicy(ctx, email, LoginMethodPassword)
	if err != nil {
		return nil, err
	}

	// Password verified -- reset failed-attempt counters.
	s.resetFailedLogin(ctx, user)

	// 2FA branch: TOTP required, either because the user enrolled it or
	// because the tenant's LoginPolicy mandates a second factor for this
	// single-factor primary method.
	if user.TotpRequired || decision.RequireSecondFactor {
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor)
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("local_login_success", zap.String("email", redactEmail(email)), zap.String("user_id", user.ID))
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
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
	if !s.oauthResolver.available(ctx) {
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

	exchanger, ok := s.oauthResolver.exchangerFor(ctx, provider)
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
		ctx,
		s.signer,
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

type OAuthLoginParams struct {
	Code             string
	Provider         string
	RedirectURI      string
	CodeVerifier     string
	State            string
	StateToken       string
	AppleUserPayload string
	IPAddr           string
	UserAgent        string
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
	params OAuthLoginParams,
) (*LoginResult, error) {
	provider := strings.ToLower(strings.TrimSpace(params.Provider))
	identity, err := s.verifyOAuthExchange(ctx, params)
	if err != nil {
		if errors.Is(err, errOAuthExchangeFailed) {
			s.logger.Info(
				"oauth_login_failed",
				zap.String("provider", provider), zap.Error(err),
			)
			s.audit.Log(
				ctx, audit.EventOAuthLogin,
				audit.WithIP(params.IPAddr), audit.WithUserAgent(params.UserAgent),
				audit.WithSuccess(false),
				audit.WithDetails(map[string]any{
					"provider": provider,
					"reason":   "code_exchange_failed",
				}),
			)
			return s.mapOAuthError(errors.Unwrap(err))
		}
		return nil, err
	}

	// Canonicalize the provider email (gmail dot/+tag, domain lowercasing) so the
	// by-email lookup/create in upsertOAuthUser → resolveOrCreateUserByEmail uses
	// the SAME key every other flow stores under — otherwise an OAuth login for
	// alice.smith@gmail.com would mint a duplicate of an account stored as
	// alicesmith@gmail.com, breaking the one-account-per-email invariant.
	// canonicalizeEmail already trims + lowercases, so the empty-email guard holds.
	// Canonicalized ONCE here; carried as cemail into upsert/resolve (gate) and as
	// email (string) for the DB link/profile writes and logging.
	cemail := canonicalize(identity.Email)
	email := string(cemail)
	if email == "" {
		return nil, fmt.Errorf("%w: provider returned no email", ErrUnauthenticated)
	}

	user, isNew, err := s.upsertOAuthUser(ctx, identity, cemail)
	if err != nil {
		return nil, err
	}

	if err := s.checkAccountStatus(ctx, user, params.IPAddr, params.UserAgent); err != nil {
		return nil, err
	}

	// Project access mode (login context). upsertOAuthUser's (provider, sub) fast
	// path returns a RETURNING user WITHOUT passing through
	// resolveOrCreateUserByEmail, so that branch alone would let a pre-linked
	// non-member back in — enforce it here too. A first-time (new-user) OAuth
	// login is gated as SELF-SIGNUP inside resolveOrCreateUserByEmail, so an
	// invite-only/closed project never JIT-provisions a new user; this login
	// check then permits the (now existing) user for invite mode. user.Email is
	// the DB-persisted (already canonical) account email; wrap once — idempotent,
	// and it self-heals a legacy non-canonical row.
	if err := s.enforceProjectAccessLogin(ctx, canonicalize(user.Email)); err != nil {
		return nil, err
	}

	// The provider has proven control of the email; consult the tenant's
	// LoginPolicy before issuing tokens so a tenant that disallows oauth is
	// honoured here too — not just on the password / passwordless paths.
	decision, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodOAuth)
	if err != nil {
		return nil, err
	}
	// OAuth is a single-factor primary: a Require2FA tenant must complete a
	// second factor before full tokens are minted.
	if user.TotpRequired || decision.RequireSecondFactor {
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor)
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info(
		"oauth_login_success",
		zap.String("email", redactEmail(email)),
		zap.String("provider", provider),
		zap.String("user_id", user.ID),
	)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, params.IPAddr, params.UserAgent)
	if err != nil {
		return nil, err
	}

	s.audit.Log(
		ctx, audit.EventOAuthLogin,
		audit.WithActor(user.ID), audit.WithIP(params.IPAddr), audit.WithUserAgent(params.UserAgent),
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
	return nil, s.mapOAuthErr(err)
}

// mapOAuthErr is the error-only form of mapOAuthError, shared by the OAuth
// login path and the self-service LinkIdentity path. Both run the same code
// exchange and want the same RPC-code mapping for a verification failure.
func (s *AuthService) mapOAuthErr(err error) error {
	switch {
	case errors.Is(err, oauth.ErrEmailNotVerified):
		return fmt.Errorf("%w: provider email is not verified", ErrUnauthenticated)
	default:
		return fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
}

// errOAuthExchangeFailed wraps a provider code-exchange failure returned by
// verifyOAuthExchange so callers can distinguish "the provider rejected the
// code" (which they audit and map via mapOAuthErr) from an input-validation
// or state-verification failure (already a typed sentinel).
var errOAuthExchangeFailed = errors.New("oauth code exchange failed")

// verifyOAuthExchange runs the trusted server-side OAuth code exchange:
// it validates inputs, verifies the signed state token (binding provider,
// redirect URI, state, and PKCE verifier), then swaps the authorization
// code for a provider-verified Identity. The frontend is never trusted to
// assert the identity — identity performs the exchange itself.
//
// provider must already be lower-cased/trimmed by the caller. On a provider
// exchange failure it returns an error wrapping errOAuthExchangeFailed.
func (s *AuthService) verifyOAuthExchange(
	ctx context.Context,
	params OAuthLoginParams,
) (*oauth.Identity, error) {
	if !s.oauthResolver.available(ctx) {
		return nil, ErrOAuthDisabled
	}
	redirectURI := strings.TrimSpace(params.RedirectURI)
	provider := strings.ToLower(strings.TrimSpace(params.Provider))
	if provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(params.Code) == "" {
		return nil, fmt.Errorf("%w: code is required", ErrInvalidArgument)
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("%w: redirect uri is required", ErrInvalidArgument)
	}

	exchanger, ok := s.oauthResolver.exchangerFor(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("%w: unknown oauth provider %q", ErrInvalidArgument, provider)
	}

	codeVerifier := params.CodeVerifier
	if strings.TrimSpace(params.StateToken) != "" {
		claims, err := oauth.VerifyStateToken(
			params.StateToken,
			s.signer,
			provider,
			redirectURI,
			params.State,
			params.CodeVerifier,
			s.nowFunc().UTC(),
		)
		if err != nil {
			s.logger.Info(
				"oauth_state_validation_failed",
				zap.String("provider", provider),
				zap.Error(err),
			)
			return nil, fmt.Errorf("%w: invalid oauth state", ErrUnauthenticated)
		}
		codeVerifier = claims.CodeVerifier
	}

	identity, err := exchanger.Exchange(ctx, oauth.ExchangeParams{
		Code:             params.Code,
		RedirectURI:      redirectURI,
		CodeVerifier:     codeVerifier,
		AppleUserPayload: params.AppleUserPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errOAuthExchangeFailed, err)
	}
	return identity, nil
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
func (s *AuthService) upsertOAuthUser(ctx context.Context, identity *oauth.Identity, email canonicalEmail) (*User, bool, error) {
	now := s.nowMs()
	emailStr := string(email)

	// 1. (provider, sub) lookup — survives provider-side email change.
	if identity.ProviderUserID != "" {
		linked, err := s.repo(ctx).FindUserByProviderID(ctx, identity.Provider, identity.ProviderUserID)
		if err != nil {
			return nil, false, err
		}
		if linked != nil {
			s.applyOAuthProfileUpdates(ctx, linked, identity, emailStr, now)
			return linked, false, nil
		}
	}

	// 2 & 3. Email-based lookup, then create. Shared with passwordless
	// login so OAuth, OTP, and magic link all converge on ONE account per
	// email — an email-based first-time OAuth login links to a pre-existing
	// password/passwordless account rather than duplicating it.
	user, isNew, err := s.resolveOrCreateUserByEmail(ctx, email, resolveOrCreateOpts{
		name:          identity.Name,
		avatarURL:     identity.AvatarURL,
		emailVerified: true, // a verified provider identity proves control
	})
	if err != nil {
		return nil, false, err
	}
	if !isNew {
		s.applyOAuthProfileUpdates(ctx, user, identity, emailStr, now)
	}
	s.linkOAuthIdentity(ctx, user.ID, identity, emailStr, now)
	if isNew {
		s.logger.Info(
			"oauth_user_provisioned",
			zap.String("email", redactEmail(emailStr)),
			zap.String("user_id", user.ID),
			zap.String("provider", identity.Provider),
		)
	}
	return user, isNew, nil
}

// resolveOrCreateOpts carries the optional profile fields a create path
// wants applied to a freshly-provisioned user. All fields are ignored
// when an existing user is found (the existing record is authoritative;
// callers that want to patch it do so explicitly).
type resolveOrCreateOpts struct {
	name          string
	avatarURL     string
	emailVerified bool
}

// resolveOrCreateUserByEmail is the single by-email account resolver: it looks
// the user up by email and, when none exists, creates one. This guarantees the
// unified-by-email invariant — an email-authenticated login for an address that
// already has an account links to the SAME user instead of minting a duplicate.
//
// Returns (user, isNewUser, error). isNewUser is true only when a User
// row was created here. On a create race (a concurrent caller created the
// row between the lookup and the insert) it re-resolves by email and
// returns the existing row with isNewUser=false, so two simultaneous
// first-time logins for the same email still converge on one account.
func (s *AuthService) resolveOrCreateUserByEmail(ctx context.Context, email canonicalEmail, opts resolveOrCreateOpts) (*User, bool, error) {
	emailStr := string(email)
	existing, err := s.repo(ctx).FindUserByEmail(ctx, emailStr)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		// Resolving an EXISTING account is a login-context access check, so an
		// invite-only project lets an already-provisioned user back in while still
		// blocking the self-signup create branch below.
		if err := s.enforceProjectAccessLogin(ctx, email); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}

	// Creating a NEW account is a self-signup access check — an invite-only or
	// closed project (or a non-matching allowlist) denies JIT provisioning here.
	if err := s.enforceProjectAccessSignup(ctx, email); err != nil {
		return nil, false, err
	}

	now := s.nowMs()
	displayName := fallbackDisplayName(emailStr, opts.name)
	emailVerifiedAt := int64(0)
	if opts.emailVerified {
		emailVerifiedAt = now
	}
	newUser := &User{
		Email:           emailStr,
		Name:            displayName,
		AvatarURL:       opts.avatarURL,
		Role:            "member",
		Status:          "active",
		EmailVerified:   opts.emailVerified,
		EmailVerifiedAt: emailVerifiedAt,
		CreatedAt:       msToTime(now),
		UpdatedAt:       msToTime(now),
	}
	userID, err := s.repo(ctx).CreateUser(ctx, newUser)
	if err != nil {
		// Lost a create race: another caller inserted the same email
		// between our lookup and insert. Re-resolve so both callers land
		// on the one account rather than surfacing a unique-constraint
		// error to the user.
		if raced, lookupErr := s.repo(ctx).FindUserByEmail(ctx, emailStr); lookupErr == nil && raced != nil {
			return raced, false, nil
		}
		return nil, false, fmt.Errorf("creating user: %w", err)
	}
	newUser.ID = userID

	// Best-effort: auto-form a company tenant from the email domain. Only on
	// a genuinely new account (a raced/existing user returned above).
	s.maybeAutoFormTenant(ctx, newUser)

	// Best-effort: emit a user.created lifecycle event. No-op when eventing
	// is disabled.
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), events.EventUserCreated, newUser)

	return newUser, true, nil
}

// markEmailVerifiedViaExternalProof flips the account to verified because an
// external method (OAuth provider assertion, or an emailed OTP/magic-link the
// user redeemed) proved control of the address. Any credential on the account
// was established BEFORE this proof — possibly by a different party (account
// pre-hijacking) — so the untrusted ones are voided:
//
//   - a planted password is cleared (the owner re-establishes it via reset);
//   - any planted passkeys are deleted. A passkey enrolled while the email was
//     unverified is exactly as untrustworthy as a planted password: passkey
//     login does not pass through the email-verification gate, so without this
//     an attacker who passkey-first-signed-up an unverified address would keep
//     a working credential after the real owner takes the account over.
//
// It is a no-op when the email is already verified (the proof adds nothing).
// Best-effort: a persistence failure is logged, not fatal — the user has
// already authenticated via the external proof.
func (s *AuthService) markEmailVerifiedViaExternalProof(ctx context.Context, user *User, nowMs int64, method string) {
	if user == nil || user.EmailVerified {
		return
	}
	patch := map[string]any{
		"email_verified":    true,
		"email_verified_at": nowMs,
		"updated_at":        nowMs,
	}
	passwordCleared := user.PasswordHash != ""
	if passwordCleared {
		// The password predates the proof of email control, so it cannot be
		// trusted to belong to the verified owner. Clear it.
		patch["password_hash"] = ""
	}

	user.EmailVerified = true
	user.EmailVerifiedAt = nowMs
	if passwordCleared {
		user.PasswordHash = ""
	}

	if err := s.repo(ctx).UpdateUser(ctx, user.ID, patch); err != nil {
		s.logger.Warn("email_verified_external_persist_failed",
			zap.String("user_id", user.ID),
			zap.String("method", method),
			zap.Error(err))
		return
	}

	// Void any passkeys planted while the address was unverified. Detect first
	// (so the audit/session-revocation only fires when there was something to
	// clear) then delete them all.
	passkeysCleared := false
	if existing, err := s.repo(ctx).ListPasskeyCredentials(ctx, user.ID); err != nil {
		s.logger.Warn("email_verified_external_passkey_list_failed",
			zap.String("user_id", user.ID), zap.String("method", method), zap.Error(err))
	} else if len(existing) > 0 {
		if err := s.repo(ctx).DeletePasskeyCredentialsForUser(ctx, user.ID); err != nil {
			s.logger.Warn("email_verified_external_passkey_clear_failed",
				zap.String("user_id", user.ID), zap.String("method", method), zap.Error(err))
		} else {
			passkeysCleared = true
		}
	}

	if passwordCleared || passkeysCleared {
		// The cleared credentials are void, so revoke any sessions too —
		// mirroring ConfirmPasswordReset — so a session established with a now-
		// voided credential cannot outlive it. With the verification gate on,
		// a planted-password session is impossible; a planted-passkey session
		// is NOT (passkey login skips the gate), so this matters either way.
		if err := s.repo(ctx).DeleteRefreshTokensForUser(ctx, user.ID); err != nil {
			s.logger.Warn("email_verified_external_revoke_failed",
				zap.String("user_id", user.ID), zap.String("method", method), zap.Error(err))
		}
		s.revokeUserSessionsIfModeSession(ctx, user.ID, "external_email_verification")
		s.logger.Info("email_verified_external_credentials_cleared",
			zap.String("user_id", user.ID),
			zap.String("method", method),
			zap.Bool("password_cleared", passwordCleared),
			zap.Bool("passkeys_cleared", passkeysCleared))
		s.audit.Log(
			ctx, audit.EventPasswordChanged,
			audit.WithActor(user.ID),
			audit.WithSuccess(true),
			audit.WithDetails(map[string]any{
				"reason":           "planted_credentials_cleared_on_external_email_verification",
				"method":           method,
				"password_cleared": passwordCleared,
				"passkeys_cleared": passkeysCleared,
			}),
		)
	}
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
	// A verified provider identity proves control of the address. Flip the
	// account to verified and clear any password planted while it was still
	// unverified (anti-pre-hijacking). This runs its own persistence, so it is
	// intentionally NOT folded into the name/avatar patch below.
	s.markEmailVerifiedViaExternalProof(ctx, u, nowMs, "oauth")
	// Provider-asserted email changes are NOT auto-applied to the local
	// account. A compromised provider account (or a provider that lets
	// admins change member emails) would otherwise let an attacker
	// rewrite the local email and complete password-reset takeover.
	// Email changes go through the user-initiated email-change flow with
	// verification on the new address. Log so operators see the divergence.
	if email != "" && email != u.Email {
		s.logger.Info(
			"oauth_provider_email_divergence",
			zap.String("user_id", u.ID),
			zap.String("provider", identity.Provider),
		)
	}
	if len(patch) == 0 {
		return
	}
	patch["updated_at"] = nowMs
	if err := s.repo(ctx).UpdateUser(ctx, u.ID, patch); err != nil {
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
	if err := s.repo(ctx).CreateOAuthIdentity(ctx, oi); err != nil {
		s.logger.Warn(
			"oauth_identity_link_failed",
			zap.String("user_id", userID),
			zap.String("provider", identity.Provider),
			zap.Error(err),
		)
		return
	}
	s.audit.Log(
		ctx, audit.EventIdentityLinked,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider":           identity.Provider,
			"provider_user_id":   identity.ProviderUserID,
			"email_at_link_time": email,
			"source":             "login_auto_link",
		}),
	)
}

// checkAccountStatus verifies the user's status allows login.
//
// Beyond the obvious "status field" check (active / invited / suspended),
// this also enforces the failed-login lockout window. Every login path —
// password, OAuth, passkey — calls this BEFORE issuing tokens, so a user
// in lockout cannot bypass the limit by switching authentication method.
// When cfg.IDVRequired is set, unverified users are blocked with
// ErrIDVRequired so the client can route them to BeginIdentityVerification.
func (s *AuthService) checkAccountStatus(ctx context.Context, user *User, ipAddr, userAgent string) error {
	if user.LockedUntil > 0 && user.LockedUntil > s.nowMs() {
		s.audit.Log(
			ctx, audit.EventLoginLocked,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"reason":       "account_locked",
				"locked_until": user.LockedUntil,
			}),
		)
		return fmt.Errorf("%w: account temporarily locked due to too many failed attempts", ErrAccountLocked)
	}

	status := strings.ToLower(user.Status)
	switch status {
	case "", StatusActive, StatusPendingDeletion:
		// PENDING_DELETION is deliberately allowed to authenticate (unlike
		// DEACTIVATED/SUSPENDED): a successful login is exactly the signal that
		// cancels the pending deletion, which issueTokens does before minting
		// tokens.
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
	// Global baseline check up front (before any token lookup); the
	// tenant-specific tightening runs once the owning user is resolved.
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	tokenHash := hashInvitationToken(invitationToken)
	inv, err := s.repo(ctx).FindInvitationByHash(ctx, tokenHash)
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
		user, err = s.repo(ctx).GetUser(ctx, inv.UserID)
		if err != nil {
			return nil, err
		}
	}
	if user == nil && inv.Email != "" {
		user, err = s.repo(ctx).FindUserByEmail(ctx, inv.Email)
		if err != nil {
			return nil, err
		}
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user for invitation not found", ErrNotFound)
	}

	// Enforce the project access mode (login/invite context) on the invitee.
	// Invitation acceptance is the sanctioned way into an invite-only project, so
	// invite/open permit it; but an allowlist project still requires the invitee
	// be on the list (an admin cannot invite someone the allowlist excludes), and
	// a closed project refuses every acceptance. user.Email is the DB-persisted
	// (canonical) account email; wrap once (idempotent, self-heals a legacy row).
	if err := s.enforceProjectAccessLogin(ctx, canonicalize(user.Email)); err != nil {
		return nil, err
	}

	// Enforce the invited member's tenant password policy now that the
	// owning user (and thus its email domain) is known.
	if err := s.validatePasswordStrengthForEmail(ctx, user.Email, password); err != nil {
		return nil, err
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
	if err := s.repo(ctx).UpdateUser(ctx, user.ID, patch); err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}

	// Mark invitation as accepted.
	_ = s.repo(ctx).UpdateInvitation(ctx, inv.NodeID, map[string]any{"accepted_at": now})

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
