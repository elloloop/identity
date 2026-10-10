package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/events"
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

// errInvalidCredentials is the one answer a password sign-in gives whenever
// the caller has not proven the password: the response must not tell an
// unknown identifier from a wrong password.
var errInvalidCredentials = fmt.Errorf("%w: invalid email or password", ErrUnauthenticated)

// refuseAsUnknownIdentifier answers a sign-in that must look exactly like one
// naming no account: the same error, after the same bcrypt cost a wrong
// password pays. Without the dummy check the refusal returns in microseconds
// while a wrong password takes ~250ms, which tells the caller the account
// exists.
func refuseAsUnknownIdentifier(password string) error {
	_ = passwords.Verify(password, getDummyPasswordHash())
	return errInvalidCredentials
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
// market is the optional jurisdiction/market code the account is created
// under; it is canonicalized (trimmed, upper-cased) and, when the resolved
// project configures per-jurisdiction thresholds, must name one of them.
// linkParams go on the verification email's link; refused ones are
// ErrInvalidArgument before any account work (see checkEmailLinkParams).
func (s *AuthService) PasswordSignup(ctx context.Context, email, password, name, recoveryEmail string, dateOfBirthMs int64, market string, linkParams EmailLinkParams) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	if !s.cfg.PasswordSignupEnabled {
		return nil, ErrSignupDisabled
	}
	link, err := s.checkEmailLinkParams(linkParams)
	if err != nil {
		return nil, err
	}
	if s.ageGate.Enabled() && s.cfg.AgeGateRequireDOB && dateOfBirthMs <= 0 {
		return nil, fmt.Errorf("%w: date of birth is required", ErrInvalidArgument)
	}
	market = normalizeJurisdictionCode(market)
	if err := s.validateAccountMarket(ctx, market); err != nil {
		return nil, err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if err := validateEmailFormat(email); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	// Canonicalize for dedup + storage: dot-stripping for @gmail.com /
	// @googlemail.com local parts, universal '+' tag stripping,
	// googlemail.com → gmail.com. One human ↔ one account. Canonicalized ONCE
	// here and reused for both the access gate (cemail) and every DB op (email).
	cemail, usable := canonicalMailbox(email)
	if !usable {
		return nil, errNoUsableMailbox
	}
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

	// Derive the age band from the supplied DOB under the thresholds the
	// account's market resolves to (per-jurisdiction when the project
	// configures them, else the deployment-wide env pair). A child-band
	// account under age-gating is created in PENDING_PARENTAL_CONSENT and is
	// not issued tokens until verifiable parental consent is granted; every
	// other band (and a disabled gate) creates an active account exactly as
	// before.
	gate := s.determinerForUser(ctx, &User{Market: market})
	ageDec := gate.Determine(dateOfBirthMs, s.nowFunc())
	status := StatusActive
	if gate.Enabled() && ageDec.Band == agegate.BandChild {
		status = StatusPendingParentalConsent
	}

	// COPPA data-minimization: never persist a recovery_email for a child
	// account. The recovery-email flow is a non-essential PII collection the
	// server declines to perform for a minor; the account row is still created
	// (in pending_parental_consent) so the parental-consent flow can proceed.
	if s.minorData.BlocksChildFor(ctx, &User{DateOfBirthMs: dateOfBirthMs, Market: market}) && recEmail != "" {
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
		Market:        market,
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
		Market:        market,
		CreatedAt:     msToTime(now),
		UpdatedAt:     msToTime(now),
	}
	s.stampAgeBand(ctx, user)
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
	if err := s.sendEmailVerification(ctx, userID, link); err != nil {
		s.logger.Warn("signup_verification_email_failed",
			zap.String("user_id", userID), zap.Error(err))
	}

	// When email verification is required, a freshly-created account is
	// unverified and gets no session (issuing one would be refused). Sign-up
	// is not a failed sign-in, so it returns the user (so the client can drive
	// "check your email") with no tokens, audited as a success; the proto
	// response shape is preserved, the tokens are simply empty.
	if s.needsEmailVerification(user) {
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
	// A genuine passkey sign-up's account is created verified (the in-flow
	// OTP proved the address), so the decoy is too.
	decoy := s.newDuplicateSignupUser(email, fallbackDisplayName(email, ""))
	decoy.EmailVerified = true
	return s.duplicateSignupDecoyResult(ctx, decoy)
}

func (s *AuthService) sendExistingSignupNotice(ctx context.Context, user *User) error {
	loginURL := appBaseURL(ctx, s.cfg)
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
		Status:    StatusActive,
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
	// A genuine new account that is issued a session is issued its account
	// address too; the decoy carries the one it would get, or it would give
	// the duplicate away.
	user.AccountAddress = predictedAccountAddress(ctx, user)
	// The same claim set a real sign-up's token carries, or the decoy's
	// shape would give the duplicate away.
	accessToken, err := s.signer.SignAccessToken(ctx, s.accessTokenClaims(ctx, user, s.nowMs()), s.cfg.JWTExpiry())
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

// PasswordLogin authenticates a user with identifier + password. The
// identifier is an email address, OR — when it contains no '@' — the username
// of a username account within the project (a managed child, a username
// sign-up or an admin-created username account). The two lookups share one
// failure surface: unknown identifier, wrong password, and (on the username
// path) a syntactically impossible username all return the identical generic
// invalid-credentials refusal, so the endpoint discloses neither which form
// matched nor whether the account exists.
// If TOTP is enabled, returns TotpRequired=true with a LoginChallengeID.
func (s *AuthService) PasswordLogin(ctx context.Context, email, password, ipAddr, userAgent string) (*LoginResult, error) {
	user, decision, err := s.verifyPasswordCredential(ctx, email, password, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	identifierKey, identifier := "email", user.Email
	if user.Email == "" || !strings.Contains(strings.TrimSpace(email), "@") {
		identifierKey, identifier = "username", user.Username
	}

	// Password verified -- reset failed-attempt counters.
	s.resetFailedLogin(ctx, user)

	// An administrator-issued password opens no session: the user replaces
	// it first. The completion step takes the second factor too, and checks
	// it before it changes anything.
	if user.PasswordChangeRequired {
		return nil, s.requirePasswordChange(ctx, user, decision.RequireSecondFactor, ipAddr, userAgent)
	}

	// 2FA branch: TOTP required, either because the user enrolled it or
	// because the tenant's LoginPolicy mandates a second factor for this
	// single-factor primary method.
	if user.TotpRequired || decision.RequireSecondFactor {
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor, ipAddr, userAgent)
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	s.logger.Info("local_login_success", zap.String(identifierKey, redactIdentifier(identifier)), zap.String("user_id", user.ID))
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "password"}),
	)
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// verifyPasswordCredential is the whole credential check of a password
// sign-in, for every caller that must prove a password: local
// auth on, the identifier resolved (an email, canonicalized, or a username),
// the project and account access gates, the lockout, the password, the
// account's status, the verified-email gate and the login policy — each with
// its audit entry. It returns the account and the policy decision (whether a
// second factor is required); it does not reset the failed-login count, record
// a sign-in, or issue anything.
func (s *AuthService) verifyPasswordCredential(ctx context.Context, email, password, ipAddr, userAgent string) (*User, loginPolicyDecision, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, loginPolicyDecision{}, ErrLocalAuthDisabled
	}
	if password == "" {
		return nil, loginPolicyDecision{}, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}

	identifier := strings.TrimSpace(strings.ToLower(email))
	// An absent identifier is a malformed request, not a failed lookup: it
	// names no account of either kind, so refusing it with InvalidArgument
	// (as the password check above does) creates no enumeration oracle. Every
	// NON-empty identifier falls through to the uniform refusal below,
	// whether it is an unknown email, an unknown username, or syntactically
	// neither.
	if identifier == "" {
		return nil, loginPolicyDecision{}, fmt.Errorf("%w: email or username is required", ErrInvalidArgument)
	}
	var user *User
	var err error
	// identifierKey names the identifier kind in audit details (the audit
	// trail is internal — it may distinguish what the client response must
	// not).
	identifierKey := "email"
	if strings.Contains(identifier, "@") {
		email = identifier
		if err := validateEmailFormat(email); err != nil {
			return nil, loginPolicyDecision{}, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
		}
		// Canonicalize the lookup key so alice.smith@gmail.com and
		// alicesmith@gmail.com both resolve to the one User row stored
		// under the canonical form. PasswordSignup writes the canonical
		// form, so lookup must use the same. Canonicalized ONCE here and reused for
		// both the access gate (cemail) and the DB lookup (email).
		cemail, usable := canonicalMailbox(email)
		if !usable {
			return nil, loginPolicyDecision{}, errNoUsableMailbox
		}
		email = string(cemail)

		// Enforce the project access mode (login context) BEFORE the user lookup and
		// bcrypt: the check is DB-free (email + config), so failing fast on a
		// closed/off-list project avoids a bcrypt CPU-DoS on disallowed addresses and
		// keeps the denial identical regardless of password correctness (no
		// password-guessing oracle). It reveals only allowlist membership — a project
		// property, not account existence — matching PasswordSignup's fail-fast.
		if err := s.enforceProjectAccessLogin(ctx, cemail); err != nil {
			return nil, loginPolicyDecision{}, err
		}
		user, err = s.repo(ctx).FindUserByEmail(ctx, email)
		if err != nil {
			return nil, loginPolicyDecision{}, err
		}
	} else {
		// Username login. The email-keyed gate cannot run before the lookup —
		// there is no email to key it on — so the account's access rule
		// (enforceAccountAccessLogin) runs once the password is proven.
		identifierKey = "username"
		username := normalizeUsername(identifier)
		if validateUsernameShape(username) == nil {
			user, err = s.repo(ctx).FindUserByUsername(ctx, username)
			if err != nil {
				return nil, loginPolicyDecision{}, err
			}
		}
		// A syntactically impossible username matches no account; fall through
		// with user == nil to the uniform refusal.
		identifier = username
	}

	if user == nil {
		refusal := refuseAsUnknownIdentifier(password)
		s.logger.Info("local_login_failed", zap.String("reason", "user_not_found"))
		s.audit.Log(
			ctx, audit.EventLoginFailure,
			audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "user_not_found", identifierKey: identifier}),
		)
		return nil, loginPolicyDecision{}, refusal
	}

	// While locked, the account is refused whatever the password, and as an
	// unknown identifier is, at the same cost: only the password could earn
	// the caller the reason, and checking it during the lockout would hand
	// back the guessing the lockout stops. A distinct answer would also let
	// anyone confirm the account by tripping the lockout. The dedicated
	// `login_locked` audit event tells operators "tried during lockout" from
	// "threshold tripped".
	if user.LockedUntil > 0 && user.LockedUntil > s.nowMs() {
		refusal := refuseAsUnknownIdentifier(password)
		s.audit.Log(
			ctx, audit.EventLoginLocked,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"reason":       "account_locked",
				"locked_until": user.LockedUntil,
			}),
		)
		return nil, loginPolicyDecision{}, refusal
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

	// An account with no password (a provider or passwordless one) can prove
	// none, so it is refused as an unknown identifier is, at the same cost:
	// saying so would tell a caller with no credential that it exists.
	if user.PasswordHash == "" {
		refusal := refuseAsUnknownIdentifier(password)
		s.audit.Log(
			ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "no_password_set"}),
		)
		return nil, loginPolicyDecision{}, refusal
	}

	if !passwords.Verify(password, user.PasswordHash) {
		// Record the failure. Errors propagate as ErrUnauthenticated so
		// a DB outage during the increment cannot be used to bypass the
		// lockout (fail-closed).
		_, lockedNow, recErr := s.recordFailedLogin(ctx, user)
		if recErr != nil {
			return nil, loginPolicyDecision{}, errInvalidCredentials
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
		return nil, loginPolicyDecision{}, errInvalidCredentials
	}

	// A username sign-in skipped the email-keyed access gate above; it gets
	// the account rule after the password, so a refusal reveals nothing to a
	// caller without it.
	decision, err := s.postPasswordGates(ctx, user, postPasswordGateOpts{
		checkAccess: identifierKey == "username",
	}, ipAddr, userAgent)
	if err != nil {
		return nil, loginPolicyDecision{}, err
	}
	return user, decision, nil
}

// postPasswordGateOpts are the ways the callers of postPasswordGates differ on
// purpose.
type postPasswordGateOpts struct {
	// checkAccess applies the project access rule to the account. A sign-in
	// by email already passed the email-keyed gate before the lookup; a
	// username sign-in, or a later step that re-checks, has not.
	checkAccess bool
}

// postPasswordGates is every gate a password sign-in applies once the
// password is proven, in one place for every caller that proves one (the
// sign-in, and a step that completes it later): the account's status and
// lockout, the access rule when asked, the verified-email requirement and the
// login policy, whose decision it returns. Each refusal is audited as the
// sign-in's.
func (s *AuthService) postPasswordGates(ctx context.Context, user *User, opts postPasswordGateOpts, ipAddr, userAgent string) (loginPolicyDecision, error) {
	// Account status (lockout / suspended / invited / IDV) is a hard gate.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent, sessionGateSignIn); err != nil {
		return loginPolicyDecision{}, err
	}
	// The rule judges an account that also has an email by that email,
	// exactly as refresh will.
	if opts.checkAccess {
		if err := s.enforceAccountAccessLogin(ctx, user); err != nil {
			return loginPolicyDecision{}, err
		}
	}
	// Email-verification gate. Callers reach this only with the password
	// proven, so the gate can fire without creating an enumeration oracle (an
	// unknown email or a wrong password was already refused with the generic
	// ErrUnauthenticated). When required, an unverified account cannot
	// authenticate — this closes the pre-hijacking vector where an attacker
	// plants a password on an unverified address and waits for the real owner
	// to verify it via OAuth/passwordless.
	//
	// An account with NO email is out of the gate's scope entirely: a managed
	// child is identified by a username and structurally has no address to
	// verify, so gating it would make the parent-set password permanently
	// unusable (the flag defaults ON) — and there is no pre-hijacking vector
	// to close, because there is no address for an attacker to plant a
	// password against or for an owner to later verify.
	if err := s.enforceVerifiedEmail(ctx, user, ipAddr, userAgent, sessionGateSignIn); err != nil {
		return loginPolicyDecision{}, err
	}

	// Credentials are proven; consult the tenant's LoginPolicy. This runs
	// only after authentication so a denial never reveals account existence,
	// and before tokens are issued so a disallowed method yields no session.
	// The policy resolves from the account's STORED email — for a username-
	// identified managed child that is "" (no governed tenant), so the project
	// default applies, matching the passkey login path.
	return s.enforceLoginPolicy(ctx, user.Email, LoginMethodPassword)
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
	// emailaddr.Canonicalize already trims + lowercases, so the empty-email guard holds.
	// Canonicalized ONCE here; carried as cemail into upsert/resolve (gate) and as
	// email (string) for the DB link/profile writes and logging.
	cemail, usable := canonicalMailbox(identity.Email)
	email := string(cemail)
	if email == "" {
		return nil, fmt.Errorf("%w: provider returned no email", ErrUnauthenticated)
	}
	if !usable {
		return nil, fmt.Errorf("%w: provider returned an email with no usable mailbox", ErrUnauthenticated)
	}

	user, isNew, err := s.upsertOAuthUser(ctx, identity, cemail)
	if err != nil {
		return nil, err
	}

	if err := s.checkAccountStatus(ctx, user, params.IPAddr, params.UserAgent, sessionGateSignIn); err != nil {
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
	if err := s.enforceAccountAccessLogin(ctx, user); err != nil {
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
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor, params.IPAddr, params.UserAgent)
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, params.IPAddr, params.UserAgent)
	if err != nil {
		return nil, err
	}
	s.logger.Info(
		"oauth_login_success",
		zap.String("email", redactEmail(email)),
		zap.String("provider", provider),
		zap.String("user_id", user.ID),
	)

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
	if linked, err := s.findLinkedOAuthUser(ctx, identity, emailStr, now); err != nil || linked != nil {
		return linked, false, err
	}

	// 2 & 3. Email-based lookup, then create. Shared with passwordless
	// login so OAuth, OTP, and magic link all converge on ONE account per
	// email — an email-based first-time OAuth login links to a pre-existing
	// password/passwordless account rather than duplicating it.
	//
	// The provider proved the address it asserted, which is the account's only
	// when no "+tag" outside Gmail was dropped to reach it.
	user, isNew, err := s.resolveOrCreateUserByEmail(ctx, email, resolveOrCreateOpts{
		name:          identity.Name,
		avatarURL:     identity.AvatarURL,
		emailVerified: ProofCarriesTo(identity.Email, emailStr),
	})
	if err != nil {
		return nil, false, err
	}
	// An existing account is the provider's only when the provider proved the
	// account's own address. A tagged address outside Gmail canonicalizes to
	// the account's but is not provably the same mailbox, so it neither signs
	// in nor links here; the owner links such a provider while signed in.
	if !isNew && !ProofCarriesTo(identity.Email, user.Email) {
		// A concurrent sign-in by this same identity may have created the
		// account, and linked it, after the lookup above: the request that
		// lost that race is answered as the sign-in arriving after it is.
		if linked, err := s.findLinkedOAuthUser(ctx, identity, emailStr, now); err != nil || linked != nil {
			return linked, false, err
		}
		s.logger.Info("oauth_login_refused",
			zap.String("reason", "provider_address_does_not_prove_account"),
			zap.String("user_id", user.ID),
			zap.String("provider", identity.Provider))
		s.audit.Log(
			ctx, audit.EventLoginFailure,
			audit.WithActor(user.ID),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"reason":   "provider_address_does_not_prove_account",
				"provider": identity.Provider,
			}),
		)
		return nil, false, fmt.Errorf("%w: sign in and link this provider to use it", ErrUnauthenticated)
	}
	if !isNew {
		if err := s.applyOAuthProfileUpdates(ctx, user, identity, emailStr, now); err != nil {
			return nil, false, err
		}
	}
	s.linkOAuthIdentity(ctx, user.ID, identity, now)
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

// findLinkedOAuthUser returns the account the provider identity is linked to,
// with the provider's profile applied, or nil when it is linked to none.
func (s *AuthService) findLinkedOAuthUser(ctx context.Context, identity *oauth.Identity, email string, nowMs int64) (*User, error) {
	var linked *User
	if identity.ProviderUserID != "" {
		var err error
		if linked, err = s.repo(ctx).FindUserByProviderID(ctx, identity.Provider, identity.ProviderUserID); err != nil {
			return nil, err
		}
	}
	if linked != nil {
		if err := s.applyOAuthProfileUpdates(ctx, linked, identity, email, nowMs); err != nil {
			return nil, err
		}
	}
	return linked, nil
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
		Status:          StatusActive,
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

// externalProof is a method outside identity proving control of an address:
// a provider's assertion, an emailed code or link the user redeemed at sign-in,
// or a verification link redeemed for an account whose address a provider
// claimed without proving it.
type externalProof struct {
	// address is the address proven.
	address string
	// method names the proof in logs and the audit trail: "oauth",
	// "passwordless" or "verification_link".
	method string
	// provider and providerUserID name the provider link that presented the
	// proof, which is kept; both are empty for an emailed proof.
	provider, providerUserID string
	// keepsAssertingLinks keeps the links whose provider asserted the
	// account's own address. Only a verification link sets it: a sign-in
	// proof also voids links recorded before links kept the asserted
	// spelling, whose canonical form reads as the account's address even
	// when the provider asserted a tagged one.
	keepsAssertingLinks bool
}

// voids reports whether the proof voids link on an account holding
// accountEmail.
func (p externalProof) voids(link *OAuthIdentity, accountEmail string) bool {
	if link.Provider == p.provider && link.ProviderUserID == p.providerUserID {
		return false
	}
	return !p.keepsAssertingLinks || !ProofCarriesTo(link.EmailAtLinkTime, accountEmail)
}

// markEmailVerifiedViaExternalProof flips the account to verified because an
// external method proved control of proof.address. It does nothing unless that
// proof carries to the account's own address (ProofCarriesTo): an account
// found by a linked provider id may hold a different address, or none. The
// write lands only while the account still holds the address checked, so an
// email change racing the proof leaves the new address unverified.
// Any credential on the account was established BEFORE this proof — possibly
// by a different party (account pre-hijacking) — so the untrusted ones are
// voided:
//
//   - a planted password is cleared (the owner re-establishes it via reset);
//   - any planted passkeys are deleted. A passkey enrolled while the email was
//     unverified is exactly as untrustworthy as a planted password: passkey
//     login does not pass through the email-verification gate, so without this
//     an attacker who passkey-first-signed-up an unverified address would keep
//     a working credential after the real owner takes the account over;
//   - every provider link the proof voids is deleted (see voids). A link
//     signs in by provider id alone, so one added to the unverified account
//     (by whoever held it, or by a sign-in from a +tag address outside Gmail
//     that only resembles this one) would otherwise outlive the proof.
//
// It is a no-op when the email is already verified (the proof adds nothing).
// It fails closed: if any step before the address is marked verified cannot
// complete, the proof fails with ErrUnavailable and the address stays
// unproven, so the next proof sweeps again. If the account's address changed
// while the proof ran, nothing is verified and the proof signs in no further
// than an unverified account would; what it voided was added to an account
// whose address was unproven, so voiding it stands.
func (s *AuthService) markEmailVerifiedViaExternalProof(ctx context.Context, user *User, proof externalProof, nowMs int64) error {
	if user == nil || user.EmailVerified || !ProofCarriesTo(proof.address, user.Email) {
		return nil
	}
	repo := s.repo(ctx)

	passkeys, err := repo.ListPasskeyCredentials(ctx, user.ID)
	if err != nil {
		return s.externalProofSweepFailed(user.ID, proof, "list_passkeys", err)
	}
	links, err := repo.ListOAuthIdentitiesForUser(ctx, user.ID)
	if err != nil {
		return s.externalProofSweepFailed(user.ID, proof, "list_provider_links", err)
	}
	plantedLinks := proof.voidedAmong(links, user.Email)
	hadPassword := user.PasswordHash != ""
	passkeysCleared := len(passkeys) > 0

	if hadPassword || passkeysCleared || len(plantedLinks) > 0 {
		// Sessions go first, as ConfirmPasswordReset ends them for a replaced
		// password: one opened with a voided credential must not outlive it.
		// Doing it before the deletions means a failure further on leaves the
		// credentials in place, so the retried proof finds them and revokes
		// again.
		if err := s.revokeSessionsForProof(ctx, user.ID, proof, nowMs); err != nil {
			return err
		}
	}
	if passkeysCleared {
		if err := repo.DeletePasskeyCredentialsForUser(ctx, user.ID); err != nil {
			return s.externalProofSweepFailed(user.ID, proof, "delete_passkeys", err)
		}
	}
	if err := s.voidProviderLinks(ctx, user.ID, proof, plantedLinks); err != nil {
		return err
	}

	// Any password the account holds at this write predates the proof of
	// email control, including one set since the read above, so it cannot
	// be trusted to belong to the verified owner. It is cleared with the flag.
	verified, passwordCleared, err := repo.SetUserEmailVerified(ctx, user.ID, user.Email, nowMs, true)
	if err != nil {
		return s.externalProofSweepFailed(user.ID, proof, "mark_verified", err)
	}
	if !verified {
		s.logger.Info("email_verified_external_address_changed",
			zap.String("user_id", user.ID), zap.String("method", proof.method))
		s.auditVoidedCredentials(ctx, user.ID, proof, false, passkeysCleared, len(plantedLinks))
		return nil
	}
	user.EmailVerified = true
	user.EmailVerifiedAt = nowMs
	user.PasswordHash = ""
	user.PasswordChangeRequired = false

	// A passkey or link a signed-in caller added after the listings above
	// escaped them. CompletePasskeyRegistration and LinkIdentity re-read the
	// account after their insert and withdraw what was added while the
	// address was being proven; listing again now that the address is marked
	// verified means one of the two sees the other.
	passkeys, err = repo.ListPasskeyCredentials(ctx, user.ID)
	if err != nil {
		return s.externalProofSweepFailed(user.ID, proof, "relist_passkeys", err)
	}
	if len(passkeys) > 0 {
		if err := repo.DeletePasskeyCredentialsForUser(ctx, user.ID); err != nil {
			return s.externalProofSweepFailed(user.ID, proof, "delete_passkeys", err)
		}
		passkeysCleared = true
	}
	links, err = repo.ListOAuthIdentitiesForUser(ctx, user.ID)
	if err != nil {
		return s.externalProofSweepFailed(user.ID, proof, "relist_provider_links", err)
	}
	if lateLinks := proof.voidedAmong(links, user.Email); len(lateLinks) > 0 {
		if err := s.voidProviderLinks(ctx, user.ID, proof, lateLinks); err != nil {
			return err
		}
		plantedLinks = append(plantedLinks, lateLinks...)
	}
	if passwordCleared || passkeysCleared || len(plantedLinks) > 0 {
		// A sign-in with a voided credential that landed between the first
		// revocation and the verified write opened a session that revocation
		// missed; end it now that the credential is gone.
		if err := s.revokeSessionsForProof(ctx, user.ID, proof, nowMs); err != nil {
			return err
		}
	}

	s.auditVoidedCredentials(ctx, user.ID, proof, passwordCleared, passkeysCleared, len(plantedLinks))
	return nil
}

// auditVoidedCredentials records what a proof voided, if anything.
func (s *AuthService) auditVoidedCredentials(ctx context.Context, userID string, proof externalProof, passwordCleared, passkeysCleared bool, linksCleared int) {
	if !passwordCleared && !passkeysCleared && linksCleared == 0 {
		return
	}
	s.logger.Info("email_verified_external_credentials_cleared",
		zap.String("user_id", userID),
		zap.String("method", proof.method),
		zap.Bool("password_cleared", passwordCleared),
		zap.Bool("passkeys_cleared", passkeysCleared),
		zap.Int("provider_links_cleared", linksCleared))
	s.audit.Log(
		ctx, audit.EventUnprovenCredentialsVoided,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"method":                 proof.method,
			"password_cleared":       passwordCleared,
			"passkeys_cleared":       passkeysCleared,
			"provider_links_cleared": linksCleared,
		}),
	)
}

// voidedAmong returns the links among links that the proof voids.
func (p externalProof) voidedAmong(links []*OAuthIdentity, accountEmail string) []*OAuthIdentity {
	var voided []*OAuthIdentity
	for _, link := range links {
		if p.voids(link, accountEmail) {
			voided = append(voided, link)
		}
	}
	return voided
}

// revokeSessionsForProof ends every session of the account the proof is
// voiding credentials on.
func (s *AuthService) revokeSessionsForProof(ctx context.Context, userID string, proof externalProof, nowMs int64) error {
	repo := s.repo(ctx)
	if err := repo.DeleteRefreshTokensForUser(ctx, userID); err != nil {
		return s.externalProofSweepFailed(userID, proof, "revoke_refresh_tokens", err)
	}
	if s.cfg.RevocationMode == config.RevocationModeSession {
		if err := repo.RevokeSessionsForUser(ctx, userID, nowMs); err != nil {
			return s.externalProofSweepFailed(userID, proof, "revoke_sessions", err)
		}
	}
	return nil
}

// voidProviderLinks deletes the links a proof voids, auditing each.
func (s *AuthService) voidProviderLinks(ctx context.Context, userID string, proof externalProof, links []*OAuthIdentity) error {
	for _, link := range links {
		if err := s.repo(ctx).DeleteOAuthIdentity(ctx, userID, link.Provider, link.ProviderUserID); err != nil {
			return s.externalProofSweepFailed(userID, proof, "delete_provider_link", err)
		}
		s.audit.Log(
			ctx, audit.EventIdentityUnlinked,
			audit.WithActor(userID),
			audit.WithSuccess(true),
			audit.WithDetails(map[string]any{
				"provider":         link.Provider,
				"provider_user_id": link.ProviderUserID,
				"reason":           "planted_link_cleared_on_external_email_verification",
				"method":           proof.method,
			}),
		)
	}
	return nil
}

// externalProofSweepFailed logs why the sweep stopped and returns the error
// the proof fails with. The store's error stays in the log: these calls are
// unauthenticated, so the caller learns only to try again.
func (s *AuthService) externalProofSweepFailed(userID string, proof externalProof, step string, err error) error {
	s.logger.Error("email_verified_external_sweep_failed",
		zap.String("user_id", userID),
		zap.String("method", proof.method),
		zap.String("step", step),
		zap.Error(err))
	return fmt.Errorf("%w: the address could not be proven", ErrUnavailable)
}

// applyOAuthProfileUpdates patches the local user record with any new
// fields from the provider (name, avatar, and the email-verified flag when
// the provider proved the account's address). Only a failure of that proof
// fails the login; a failed profile patch is logged.
func (s *AuthService) applyOAuthProfileUpdates(ctx context.Context, u *User, identity *oauth.Identity, email string, nowMs int64) error {
	patch := make(map[string]any)
	if identity.Name != "" && identity.Name != u.Name {
		patch["name"] = identity.Name
		u.Name = identity.Name
	}
	if identity.AvatarURL != "" && identity.AvatarURL != u.AvatarURL {
		patch["avatar_url"] = identity.AvatarURL
		u.AvatarURL = identity.AvatarURL
	}
	// A verified provider identity proves control of the address it asserts.
	// When that is the account's address, flip the account to verified and
	// clear any password planted while it was still unverified
	// (anti-pre-hijacking). This runs its own persistence, so it is
	// intentionally NOT folded into the name/avatar patch below.
	if err := s.markEmailVerifiedViaExternalProof(ctx, u, externalProof{
		address:        identity.Email,
		method:         "oauth",
		provider:       identity.Provider,
		providerUserID: identity.ProviderUserID,
	}, nowMs); err != nil {
		return err
	}
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
		return nil
	}
	patch["updated_at"] = nowMs
	if err := s.repo(ctx).UpdateUser(ctx, u.ID, patch); err != nil {
		s.logger.Warn("oauth_upsert_update_failed", zap.Error(err))
	}
	return nil
}

// linkOAuthIdentity persists the (provider, sub) → user_id linkage and
// emits an audit event. Best-effort: a failure is logged but does not
// fail the login since the user has already been authenticated. On a
// duplicate-link race the duplicate is treated as success — the next
// login will simply hit the fast path.
func (s *AuthService) linkOAuthIdentity(ctx context.Context, userID string, identity *oauth.Identity, nowMs int64) {
	if identity.ProviderUserID == "" || identity.Provider == "" {
		return
	}
	email := assertedAddress(identity)
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
// A refused lockout is audited as login_locked when refusalAuditDue.
func (s *AuthService) checkAccountStatus(ctx context.Context, user *User, ipAddr, userAgent string, gate sessionGate) error {
	if user.LockedUntil > 0 && user.LockedUntil > s.nowMs() {
		if s.refusalAuditDue(user, gate, "account_locked") {
			s.audit.Log(
				ctx, audit.EventLoginLocked,
				audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
				audit.WithSuccess(false),
				audit.WithDetails(map[string]any{
					"reason":       "account_locked",
					"locked_until": user.LockedUntil,
				}),
			)
		}
		return fmt.Errorf("%w: account temporarily locked due to too many failed attempts", ErrAccountLocked)
	}

	status := strings.ToLower(user.Status)
	switch {
	case isActiveStatus(status) || status == StatusPendingDeletion:
		// PENDING_DELETION is deliberately allowed to authenticate (unlike
		// DEACTIVATED/SUSPENDED): a successful login is exactly the signal that
		// cancels the pending deletion, which issueTokens does before minting
		// tokens.
	case status == StatusInvited:
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
	// A merged account is retired for good; accepting an old invitation must
	// not bring it back.
	if user.MergedIntoUserID != "" {
		return nil, fmt.Errorf("%w: a merged account cannot accept an invitation", ErrMergeRefused)
	}

	// Enforce the project access mode (login/invite context) on the invitee.
	// Invitation acceptance is the sanctioned way into an invite-only project, so
	// invite/open permit it; but an allowlist project still requires the invitee
	// be on the list (an admin cannot invite someone the allowlist excludes), and
	// a closed project refuses every acceptance. user.Email is the DB-persisted
	// (canonical) account email; wrap once (idempotent, self-heals a legacy row).
	if err := s.enforceAccountAccessLogin(ctx, user); err != nil {
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
		"password_hash":            pwHash,
		"password_change_required": false,
		"status":                   StatusActive,
		"updated_at":               now,
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

	user.Status = StatusActive
	user.UpdatedAt = msToTime(now)

	// The invitation token is shown to the inviting admin as well as mailed,
	// so redeeming it proves nothing about the address. While verification is
	// required, an unproven invitee gets no session: like a new sign-up, it is
	// sent a verification email and signs in once that is redeemed.
	if s.needsEmailVerification(user) {
		if err := s.sendEmailVerification(ctx, user.ID, emailLink{}); err != nil {
			s.logger.Warn("invitation_verification_email_failed",
				zap.String("user_id", user.ID), zap.Error(err))
		}
		s.logger.Info("invitation_accepted", zap.String("user_id", user.ID),
			zap.Bool("email_verification_required", true))
		return &LoginResult{User: user}, nil
	}

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
