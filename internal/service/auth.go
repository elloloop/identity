// Package service implements the business logic for the identity service.
//
// The AuthService sits between the Connect-Go handler layer and the EntDB
// persistence layer. It contains all authentication, token management, and
// 2FA logic. It does NOT import Connect/protobuf types -- it uses plain Go
// structs and returns errors that the handler translates to gRPC codes.
//
// Security invariants:
//   - Passwords, secrets, and tokens are NEVER logged.
//   - Failed login lockout: 5 attempts, 15-min lock (configurable).
//   - TOTP challenges: 5-min expiry, single-use.
//   - QR login sessions: 5-min expiry, consumed after token issuance.
//   - Refresh tokens: rotated on every use (old token deleted, new one issued).
//   - All security events are audit-logged via the audit.Logger.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
	"github.com/elloloop/identity/pkg/totp"
)

// ── Domain types ───────────────────────────────────────────────────────

// User represents a user in the identity system.
type User struct {
	ID               string
	Email            string
	Name             string
	AvatarURL        string
	Role             string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	TotpRequired     bool
	Status           string // "active", "invited", "deactivated", "suspended"
	RecoveryEmail    string
	QuotaBytes       int64
	LastLoginAtMs    int64
	PasswordHash     string // never exposed via RPC
	FailedLoginCount int
	LockedUntil      int64 // epoch ms; 0 = not locked
	EmailVerified    bool
	EmailVerifiedAt  int64 // epoch ms
}

// PasskeyInfo holds display-safe passkey credential metadata.
type PasskeyInfo struct {
	CredentialID string
	DeviceName   string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

// LoginResult is returned by password/OAuth login when successful.
type LoginResult struct {
	User             *User
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int32
	TotpRequired     bool
	LoginChallengeID string
}

// OAuthBeginResult carries the provider authorization URL and the
// server-minted state artifacts needed to complete the OAuth flow.
type OAuthBeginResult struct {
	AuthorizationURL string
	State            string
	StateToken       string
	CodeVerifier     string
	ExpiresIn        int32
}

// QrSessionInfo holds the public details of a QR login session.
type QrSessionInfo struct {
	Status        string
	NewDeviceInfo string
	NewDeviceIP   string
	ExpiresAt     time.Time
}

// PollQrResult holds the result of polling a QR login session.
type PollQrResult struct {
	Status       string
	User         *User
	AccessToken  string
	RefreshToken string
	ExpiresIn    int32
}

// ── Repository interface ───────────────────────────────────────────────
// All EntDB operations are behind this interface so the service layer
// is testable without a live gRPC connection.

// Repository abstracts all persistence operations for the auth service.
type Repository interface {
	// Users
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	GetUser(ctx context.Context, userID string) (*User, error)
	CreateUser(ctx context.Context, u *User) (string, error) // returns node ID
	UpdateUser(ctx context.Context, userID string, fields map[string]any) error

	// Lockout state. These are dedicated methods (rather than UpdateUser
	// patches) so the persistence layer can implement them as single
	// atomic writes — important for racing concurrent failed-login
	// attempts on the same account.
	IncrementFailedLoginCount(ctx context.Context, userID string) (newCount int32, err error)
	ResetFailedLoginCount(ctx context.Context, userID string) error
	SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error

	// Refresh tokens
	FindRefreshTokenByHash(ctx context.Context, hash string) (*RefreshTokenRecord, error)
	// FindRefreshTokenByHashIncludingConsumed returns the row even when
	// consumed_at != 0, so the replay-detection branch can identify the
	// user_id whose sessions must be invalidated.
	FindRefreshTokenByHashIncludingConsumed(ctx context.Context, hash string) (*RefreshTokenRecord, error)
	CreateRefreshToken(ctx context.Context, r *RefreshTokenRecord) (string, error)
	DeleteRefreshToken(ctx context.Context, nodeID string) error
	DeleteRefreshTokensForUser(ctx context.Context, userID string) error
	// ConsumeRefreshTokenByHash marks the refresh-token row as rotated by
	// setting consumed_at = atMs. The row is NOT deleted: replay attempts
	// must still find it so they can be detected. The implementation must
	// only mark a row consumed if it is currently unconsumed (consumed_at
	// == 0); concurrent rotations of the same token must result in
	// exactly one caller succeeding. Returns ErrUnauthenticated when the
	// row is already consumed or does not exist.
	//
	// Background sweep: rows with consumed_at older than the desired
	// retention window (e.g. 90 days, comfortably exceeding the longest
	// refresh-token lifetime) may be hard-deleted by a periodic job. Such
	// a sweep is not implemented in this package.
	ConsumeRefreshTokenByHash(ctx context.Context, hash string, atMs int64) error

	// Passkey credentials
	ListPasskeyCredentials(ctx context.Context, userID string) ([]*PasskeyCredRecord, error)
	GetPasskeyCredentialByCredID(ctx context.Context, credentialID string) (*PasskeyCredRecord, error)
	CreatePasskeyCredential(ctx context.Context, r *PasskeyCredRecord) (string, error)
	UpdatePasskeyCredential(ctx context.Context, nodeID string, fields map[string]any) error

	// Passkey challenges
	GetPasskeyChallenge(ctx context.Context, nodeID string) (*PasskeyChallengeRecord, error)
	CreatePasskeyChallenge(ctx context.Context, r *PasskeyChallengeRecord) (string, error)
	DeletePasskeyChallenge(ctx context.Context, nodeID string) error

	// QR login sessions
	FindQrLoginSession(ctx context.Context, sessionID string) (*QrLoginSessionRecord, error)
	CreateQrLoginSession(ctx context.Context, r *QrLoginSessionRecord) (string, error)
	UpdateQrLoginSession(ctx context.Context, nodeID string, fields map[string]any) error

	// TOTP credentials
	GetTotpCredential(ctx context.Context, userID string) (*TotpCredRecord, error)
	CreateTotpCredential(ctx context.Context, r *TotpCredRecord) (string, error)
	UpdateTotpCredential(ctx context.Context, nodeID string, fields map[string]any) error
	DeleteTotpCredential(ctx context.Context, nodeID string) error
	DeleteTotpCredentialsForUser(ctx context.Context, userID string) error

	// Recovery codes
	CreateRecoveryCode(ctx context.Context, r *RecoveryCodeRecord) (string, error)
	FindRecoveryCodeByHash(ctx context.Context, userID, hash string) (*RecoveryCodeRecord, error)
	UpdateRecoveryCode(ctx context.Context, nodeID string, fields map[string]any) error
	DeleteRecoveryCodesForUser(ctx context.Context, userID string) error

	// Login challenges (TOTP 2FA step)
	CreateLoginChallenge(ctx context.Context, r *LoginChallengeRecord) (string, error)
	GetLoginChallengeByChallengeID(ctx context.Context, challengeID string) (*LoginChallengeRecord, error)
	DeleteLoginChallenge(ctx context.Context, nodeID string) error

	// User invitations
	FindInvitationByHash(ctx context.Context, tokenHash string) (*InvitationRecord, error)
	UpdateInvitation(ctx context.Context, nodeID string, fields map[string]any) error

	// Password-reset tokens
	CreatePasswordResetToken(ctx context.Context, t *PasswordResetToken) error
	FindPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	MarkPasswordResetTokenConsumed(ctx context.Context, tokenID string, atMs int64) error

	// Email-verification tokens
	CreateEmailVerificationToken(ctx context.Context, t *EmailVerificationToken) error
	FindEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*EmailVerificationToken, error)
	MarkEmailVerificationTokenConsumed(ctx context.Context, tokenID string, atMs int64) error

	// User email-verified update
	SetUserEmailVerified(ctx context.Context, userID string, atMs int64) error

	// Email-change tokens (primary email rotation, double-opt-in)
	CreateEmailChangeToken(ctx context.Context, t *EmailChangeToken) error
	FindEmailChangeTokenByHash(ctx context.Context, tokenHash string) (*EmailChangeToken, error)
	MarkEmailChangeTokenConsumed(ctx context.Context, tokenID string, atMs int64) error
	// UpdateUserEmail sets the user's primary email and marks it verified
	// (since the new address has just proven control via the consumed
	// token). Implementations must also set updated_at = atMs.
	UpdateUserEmail(ctx context.Context, userID, newEmail string, atMs int64) error

	// OAuth identities — links a (provider, provider_user_id) pair to a
	// local User so OAuth login can survive provider-side email changes.
	FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*User, error)
	CreateOAuthIdentity(ctx context.Context, oi *OAuthIdentity) error
	ListOAuthIdentitiesForUser(ctx context.Context, userID string) ([]*OAuthIdentity, error)
}

// ── Record types for persistence ───────────────────────────────────────

// RefreshTokenRecord represents a stored refresh token.
type RefreshTokenRecord struct {
	NodeID       string
	TokenHash    string
	UserID       string
	DeviceInfo   string
	DeviceName   string
	IPAddress    string
	UserAgent    string
	ExpiresAt    int64 // epoch ms
	CreatedAt    int64
	LastUsedAt   int64
	ConsumedAtMs int64 // epoch ms; 0 = unconsumed (still valid for refresh)
}

// PasskeyCredRecord represents a stored passkey credential.
type PasskeyCredRecord struct {
	NodeID       string
	CredentialID string
	UserID       string
	PublicKey    string
	SignCount    int64
	DeviceName   string
	AAGUID       string
	Transports   string
	CreatedAt    int64
	LastUsedAt   int64
}

// PasskeyChallengeRecord represents a stored passkey challenge.
type PasskeyChallengeRecord struct {
	NodeID        string
	Challenge     string // base64url
	UserID        string
	ChallengeType string // "registration" or "authentication"
	ExpiresAt     int64
	CreatedAt     int64
}

// QrLoginSessionRecord represents a stored QR login session.
type QrLoginSessionRecord struct {
	NodeID             string
	SessionID          string
	Status             string
	UserID             string
	NewDeviceInfo      string
	NewDeviceIP        string
	NewDeviceUserAgent string
	ApprovedDeviceInfo string
	ExpiresAt          int64
	CreatedAt          int64
	UpdatedAt          int64
}

// TotpCredRecord represents a stored TOTP credential.
type TotpCredRecord struct {
	NodeID          string
	UserID          string
	SecretEncrypted string
	Verified        bool
	CreatedAt       int64
	LastUsedAt      int64
}

// RecoveryCodeRecord represents a stored recovery code.
type RecoveryCodeRecord struct {
	NodeID    string
	UserID    string
	CodeHash  string
	Used      bool
	CreatedAt int64
	UsedAt    int64
}

// LoginChallengeRecord represents a pending 2FA login challenge.
type LoginChallengeRecord struct {
	NodeID      string
	ChallengeID string
	UserID      string
	ExpiresAt   int64
	CreatedAt   int64
}

// PasswordResetToken represents a stored password-reset token.
type PasswordResetToken struct {
	NodeID     string
	TokenHash  string
	UserID     string
	ExpiresAt  int64 // epoch ms
	CreatedAt  int64 // epoch ms
	ConsumedAt int64 // epoch ms; 0 = unconsumed
}

// EmailVerificationToken represents a stored email-verification token.
type EmailVerificationToken struct {
	NodeID     string
	TokenHash  string
	UserID     string
	Email      string
	ExpiresAt  int64 // epoch ms
	CreatedAt  int64 // epoch ms
	ConsumedAt int64 // epoch ms; 0 = unconsumed
}

// EmailChangeToken represents a pending primary-email rotation.
// The token is created at request time (after re-auth) and consumed
// when the user clicks the verification link sent to the *new* address.
type EmailChangeToken struct {
	NodeID     string
	TokenHash  string
	UserID     string
	OldEmail   string
	NewEmail   string
	ExpiresAt  int64 // epoch ms
	CreatedAt  int64 // epoch ms
	ConsumedAt int64 // epoch ms; 0 = unconsumed
}

// OAuthIdentity is the persisted link between a local User and a
// provider-side stable identity (provider, provider_user_id).
//
// Lookups by (provider, provider_user_id) are what make OAuth login
// resilient to a provider-side email change: the user keeps the same
// local account even if their gmail address changes.
//
// Composite uniqueness on (provider, provider_user_id) is enforced at
// the application layer — EntDB does not currently expose composite
// unique constraints. CreateOAuthIdentity callers must lookup first.
type OAuthIdentity struct {
	NodeID          string
	UserID          string
	Provider        string
	ProviderUserID  string
	EmailAtLinkTime string
	CreatedAt       int64 // epoch ms
}

// InvitationRecord represents a user invitation.
type InvitationRecord struct {
	NodeID     string
	TokenHash  string
	Email      string
	UserID     string
	InvitedBy  string
	Role       string
	ExpiresAt  int64
	AcceptedAt int64
	CreatedAt  int64
}

// ── Sentinel errors ────────────────────────────────────────────────────

var (
	ErrUnauthenticated   = errors.New("unauthenticated")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrInvalidArgument   = errors.New("invalid argument")
	ErrNotFound          = errors.New("not found")
	ErrAlreadyExists     = errors.New("already exists")
	ErrAccountLocked     = errors.New("account locked")
	ErrNoPasswordSet     = errors.New("no password set for this account")
	ErrAccountNotActive  = errors.New("account is not active")
	ErrInvitationPending = errors.New("account has not completed invitation")
	ErrWeakPassword      = errors.New("password does not meet strength requirements")
	ErrTotpRequired      = errors.New("totp required")
	ErrTokenExpired      = errors.New("token expired")
	ErrInvalidTotpCode   = errors.New("invalid totp code")
	ErrQrLoginExpired    = errors.New("qr login session expired")
	ErrQrLoginNotPending = errors.New("qr login session is not pending")
	ErrInvitationUsed    = errors.New("invitation has already been accepted")
	ErrInvitationExpired = errors.New("invitation has expired")
	ErrLocalAuthDisabled = errors.New("local auth disabled")
	ErrOAuthDisabled     = errors.New("oauth login is not configured")
	ErrSignupDisabled    = errors.New("signup is disabled for this deployment")
)

// ── AuthService ────────────────────────────────────────────────────────

// AuthService implements authentication and token management business logic.
type AuthService struct {
	repo     Repository
	tenantID string
	keyRing  *jwt.KeyRing
	passkeys *passkeys.WebAuthnService
	audit    *audit.Logger
	cfg      *config.Config
	totpKey  []byte
	mailer   email.Transport
	logger   *zap.Logger
	// oauthRegistry holds per-provider Exchangers. May be nil; in that
	// case OAuthLogin returns ErrOAuthDisabled. A non-nil but empty
	// registry has the same effect when looking up a specific provider.
	oauthRegistry *oauth.Registry
	nowFunc       func() time.Time // overridable for testing
}

// NewAuthService creates an AuthService with all required dependencies.
//
// mailer may be nil; if nil, a non-delivering log-only transport is
// substituted so service code can always call s.mailer.Send without a
// nil check. Email-side-effect failures are logged and do NOT fail the
// surrounding RPC.
func NewAuthService(
	repo Repository,
	cfg *config.Config,
	keyRing *jwt.KeyRing,
	passkeysSvc *passkeys.WebAuthnService,
	auditLogger *audit.Logger,
	totpKey []byte,
	mailer email.Transport,
	logger *zap.Logger,
) *AuthService {
	return NewAuthServiceWithOAuth(repo, cfg, keyRing, passkeysSvc, auditLogger, totpKey, mailer, logger, nil)
}

// NewAuthServiceWithOAuth is the extended constructor that injects an
// oauth.Registry. Pass nil to disable OAuth login.
func NewAuthServiceWithOAuth(
	repo Repository,
	cfg *config.Config,
	keyRing *jwt.KeyRing,
	passkeysSvc *passkeys.WebAuthnService,
	auditLogger *audit.Logger,
	totpKey []byte,
	mailer email.Transport,
	logger *zap.Logger,
	oauthRegistry *oauth.Registry,
) *AuthService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if mailer == nil {
		mailer = email.NewLogOnly(logger)
	}
	if !cfg.PasswordSignupEnabled {
		logger.Warn("password_signup_disabled")
	}
	if !cfg.PasswordResetEnabled {
		logger.Warn("password_reset_disabled")
	}
	return &AuthService{
		repo:          repo,
		tenantID:      cfg.DefaultTenantID,
		keyRing:       keyRing,
		passkeys:      passkeysSvc,
		audit:         auditLogger,
		cfg:           cfg,
		totpKey:       totpKey,
		mailer:        mailer,
		logger:        logger,
		oauthRegistry: oauthRegistry,
		nowFunc:       time.Now,
	}
}

// ── Internal helpers ───────────────────────────────────────────────────

func (s *AuthService) nowMs() int64 { return s.nowFunc().UnixMilli() }

// generateRefreshToken creates a cryptographically random refresh token
// and its SHA-256 hash. Returns (rawToken, hash).
func generateRefreshToken() (string, string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	raw := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(h[:])
}

// hashRefreshToken returns the SHA-256 hex digest of a raw refresh token.
func hashRefreshToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// hashInvitationToken returns the SHA-256 hex digest of a raw invitation token.
func hashInvitationToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateChallengeID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// issueTokens creates a JWT access token and a refresh token stored in the repo.
func (s *AuthService) issueTokens(ctx context.Context, user *User, ipAddr, userAgent string) (string, string, error) {
	claims := jwt.Claims{
		Sub:       user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Role:      user.Role,
		Tenant:    s.tenantID,
		AvatarURL: user.AvatarURL,
	}
	accessToken, err := jwt.CreateAccessToken(claims, s.keyRing, s.cfg.JWTExpiry())
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	rawRefresh, refreshHash := generateRefreshToken()
	now := s.nowMs()
	devName := friendlyDeviceName(userAgent)

	_, err = s.repo.CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash:  refreshHash,
		UserID:     user.ID,
		DeviceInfo: devName,
		DeviceName: devName,
		IPAddress:  ipAddr,
		UserAgent:  truncate(userAgent, 512),
		ExpiresAt:  now + int64(s.cfg.RefreshExpirySeconds)*1000,
		CreatedAt:  now,
		LastUsedAt: now,
	})
	if err != nil {
		return "", "", fmt.Errorf("storing refresh token: %w", err)
	}
	return accessToken, rawRefresh, nil
}

// recordFailedLogin increments the failed login counter and, if the
// configured threshold is now reached, locks the account for the
// configured cooldown. Returns the new counter value (0 if increment
// failed) and a "locked" flag indicating the threshold was tripped on
// THIS call. Errors are returned so callers can fail closed: a silent
// swallow here would let a database outage become a lockout-bypass.
func (s *AuthService) recordFailedLogin(ctx context.Context, user *User) (newCount int32, lockedNow bool, err error) {
	newCount, err = s.repo.IncrementFailedLoginCount(ctx, user.ID)
	if err != nil {
		s.logger.Warn("failed_login_increment_failed",
			zap.String("user_id", user.ID), zap.Error(err))
		return 0, false, err
	}
	if int(newCount) >= s.cfg.LoginMaxFailedAttempts {
		now := s.nowMs()
		lockedUntil := now + int64(s.cfg.LoginLockoutSeconds)*1000
		if lockErr := s.repo.SetUserLockedUntil(ctx, user.ID, lockedUntil); lockErr != nil {
			s.logger.Warn("set_locked_until_failed",
				zap.String("user_id", user.ID), zap.Error(lockErr))
			return newCount, false, lockErr
		}
		s.logger.Warn("account_locked",
			zap.String("user_id", user.ID),
			zap.Int("lockout_seconds", s.cfg.LoginLockoutSeconds),
		)
		return newCount, true, nil
	}
	return newCount, false, nil
}

// resetFailedLogin clears the failed login counter and any active
// lockout on successful authentication. Best-effort: a failure to
// clear is logged but not propagated, since the user has already
// proven they hold the credentials.
func (s *AuthService) resetFailedLogin(ctx context.Context, user *User) {
	if user.FailedLoginCount == 0 && user.LockedUntil == 0 {
		return
	}
	if err := s.repo.ResetFailedLoginCount(ctx, user.ID); err != nil {
		s.logger.Warn("failed_login_reset_failed", zap.String("user_id", user.ID), zap.Error(err))
	}
}

// updateLastLogin sets last_login_at for admin visibility (best-effort).
func (s *AuthService) updateLastLogin(ctx context.Context, userID string) {
	now := s.nowMs()
	if err := s.repo.UpdateUser(ctx, userID, map[string]any{
		"last_login_at": now, "updated_at": now,
	}); err != nil {
		s.logger.Warn("last_login_update_failed", zap.String("user_id", userID), zap.Error(err))
	}
}

// issueLoginChallenge creates a pending 2FA login challenge.
func (s *AuthService) issueLoginChallenge(ctx context.Context, userID string) (string, error) {
	now := s.nowMs()
	challengeID := generateChallengeID()
	_, err := s.repo.CreateLoginChallenge(ctx, &LoginChallengeRecord{
		ChallengeID: challengeID,
		UserID:      userID,
		ExpiresAt:   now + int64(s.cfg.LoginChallengeExpirySeconds)*1000,
		CreatedAt:   now,
	})
	if err != nil {
		return "", fmt.Errorf("creating login challenge: %w", err)
	}
	return challengeID, nil
}

// consumeLoginChallenge validates and deletes a pending login challenge.
func (s *AuthService) consumeLoginChallenge(ctx context.Context, challengeID string) (*LoginChallengeRecord, error) {
	record, err := s.repo.GetLoginChallengeByChallengeID(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("%w: invalid or expired login challenge", ErrUnauthenticated)
	}
	if record.ExpiresAt < s.nowMs() {
		_ = s.repo.DeleteLoginChallenge(ctx, record.NodeID)
		return nil, fmt.Errorf("%w: login challenge expired", ErrUnauthenticated)
	}
	// Single-use: delete before returning success.
	if err := s.repo.DeleteLoginChallenge(ctx, record.NodeID); err != nil {
		s.logger.Warn("login_challenge_delete_failed", zap.String("challenge_id", challengeID))
	}
	return record, nil
}

// storeRecoveryCodes deletes existing codes for a user and stores fresh hashes.
func (s *AuthService) storeRecoveryCodes(ctx context.Context, userID string, codes []string) error {
	if err := s.repo.DeleteRecoveryCodesForUser(ctx, userID); err != nil {
		return fmt.Errorf("deleting old recovery codes: %w", err)
	}
	now := s.nowMs()
	for _, code := range codes {
		_, err := s.repo.CreateRecoveryCode(ctx, &RecoveryCodeRecord{
			UserID:    userID,
			CodeHash:  totp.HashRecoveryCode(code),
			Used:      false,
			CreatedAt: now,
		})
		if err != nil {
			return fmt.Errorf("creating recovery code: %w", err)
		}
	}
	return nil
}

// ensureMailbox auto-provisions an email mailbox for new users. Best-effort.
func (s *AuthService) ensureMailbox(_ context.Context, _ string, _ string, _ string) {
	// Placeholder -- email service client not yet wired.
}

// validatePasswordStrength checks password requirements and returns an error if weak.
func validatePasswordStrength(pw string) error {
	issues := passwords.ValidateStrength(pw)
	if len(issues) > 0 {
		return fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(issues, "; "))
	}
	return nil
}

// friendlyDeviceName collapses a User-Agent string into a short display name.
func friendlyDeviceName(userAgent string) string {
	if userAgent == "" {
		return "Unknown device"
	}
	low := strings.ToLower(userAgent)
	browser := "Browser"
	switch {
	case strings.Contains(low, "edg/"):
		browser = "Edge"
	case strings.Contains(low, "chrome/") && strings.Contains(low, "safari/") && !strings.Contains(low, "edg/"):
		browser = "Chrome"
	case strings.Contains(low, "firefox/"):
		browser = "Firefox"
	case strings.Contains(low, "safari/") && !strings.Contains(low, "chrome/"):
		browser = "Safari"
	case strings.Contains(low, "postman"):
		browser = "Postman"
	case strings.Contains(low, "curl/"):
		browser = "curl"
	}
	osName := "Unknown OS"
	switch {
	case strings.Contains(low, "iphone") || strings.Contains(low, "ipad") || strings.Contains(low, "ipod"):
		osName = "iOS"
	case strings.Contains(low, "android"):
		osName = "Android"
	case strings.Contains(low, "windows nt"):
		osName = "Windows"
	case strings.Contains(low, "mac os x") || strings.Contains(low, "macintosh"):
		osName = "macOS"
	case strings.Contains(low, "linux"):
		osName = "Linux"
	}
	return browser + " on " + osName
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// ── GetCurrentUser ─────────────────────────────────────────────────────

// GetCurrentUser returns the user record for the given user ID.
func (s *AuthService) GetCurrentUser(ctx context.Context, userID string) (*User, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: missing user ID", ErrUnauthenticated)
	}
	user, err := s.repo.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	return user, nil
}

// ── RefreshToken ───────────────────────────────────────────────────────

// RefreshToken validates a refresh token, rotates it, and returns new tokens.
//
// Replay detection is durable: rotated tokens are kept in the repository
// with consumed_at != 0 instead of being deleted, so any instance — and
// any process restart — can detect a stolen-token replay (OAuth 2.1
// §4.13). When replay is detected, ALL of the user's refresh tokens are
// hard-deleted to bound the blast radius.
//
// Concurrency: the repository's ConsumeRefreshTokenByHash is the
// serialization point. Two goroutines presenting the same refresh token
// race to consume it; the loser sees ErrUnauthenticated and the row
// stays consumed exactly once.
//
// Background sweep: rows whose ConsumedAtMs is older than the desired
// retention window (e.g. 90 days) may be hard-deleted by a periodic job.
// That sweep is intentionally NOT implemented here.
func (s *AuthService) RefreshToken(ctx context.Context, rawRefreshToken, ipAddr, userAgent string) (*User, string, string, error) {
	if rawRefreshToken == "" {
		return nil, "", "", fmt.Errorf("%w: missing refresh token", ErrUnauthenticated)
	}
	tokenHash := hashRefreshToken(rawRefreshToken)

	record, err := s.repo.FindRefreshTokenByHashIncludingConsumed(ctx, tokenHash)
	if err != nil {
		return nil, "", "", fmt.Errorf("querying refresh token: %w", err)
	}
	if record == nil {
		return nil, "", "", fmt.Errorf("%w: invalid refresh token", ErrUnauthenticated)
	}

	if record.ConsumedAtMs > 0 {
		// Refresh-token reuse detection (OAuth 2.1 §4.13): the row exists
		// but has already been rotated. Treat as a stolen token and
		// revoke ALL refresh tokens for that user — even the legitimate
		// user will be forced to re-authenticate.
		userID := record.UserID
		s.logger.Warn("refresh_token_replay_detected", zap.String("user_id", userID))
		if delErr := s.repo.DeleteRefreshTokensForUser(ctx, userID); delErr != nil {
			s.logger.Warn("refresh_token_replay_revoke_failed",
				zap.String("user_id", userID), zap.Error(delErr))
		}
		s.audit.Log(ctx, audit.EventLoginFailure,
			audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "refresh_token_replay"}),
		)
		return nil, "", "", fmt.Errorf("%w: refresh token replay", ErrUnauthenticated)
	}

	if record.ExpiresAt < s.nowMs() {
		_ = s.repo.DeleteRefreshToken(ctx, record.NodeID)
		return nil, "", "", fmt.Errorf("%w: refresh token expired", ErrTokenExpired)
	}

	// Rotation. ConsumeRefreshTokenByHash is the serialization point: it
	// only succeeds when the row's consumed_at is currently 0, so two
	// concurrent rotations of the same token resolve to exactly one
	// winner. The loser observes the now-consumed state on its next read
	// and gets ErrUnauthenticated.
	if err := s.repo.ConsumeRefreshTokenByHash(ctx, tokenHash, s.nowMs()); err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return nil, "", "", fmt.Errorf("%w: refresh token already consumed", ErrUnauthenticated)
		}
		return nil, "", "", fmt.Errorf("consuming refresh token: %w", err)
	}

	user, err := s.repo.GetUser(ctx, record.UserID)
	if err != nil {
		return nil, "", "", err
	}
	if user == nil {
		return nil, "", "", fmt.Errorf("%w: user not found", ErrNotFound)
	}

	accessToken, newRefresh, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, "", "", err
	}
	return user, accessToken, newRefresh, nil
}

// ── Logout ─────────────────────────────────────────────────────────────

// Logout deletes the refresh token identified by the raw token value.
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	if rawRefreshToken == "" {
		return nil
	}
	tokenHash := hashRefreshToken(rawRefreshToken)
	record, err := s.repo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("querying refresh token: %w", err)
	}
	if record == nil {
		return nil
	}
	userID := record.UserID
	_ = s.repo.DeleteRefreshToken(ctx, record.NodeID)

	if userID != "" {
		s.audit.Log(ctx, audit.EventLogout, audit.WithActor(userID))
	}
	return nil
}
