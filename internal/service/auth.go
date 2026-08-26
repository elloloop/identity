// Package service implements the business logic for the identity service.
//
// The AuthService sits between the Connect-Go handler layer and the graph
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
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
	"github.com/elloloop/identity/pkg/sms"
	"github.com/elloloop/identity/pkg/totp"
)

// ── Domain types ───────────────────────────────────────────────────────

// StatusPendingParentalConsent is the user status for a child-band account
// created under age-gating that has not yet obtained verifiable parental
// consent. Such an account exists but cannot be issued access tokens.
const StatusPendingParentalConsent = "pending_parental_consent"

// User status strings shared across the service. Persisted verbatim in the
// status column; the connect layer maps them to the UserStatus proto enum.
const (
	// StatusActive is a normal, fully-usable account.
	StatusActive = "active"
	// StatusPendingDeletion marks an account whose owner requested
	// self-service deletion. It is disabled and scheduled for a permanent
	// purge once the grace window elapses; a successful interactive login
	// during the window cancels it and restores StatusActive.
	StatusPendingDeletion = "pending_deletion"
	// StatusDeactivated is a suspended account: it exists, cannot be issued
	// tokens, and is reversible by whoever suspended it (an admin via
	// ReactivateUser, a guardian via ReactivateManagedChildAccount).
	StatusDeactivated = "deactivated"
)

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
	IDVVerified      bool  // latest identity verification reached APPROVED
	IDVVerifiedAt    int64 // epoch ms; 0 = never verified
	PhoneNumber      string
	PhoneVerified    bool
	PhoneVerifiedAt  int64 // epoch ms; 0 = never verified
	DateOfBirthMs    int64 // epoch ms of date of birth; 0 = unknown (persisted)
	// Market is the jurisdiction/market code (e.g. "IN", "US") the account
	// belongs to, captured at account creation or set via SetAccountMarket
	// (persisted, canonicalized to the trimmed upper-case form). When the
	// project configures per-jurisdiction thresholds it selects the boundary
	// pair the age band derives from; empty means the project default or the
	// deployment-wide env thresholds apply.
	Market string
	// Username is the parent-chosen, project-unique handle identifying a
	// managed child account (children often have no email). Lowercase
	// alphanumerics plus `_`/`-`/`.`, 3..32 chars, normalized to lowercase
	// before storage; unique within the project when non-empty (the SQL
	// drivers' partial unique index), and usable as the PasswordLogin
	// identifier. Empty on every account not created via
	// CreateManagedChildAccount.
	Username string
	// DeletionScheduledAtMs is the epoch-ms instant a PENDING_DELETION account
	// is permanently purged. 0 when the account is not pending self-service
	// deletion. Set when the owner requests deletion; cleared on cancel or a
	// login-time auto-cancel.
	DeletionScheduledAtMs int64
	// IsMinor and AgeBand are DERIVED from DateOfBirthMs + the age-gate
	// configuration; they are NOT persisted. The service stamps them on a
	// user before returning it so the handler/JWT layers can read a single
	// authoritative value.
	IsMinor    bool
	AgeBand    string // "CHILD" | "TEEN" | "ADULT" | "" (unknown)
	ExternalID string // IdP-owned stable identifier (SCIM externalId); unique per tenant when set
	// IsAnonymous marks a user created by SignInAnonymously: a real account
	// with a stable id but no credential of any kind (no email, no password,
	// no provider identity, no passkey). It is reachable only through its
	// refresh token. Upgrading the account attaches a credential and clears
	// this flag WITHOUT changing ID, so data the client wrote against the id
	// survives. Email is always "" while this is true — that is what keeps
	// any number of anonymous users inside one project, since the per-project
	// email uniqueness index only covers non-empty addresses.
	IsAnonymous bool
	// AnonymousLastSeenMs is the retention sweep's activity clock, advanced
	// on each anonymous refresh. Deliberately its OWN column rather than
	// last_login_at_ms: indexing that column would defeat HOT updates for
	// every ordinary login's last-login stamp (Postgres derives HOT
	// eligibility from the union of indexed columns and ignores
	// partial-index predicates). 0 for permanent accounts.
	AnonymousLastSeenMs int64
}

// DefaultUserListLimit and MaxUserListLimit bound a Repository.ListUsers
// page so a caller (e.g. the SCIM list surface) cannot request an
// unbounded scan. Every driver clamps to these identically.
const (
	DefaultUserListLimit = 50
	MaxUserListLimit     = 500
)

// UserListFilter narrows and paginates a Repository.ListUsers query. Zero
// values mean "no constraint": an empty Email/ExternalID does not filter,
// and a non-positive Limit means "use the driver default". Equality
// filters are case-insensitive for Email (RFC 7644 §3.4.2 treats userName
// — mapped to email — case-insensitively) and exact for ExternalID.
type UserListFilter struct {
	Email      string // exact (case-insensitive) email match when non-empty
	ExternalID string // exact external_id match when non-empty
	Offset     int    // skip this many matching rows (cursor)
	Limit      int    // max rows to return; <=0 → driver default
	// IncludeAnonymous admits credential-less accounts. It defaults FALSE
	// because an anonymous user has no email, and every consumer of this
	// filter presents users by one: SCIM makes userName REQUIRED and unique
	// (RFC 7643 §4.1.1), so exporting them yields N resources all carrying
	// an empty userName. Excluded in the DRIVER, not the caller, so a
	// paginated count matches the rows returned.
	IncludeAnonymous bool
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
// All graph DB operations are behind this interface so the service layer
// is testable without a live gRPC connection.

// Repository abstracts all persistence operations for the auth service.
type Repository interface {
	// Users
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	// FindUserByUsername resolves a managed child account by its
	// project-unique username (empty username matches nobody). It backs
	// username-identified PasswordLogin and the create-time uniqueness
	// pre-check.
	FindUserByUsername(ctx context.Context, username string) (*User, error)
	GetUser(ctx context.Context, userID string) (*User, error)
	CreateUser(ctx context.Context, u *User) (string, error) // returns node ID
	UpdateUser(ctx context.Context, userID string, fields map[string]any) error
	// DeleteUser physically removes the user and every user_id-keyed
	// record, synchronously, on every driver. This covers the durable
	// identity/auth material — sessions, refresh tokens, oauth identities,
	// passkey credentials, totp credentials, recovery codes, identity
	// verifications, and phone verification codes — and, as of #168, the
	// short-lived tokens too: password-reset, email-verification/change,
	// passkey and login challenges, qr sessions, oauth one-time codes, and
	// invitations.
	// After it, GetUser returns nil and the email is reusable for a new
	// CreateUser.
	//
	// The only artifacts NOT removed synchronously are the email-keyed
	// login codes / magic-link tokens, which carry no user_id and so
	// cannot be enumerated per-user; they are reaped by the TTL sweepers —
	// safe, since they expire quickly, reference a now-deleted user, and
	// never block email reuse. audit_events are retained for
	// accountability. Idempotent: deleting a non-existent user returns nil.
	//
	// (Invitations are drained but are the one user_id-keyed type the
	// cross-driver conformance suite cannot seed/assert — Repository
	// exposes no invitation create method; they are written via the graph
	// graph.)
	DeleteUser(ctx context.Context, userID string) error

	// ListUsersPendingDeletionBefore returns users whose status is
	// pending_deletion AND whose deletion_scheduled_at_ms is > 0 and <=
	// cutoffMs, ordered by deletion_scheduled_at_ms ascending then id, capped
	// at limit rows. It backs the account-deletion sweeper: rows it returns are
	// past their grace window and due for the hard-delete cascade. limit <= 0
	// is rejected (an uncapped scan could lock a hot table). Drivers must apply
	// the status/cutoff filter and ordering identically (see conformance).
	ListUsersPendingDeletionBefore(ctx context.Context, cutoffMs int64, limit int) ([]*User, error)

	// ListUsers returns users in the request's project that match filter,
	// ordered by created_at ascending then id, with a stable offset cursor.
	// It backs the SCIM /Users list/filter surface — including externalId
	// correlation via UserListFilter.ExternalID, the production path an IdP
	// uses to find a previously-provisioned account. Drivers must apply the
	// filter and ordering identically (see conformance).
	ListUsers(ctx context.Context, filter UserListFilter) ([]*User, error)

	// CountUsers returns the total number of users in the request's project
	// matching filter's equality predicates (Email/ExternalID), ignoring
	// Offset/Limit. It backs the SCIM /Users totalResults so a page reports
	// the true match count instead of the page size — and large projects are
	// never silently truncated at the page cap. Drivers must count the same
	// rows ListUsers would return across all pages (see conformance).
	CountUsers(ctx context.Context, filter UserListFilter) (int, error)

	// Lockout state. These are dedicated methods (rather than UpdateUser
	// patches) so the persistence layer can implement them as single
	// atomic writes — important for racing concurrent failed-login
	// attempts on the same account.
	IncrementFailedLoginCount(ctx context.Context, userID string) (newCount int32, err error)
	ResetFailedLoginCount(ctx context.Context, userID string) error
	SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error

	// Sessions (mode=session revocation). The verification middleware
	// looks the row up by SID on every authenticated request (via an
	// in-process cache; see internal/middleware/session.go). A non-zero
	// RevokedAtMs means the session has been killed and any access
	// token carrying this SID must be rejected.
	//
	// CreateSession is invoked from the token-issuance path when
	// `mode=session`. GetSessionBySid is the read on the hot path;
	// RevokeSession atomically marks one session revoked; and
	// RevokeSessionsForUser is invoked from DeleteRefreshTokensForUser
	// so the existing replay-detection path also kills the access
	// tokens.
	//
	// Implementations MUST guarantee SID uniqueness; CreateSession
	// returns ErrAlreadyExists when the SID collides. RevokeSession
	// is idempotent — re-revoking an already-revoked session is a
	// no-op rather than an error so concurrent revoke calls don't
	// race each other into failure.
	CreateSession(ctx context.Context, s *SessionRecord) (string, error)
	GetSessionBySid(ctx context.Context, sid string) (*SessionRecord, error)
	RevokeSession(ctx context.Context, sid string, atMs int64) error
	RevokeSessionsForUser(ctx context.Context, userID string, atMs int64) error

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
	// DeletePasskeyCredentialsForUser removes every passkey credential
	// owned by userID, synchronously, on every driver. It backs the
	// anti-pre-hijacking clearing in markEmailVerifiedViaExternalProof: a
	// passkey enrolled while the email was unverified is untrusted (it may
	// have been planted by an attacker), exactly like a planted password, so
	// external proof of email control voids it. Idempotent: a user with no
	// passkeys is a no-op returning nil.
	DeletePasskeyCredentialsForUser(ctx context.Context, userID string) error

	// Passkey challenges
	GetPasskeyChallenge(ctx context.Context, nodeID string) (*PasskeyChallengeRecord, error)
	CreatePasskeyChallenge(ctx context.Context, r *PasskeyChallengeRecord) (string, error)
	DeletePasskeyChallenge(ctx context.Context, nodeID string) error

	// Assurance: hardware-attested devices and their one-shot challenges.
	// CreateAttestedDevice returns ErrAlreadyExists when the project
	// already holds the KeyID (one hardware key, one record).
	// GetAttestedDeviceByKeyID returns (nil, nil) when absent.
	// UpdateAttestedDeviceCounter is a compare-and-swap: it advances
	// SignCount from fromCount to toCount (stamping LastUsedAt) and
	// returns ErrCounterStale when the stored count is no longer
	// fromCount, or ErrNotFound when the device is gone — the CAS is what
	// keeps the App Attest counter strictly increasing under concurrent
	// assertions. ConsumeAssuranceChallenge atomically deletes and
	// returns the challenge so a nonce can never be redeemed twice;
	// (nil, nil) when absent or already consumed.
	CreateAttestedDevice(ctx context.Context, r *AttestedDeviceRecord) (string, error)
	GetAttestedDeviceByKeyID(ctx context.Context, keyID string) (*AttestedDeviceRecord, error)
	UpdateAttestedDeviceCounter(ctx context.Context, nodeID string, fromCount, toCount, lastUsedAtMs int64) error
	CreateAssuranceChallenge(ctx context.Context, r *AssuranceChallengeRecord) (string, error)
	ConsumeAssuranceChallenge(ctx context.Context, nodeID string) (*AssuranceChallengeRecord, error)
	DeleteExpiredAssuranceChallenges(ctx context.Context, beforeMs int64, limit int) error
	// DeleteStaleAttestedDevices reaps device rows whose LastUsedAt is older
	// than beforeMs. Attestation inserts a permanent row per key, and a
	// reinstall or key regeneration yields a NEW key id, so without a
	// retention sweep the table only ever grows. A reaped device simply
	// re-attests on its next refresh.
	DeleteStaleAttestedDevices(ctx context.Context, beforeMs int64, limit int) error

	// DeleteStaleAnonymousUsers reaps anonymous users whose
	// AnonymousLastSeenMs is older than beforeMs, together with the rows
	// that cascade from them.
	// An anonymous user holds no credential, so once it stops refreshing it
	// is unreachable forever and would otherwise accumulate one permanent
	// row per app install. Implementations MUST match on is_anonymous and
	// must never touch a user that has been upgraded to a permanent account
	// (which clears the flag, see UpgradeAnonymousUser).
	DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error

	// QR login sessions
	FindQrLoginSession(ctx context.Context, sessionID string) (*QrLoginSessionRecord, error)
	CreateQrLoginSession(ctx context.Context, r *QrLoginSessionRecord) (string, error)
	UpdateQrLoginSession(ctx context.Context, nodeID string, fields map[string]any) error
	// ConsumeQrLoginSession atomically transitions a QR login session
	// from status="approved" to status="consumed", setting updated_at
	// to atMs. Implementations must guarantee single-winner semantics
	// across concurrent callers: exactly one of N replicas polling the
	// same approved session may complete the transition; the rest see
	// ErrQrLoginNotPending and must NOT mint tokens. This is the
	// serialization point for the QR-login token-issuance flow in
	// multi-replica deployments. Returns ErrQrLoginNotPending when the
	// session does not exist or is no longer in the "approved" state.
	ConsumeQrLoginSession(ctx context.Context, nodeID string, atMs int64) error

	// OAuth one-time codes (hosted-flow SPA handover).
	//
	// CreateOAuthOneTimeCode stores the code-hash → user binding written
	// by the hosted /oauth/callback handler. ConsumeOAuthOneTimeCode is
	// the single-winner compare-and-set: it marks the row consumed
	// (consumed_at = atMs) only if it is currently unconsumed
	// (consumed_at == 0) AND not yet expired (expires_at > atMs),
	// returning the bound record on success. A replay, an expired code,
	// or a code that does not exist all return ErrOAuthCodeInvalid so
	// the redeem endpoint cannot be probed. Like ConsumeQrLoginSession
	// this is the serialization point across replicas: exactly one of N
	// concurrent redeems of the same code wins.
	CreateOAuthOneTimeCode(ctx context.Context, r *OAuthOneTimeCodeRecord) (string, error)
	ConsumeOAuthOneTimeCode(ctx context.Context, codeHash string, atMs int64) (*OAuthOneTimeCodeRecord, error)

	// Native ID-token replay cache (bearer-token single-use).
	//
	// Native mobile-SDK ID tokens (Google idToken / Apple identityToken) are
	// bearer JWTs replayable until their `exp` (~1h for Google; the Apple
	// nonce is client-optional), so a captured token could be redeemed more
	// than once. RecordNativeTokenRedemption makes each token single-use: it
	// atomically inserts the token's replay key (see NativeVerification.
	// ReplayKey) and returns nil on the FIRST redemption; a second insert of
	// the same key — a replay of the same bearer token — hits the unique
	// index and returns ErrNativeTokenReplayed. This is the multi-replica
	// serialization point: exactly one of N concurrent redemptions of the
	// same token wins. Retention is bounded by ExpiresAt (= the token's `exp`,
	// capped) so a swept row can never resurrect a still-valid token — once
	// the row's expiry passes, the token itself can no longer be presented.
	RecordNativeTokenRedemption(ctx context.Context, r *NativeTokenRedemptionRecord) (string, error)

	// Email login codes (OTP arm of passwordless email login).
	//
	// UpsertEmailLoginCode stores the latest code for an email, replacing
	// any existing live code for that address so at most one is valid at a
	// time (a re-request invalidates the previous code). It is keyed on
	// email; the unique index makes the upsert a delete-then-create or an
	// in-place overwrite depending on the backend.
	//
	// FindEmailLoginCodeByEmail returns the live row (consumed or not) so
	// the verify path can compare the code hash, count attempts, and
	// distinguish expired/consumed from a hash mismatch. Returns nil when
	// no row exists for the email.
	//
	// IncrementEmailLoginCodeAttempts bumps attempt_count by one. Used on
	// a wrong-code guess; the service invalidates the code once the count
	// reaches the cap captured on the record.
	//
	// ConsumeEmailLoginCode is the single-winner compare-and-set: it marks
	// the row consumed (consumed_at = atMs) only when currently unconsumed
	// AND unexpired, returning the bound record on success. A replay, an
	// expired code, or a missing code all return ErrEmailLoginCodeInvalid.
	UpsertEmailLoginCode(ctx context.Context, r *EmailLoginCodeRecord) (string, error)
	FindEmailLoginCodeByEmail(ctx context.Context, email string) (*EmailLoginCodeRecord, error)
	IncrementEmailLoginCodeAttempts(ctx context.Context, nodeID string) error
	ConsumeEmailLoginCode(ctx context.Context, email string, atMs int64) (*EmailLoginCodeRecord, error)

	// Magic-link tokens (magic-link arm of passwordless email login).
	//
	// CreateMagicLinkToken stores the token-hash → (email, return_to)
	// binding. ConsumeMagicLinkToken is the single-winner compare-and-set
	// (same shape as ConsumeOAuthOneTimeCode): it marks the row consumed
	// only when currently unconsumed AND unexpired, returning the bound
	// record on success. A replay, expired, or missing token all return
	// ErrMagicLinkInvalid.
	CreateMagicLinkToken(ctx context.Context, r *MagicLinkTokenRecord) (string, error)
	ConsumeMagicLinkToken(ctx context.Context, tokenHash string, atMs int64) (*MagicLinkTokenRecord, error)

	// Phone verification codes (SMS-OTP phone-ownership verification).
	//
	// UpsertPhoneVerificationCode stores the latest code for a user,
	// replacing any existing live code for that user so at most one is
	// valid at a time (a re-request invalidates the previous code). It is
	// keyed on user_id.
	//
	// FindPhoneVerificationCodeByUser returns the live row (consumed or
	// not) so the verify path can compare the code hash, count attempts,
	// and distinguish expired/consumed from a hash mismatch. Returns nil
	// when no row exists for the user.
	//
	// IncrementPhoneVerificationCodeAttempts bumps attempt_count by one,
	// used on a wrong-code guess; the service invalidates the code once
	// the count reaches the cap captured on the record.
	//
	// ConsumePhoneVerificationCode is the single-winner compare-and-set:
	// it marks the row consumed (consumed_at = atMs) only when currently
	// unconsumed AND unexpired, returning the bound record on success. A
	// replay, an expired code, or a missing code all return
	// ErrPhoneCodeInvalid.
	//
	// SetUserPhoneVerified records the verified phone on the user and
	// flips phone_verified, mirroring SetUserEmailVerified.
	UpsertPhoneVerificationCode(ctx context.Context, r *PhoneVerificationCodeRecord) (string, error)
	FindPhoneVerificationCodeByUser(ctx context.Context, userID string) (*PhoneVerificationCodeRecord, error)
	IncrementPhoneVerificationCodeAttempts(ctx context.Context, nodeID string) error
	ConsumePhoneVerificationCode(ctx context.Context, userID string, atMs int64) (*PhoneVerificationCodeRecord, error)
	SetUserPhoneVerified(ctx context.Context, userID, phoneNumber string, atMs int64) error

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

	// User idv-verified update; called by IdentityVerificationService
	// when a verification reaches APPROVED.
	SetUserIDVVerified(ctx context.Context, userID string, atMs int64) error

	// Identity-verification records (document + selfie verification).
	// Latest ordering is by CreatedAt descending.
	CreateIdentityVerification(ctx context.Context, r *IdentityVerificationRecord) error
	GetIdentityVerification(ctx context.Context, verificationID string) (*IdentityVerificationRecord, error)
	GetLatestIdentityVerificationForUser(ctx context.Context, userID string) (*IdentityVerificationRecord, error)
	UpdateIdentityVerificationStatus(ctx context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error

	// Parental-consent records (Verifiable Parental Consent — COPPA/DPDP/UK
	// Children's Code). The record is the auditable, revocable artifact proving
	// an adult consented for a child account.
	//
	// CreateParentalConsent persists a new record; the caller mints ConsentID.
	// GetActiveParentalConsentForChild returns the latest record for a child
	// whose RevokedAt == 0 (nil when none — no error), ordered by GrantedAt
	// descending; it backs both the double-grant guard and the revoke lookup.
	// MarkParentalConsentRevoked stamps RevokedAt/RevokedBy on the record.
	//
	// Like audit_events, these records carry NO users foreign key and are NOT
	// removed by DeleteUser: the proof of consent must survive deletion of the
	// child or the adult it references, to defend a later regulatory inquiry.
	CreateParentalConsent(ctx context.Context, r *ParentalConsentRecord) error
	GetActiveParentalConsentForChild(ctx context.Context, childUserID string) (*ParentalConsentRecord, error)
	// ListActiveParentalConsentsForChild returns EVERY non-revoked consent
	// record for a child, newest grant first. Only one can be active today
	// (a grant requires a gated child, and a gated child has no active
	// consent), but the last-guardian rule in RevokeParentalConsent has to
	// ask "does another guardian still consent?" about a record it has not
	// yet marked revoked — a question the single-record lookup above cannot
	// answer. Empty slice, not an error, when there are none.
	ListActiveParentalConsentsForChild(ctx context.Context, childUserID string) ([]*ParentalConsentRecord, error)
	MarkParentalConsentRevoked(ctx context.Context, consentID, revokedByUserID string, atMs int64) error

	// Guardian edges: the authorization
	// fact that guardian_user_id manages child_user_id. Unlike consent
	// records, edges are live authorization state — they carry users foreign
	// keys and are removed by DeleteUser of either side.
	//
	// UpsertGuardianEdge is idempotent on (guardian, child): re-adding an
	// existing edge is a no-op that preserves the original CreatedAtMs.
	// DeleteGuardianEdge removes the edge if present (absent is not an
	// error). GetGuardianEdge returns (nil, nil) when no edge exists.
	UpsertGuardianEdge(ctx context.Context, e *GuardianEdge) error
	DeleteGuardianEdge(ctx context.Context, guardianUserID, childUserID string) error
	GetGuardianEdge(ctx context.Context, guardianUserID, childUserID string) (*GuardianEdge, error)
	ListGuardiansOfChild(ctx context.Context, childUserID string) ([]*GuardianEdge, error)
	ListChildrenOfGuardian(ctx context.Context, guardianUserID string) ([]*GuardianEdge, error)

	// CreateManagedChildAccount atomically persists the three artifacts of
	// the parent-creates-child flow: the child user row, the (guardian ->
	// child) edge, and the parental-consent record. The implementation binds
	// edge.ChildUserID and consent.ChildUserID to the inserted user's id, so
	// callers leave them unset. ALL THREE commit or NONE do — a partial state
	// (an account without its edge, an edge without its consent record) must
	// never be observable. A username that already exists in the project
	// returns ErrAlreadyExists with nothing committed (see conformance).
	CreateManagedChildAccount(ctx context.Context, u *User, edge *GuardianEdge, consent *ParentalConsentRecord) error

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
	// DeleteOAuthIdentity removes the (provider, provider_user_id) link
	// owned by userID. It is scoped to the owning user so one user can
	// never unlink another user's identity. Implementations return
	// ErrNotFound when no matching link exists for that user.
	DeleteOAuthIdentity(ctx context.Context, userID, provider, providerUserID string) error

	// Audit events.
	//
	// CreateAuditEvent persists one audit event and returns its node id. A
	// blank Event.ID is server-minted; a non-empty one is honoured. The
	// audit trail is retained for accountability and is NOT removed by
	// DeleteUser.
	//
	// ListAuditEventsForUser returns the audit events where userID is EITHER
	// the actor OR the target, newest first (occurred-at descending, then id
	// descending), capped at limit rows. It backs the self-service data
	// export (GDPR Art 15): it is scoped to the one user and never returns
	// another user's events. Implementations MUST reject limit <= 0 — an
	// uncapped scan of a hot table is never acceptable.
	CreateAuditEvent(ctx context.Context, e *AuditEvent) (string, error)
	ListAuditEventsForUser(ctx context.Context, userID string, limit int) ([]*AuditEvent, error)

	// DeleteAuditEventsBefore removes every audit event whose occurred-at
	// instant is strictly older than cutoffMs, returning the number deleted.
	// It is the GDPR Art 5(1)(e) storage-limitation sweep for the audit trail:
	// the background sweeper calls it once per tick with a cutoff of
	// now - GATEWAY_AUDIT_RETENTION_DAYS so audit/security logs (which record
	// IP + user-agent) are not held forever. Unlike the DeleteExpired* sweeps
	// this returns a real deleted count — it is a direct delete on the audit
	// store, not the count-less tenant-shard-db OpDeleteWhere path — which the
	// sweeper surfaces for operability. Implementations that could face a large
	// backlog (postgres) delete in internally-capped batches so a single call
	// never takes a table-wide lock; the whole eligible set is drained per call.
	DeleteAuditEventsBefore(ctx context.Context, cutoffMs int64) (int, error)

	// Garbage-collection sweepers for ephemeral state. The
	// background sweeper started by app.New calls these every
	// GATEWAY_SWEEPER_INTERVAL_SECONDS; each call deletes up to
	// `limit` rows whose ExpiresAt is strictly less than `beforeMs`.
	// Every shipping backend (memory, postgres) implements the
	// real sweep; the ErrSweepNotImplemented sentinel remains so a new
	// backend can land its CRUD methods first and its sweep in a
	// follow-up PR without erroring the sweeper goroutine.
	// Implementations MUST reject limit <= 0 — an unbounded delete
	// batch could lock a hot table for an unbounded window.
	//
	// Return value is only error: tenant-shard-db v1.14.0's
	// OpDeleteWhere primitive intentionally does not return a deleted-
	// row count (see #540 "applied, no count for v1"), so identity
	// drops the count from the contract to avoid forcing one of the
	// three backends into a per-row tally that the others can't
	// match. The app-layer sweeper emits per-tick "sweep completed"
	// events instead of a row count.
	DeleteExpiredWebAuthnChallenges(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredEmailVerificationTokens(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredPasswordResetTokens(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredEmailChangeTokens(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredLoginChallenges(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredOAuthOneTimeCodes(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredNativeTokenRedemptions(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredEmailLoginCodes(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredMagicLinkTokens(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredPhoneVerificationCodes(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredQrLoginSessions(ctx context.Context, beforeMs int64, limit int) error
	DeleteExpiredInvitations(ctx context.Context, beforeMs int64, limit int) error
}

// ErrSweepNotImplemented is the soft-skip sentinel a Repository may
// return from a DeleteExpired* method when the backend cannot yet
// run the expired-row sweep. The sweeper goroutine in
// internal/app/sweeper.go logs this once per node type per process
// and continues. No backend in tree returns this today; it remains
// so a new backend can land its CRUD methods first and its sweep in
// a follow-up PR without erroring the sweeper goroutine.
var ErrSweepNotImplemented = errors.New("identity: sweep not implemented for this backend")

// ── Record types for persistence ───────────────────────────────────────

// SessionRecord represents a stored access-token-bound session, used
// by `GATEWAY_REVOCATION_MODE=session` deployments. The SID is the
// stable per-session identifier carried as the `sid` claim on access
// tokens; the verification middleware looks the row up on every
// authenticated request (via an in-process cache).
//
// In `mode=ttl` deployments (the default) this record type is not
// written or read — the row type costs zero on the hot path for
// deployers who never opt in.
type SessionRecord struct {
	NodeID      string
	SID         string
	UserID      string
	CreatedAtMs int64 // epoch ms
	RevokedAtMs int64 // epoch ms; 0 = active
}

// RefreshTokenRecord represents a stored refresh token.
type RefreshTokenRecord struct {
	NodeID     string
	TokenHash  string
	UserID     string
	DeviceInfo string
	DeviceName string
	IPAddress  string
	UserAgent  string
	ExpiresAt  int64 // epoch ms
	CreatedAt  int64
	LastUsedAt int64
	// SessionStartedAt anchors the session's absolute lifetime. Unlike
	// CreatedAt — which is re-stamped on every rotation — it is copied
	// UNCHANGED from the consumed token across refreshes, so the per-tenant
	// absolute session timeout is measured from the original login rather
	// than the latest refresh. It is set to now only at initial login. 0
	// means "no anchor recorded" (legacy rows), in which case the absolute
	// timeout is skipped until the next rotation re-anchors it.
	SessionStartedAt int64 // epoch ms
	ConsumedAtMs     int64 // epoch ms; 0 = unconsumed (still valid for refresh)
	// SID links this refresh token to the access-token Session minted alongside
	// it under GATEWAY_REVOCATION_MODE=session — it carries the same value as
	// the access token's `sid` claim. A path that invalidates the refresh token
	// (a session-timeout breach) uses it to revoke the still-valid access
	// session scoped to exactly this session, not the user's others. Empty in
	// mode=ttl and for legacy rows, where there is no session to revoke.
	SID string
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
	// BackupEligible / BackupState are the WebAuthn backup flags captured at
	// registration. They must be persisted and replayed at login: go-webauthn
	// rejects an assertion whose backup flags are inconsistent with the stored
	// credential, and every synced platform passkey (iCloud Keychain, Google
	// Password Manager) sets BackupEligible, so dropping them breaks login.
	BackupEligible bool
	BackupState    bool
	CreatedAt      int64
	LastUsedAt     int64
}

// PasskeyChallengeRecord represents a stored passkey challenge.
type PasskeyChallengeRecord struct {
	NodeID        string
	Challenge     string // base64url
	UserID        string
	ChallengeType string // "registration" or "authentication"
	// Email binds the account a passkey-first signup challenge will create the
	// user under (see BeginPasskeySignup); empty for add-a-passkey
	// registration and for authentication challenges.
	Email     string
	ExpiresAt int64
	CreatedAt int64
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
	// PollSecretHash is sha256(poll_secret) where poll_secret is returned
	// only to the initiating device by InitiateQrLogin. PollQrLogin must
	// present the matching plaintext or the session looks "expired".
	PollSecretHash string
	ExpiresAt      int64
	CreatedAt      int64
	UpdatedAt      int64
}

// OAuthOneTimeCodeRecord is the single-use handover artifact for the
// hosted OAuth flow. The hosted callback stores the SHA-256 hash of an
// opaque code keyed to the authenticated user; RedeemOAuthCode consumes
// it (consumed_at CAS from 0) and mints a fresh token pair. Only the
// user id is persisted — no token material is stored at rest.
type OAuthOneTimeCodeRecord struct {
	NodeID     string
	CodeHash   string
	UserID     string
	ExpiresAt  int64 // epoch ms
	CreatedAt  int64 // epoch ms
	ConsumedAt int64 // epoch ms; 0 = unconsumed
}

// NativeTokenRedemptionRecord is the replay-cache row that makes a native ID
// token (Google idToken / Apple identityToken) single-use. ReplayKey uniquely
// identifies one issued token — the token's `jti` when present, else a stable
// digest of (provider|iss|sub|iat|aud|nonce); see oauth.NativeVerification.
// ExpiresAt is the token's own `exp` (bounded to a sane max) so the row is
// retained only as long as the token could still be presented. No token
// material or user id is stored at rest — the key is opaque.
type NativeTokenRedemptionRecord struct {
	NodeID    string
	ReplayKey string
	ExpiresAt int64 // epoch ms
	CreatedAt int64 // epoch ms
}

// EmailLoginCodeRecord is the OTP arm of passwordless email login. The
// record is keyed by Email (at most one live code per address); a new
// request overwrites the previous one. CodeHash is sha256 of the 6-digit
// code. AttemptCount tracks failed verifies; once it reaches MaxAttempts
// the code is invalidated (brute-force cap). The record carries no user
// id — the account may not exist until VerifyEmailLoginCode resolves or
// creates it.
type EmailLoginCodeRecord struct {
	NodeID       string
	Email        string
	CodeHash     string
	ExpiresAt    int64 // epoch ms
	CreatedAt    int64 // epoch ms
	ConsumedAt   int64 // epoch ms; 0 = unconsumed
	AttemptCount int64
	MaxAttempts  int64
}

// MagicLinkTokenRecord is the magic-link arm of passwordless email
// login. TokenHash is sha256 of a high-entropy opaque token; the row is
// bound to the requested Email and the allowlist-validated ReturnTo.
// Single-use is enforced by the ConsumedAt compare-and-set.
type MagicLinkTokenRecord struct {
	NodeID     string
	TokenHash  string
	Email      string
	ReturnTo   string
	ExpiresAt  int64 // epoch ms
	CreatedAt  int64 // epoch ms
	ConsumedAt int64 // epoch ms; 0 = unconsumed
}

// PhoneVerificationCodeRecord is the SMS-OTP arm of phone-ownership
// verification. The record is keyed by UserID (at most one live code per
// user); a new request overwrites the previous one. CodeHash is sha256
// of the 6-digit code. AttemptCount tracks failed verifies; once it
// reaches MaxAttempts the code is invalidated (brute-force cap). Unlike
// EmailLoginCodeRecord this always carries a UserID — the caller is an
// already-authenticated user proving ownership of PhoneNumber.
type PhoneVerificationCodeRecord struct {
	NodeID       string
	UserID       string
	PhoneNumber  string
	CodeHash     string
	ExpiresAt    int64 // epoch ms
	CreatedAt    int64 // epoch ms
	ConsumedAt   int64 // epoch ms; 0 = unconsumed
	AttemptCount int64
	MaxAttempts  int64
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

// Identity-verification status string constants. Mirrored as proto
// enum values in IdentityVerificationStatus.
const (
	IDVStatusPending  = "pending"
	IDVStatusInReview = "in_review"
	IDVStatusApproved = "approved"
	IDVStatusRejected = "rejected"
	IDVStatusExpired  = "expired"
)

// IdentityVerificationRecord represents a single verification session
// (document + selfie) tracked by the service. The provider field names
// the backing implementation (e.g. "azure", "stub"); ProviderSessionID
// is the provider's own identifier for the check.
type IdentityVerificationRecord struct {
	NodeID            string
	VerificationID    string // public identifier returned to clients
	UserID            string
	ProjectID         string // storage shard (ADR-0002): the per-request project
	Provider          string
	ProviderSessionID string
	Status            string // one of IDVStatus* constants
	CreatedAt         int64  // epoch ms
	UpdatedAt         int64  // epoch ms
	CompletedAt       int64  // epoch ms; 0 if not yet completed
	RejectionReason   string // empty unless Status == IDVStatusRejected
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
// the application layer — the graph DB does not expose composite
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
	ErrUnauthenticated  = errors.New("unauthenticated")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrNotFound         = errors.New("not found")
	// ErrAccessNotAllowed is returned when a project's access mode denies the
	// authenticating email: an allowlist mode whose list omits the email, a
	// closed mode, or an unset/unrecognized mode (the default-DENY posture). It
	// is a membership denial, distinct from ErrPermissionDenied (a login-method
	// policy denial) so the two can be told apart; both map to
	// CodePermissionDenied. The message is deliberately generic — it discloses
	// neither whether an account exists nor the allowlist's contents.
	ErrAccessNotAllowed = errors.New("access not allowed for this project")
	// ErrSignupByInvitationOnly is returned when a project's access mode is
	// "invite": self-signup is blocked, but login for an existing user and
	// admin-issued invitation acceptance still work. It is distinct from
	// ErrAccessNotAllowed so a client can route the user to request an invite
	// rather than show a generic denial. Both map to CodePermissionDenied, and
	// the denial is uniform across every email (invite-only is a project
	// property, not a per-account signal), so it discloses no account existence.
	ErrSignupByInvitationOnly = errors.New("this project is invitation-only; self-signup is disabled")
	// ErrProductAgeRestricted is returned when authentication succeeded but the
	// account's derived age band is below the minimum the requested product
	// configures (ProjectProductsConfig). It maps to CodePermissionDenied, and
	// its message leads with the stable `product_age_restricted` token that
	// clients match on to show kind, child-appropriate copy instead of a raw
	// error. The token is part of the wire contract — do not reword it.
	ErrProductAgeRestricted = errors.New("product_age_restricted: this account is not old enough for this product")
	// ErrDOBRequired is returned when GATEWAY_AGEGATE_REQUIRE_DOB is on and
	// authentication succeeded for an account with no date of birth on file:
	// no session is minted until the client completes the DOB step through
	// SubmitDateOfBirth. It maps to CodeFailedPrecondition, and its message
	// leads with the stable `dob_required` token clients match on to show the
	// completion UI. The token is part of the wire contract — do not reword
	// it. The returned error is a *DOBRequiredError carrying the completion
	// ticket the client submits with the date of birth.
	ErrDOBRequired = errors.New("dob_required: date of birth required before sign-in can complete")
	// ErrDOBAlreadySet is returned by SubmitDateOfBirth when the account
	// already has a date of birth: the completion step sets it exactly once
	// and is not a DOB-change channel.
	ErrDOBAlreadySet = errors.New("date of birth is already set for this account")
	// ErrProjectSecretsKeyMissing is returned when an admin write carries a
	// plaintext provider secret to encrypt but GATEWAY_PROJECT_SECRETS_KEY is
	// not configured, so the server cannot encrypt it for storage. It is a
	// server-configuration precondition (mapped to FailedPrecondition), not a
	// bad client argument. In a postgres control plane the key is required, so
	// this only fires on a misconfigured or non-control-plane build.
	ErrProjectSecretsKeyMissing = errors.New("GATEWAY_PROJECT_SECRETS_KEY is not configured; cannot store per-project OAuth secrets")
	ErrAlreadyExists            = errors.New("already exists")
	ErrAccountLocked            = errors.New("account locked")
	ErrNoPasswordSet            = errors.New("no password set for this account")
	ErrAccountNotActive         = errors.New("account is not active")
	// ErrAccountDeletionNotAllowed is returned by DeleteMyAccount when the
	// caller's account is in a state from which self-service deletion makes no
	// sense (e.g. already deactivated or suspended by an admin). Mapped to
	// CodeFailedPrecondition by the Connect layer.
	ErrAccountDeletionNotAllowed = errors.New("account cannot be self-deleted in its current state")
	ErrInvitationPending         = errors.New("account has not completed invitation")
	ErrIDVRequired               = errors.New("identity verification required")
	// ErrEmailVerificationRequired is returned when GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL
	// is enabled and the account's email is not yet verified. Like ErrIDVRequired
	// it is a "do something else first" precondition (verify your email, then
	// retry), mapped to CodeFailedPrecondition by the Connect layer.
	ErrEmailVerificationRequired = errors.New("email verification required")
	// ErrMinorDataMinimized is returned when GATEWAY_MINOR_DATA_MINIMIZATION is
	// enabled and a CHILD-band account attempts an RPC that would collect
	// non-essential PII the server refuses to gather from a minor — phone
	// verification or identity verification. Like ErrIDVRequired it is a
	// "this is not permitted for this account" precondition, mapped to
	// CodeFailedPrecondition by the Connect layer.
	ErrMinorDataMinimized = errors.New("data collection not permitted for a minor account")
	// ErrParentalConsentRequired is returned when an admin status mutator
	// (e.g. ReactivateUser) attempts to move an account out of
	// pending_parental_consent. The only valid transition out of that state
	// is the dedicated parental-consent flow; ordinary status patches must
	// not silently bypass the COPPA consent gate.
	ErrParentalConsentRequired = errors.New("account is pending parental consent and cannot be activated by this operation")
	ErrWeakPassword            = errors.New("password does not meet strength requirements")
	ErrTotpRequired            = errors.New("totp required")
	// ErrSSORequired is returned when a claimed tenant's LoginPolicy mandates
	// single sign-on and the caller attempted a non-SSO method. Like
	// ErrTotpRequired it is a "do something else first" signal rather than a
	// hard failure, so the Connect handler maps it to CodeFailedPrecondition,
	// steering the client to the tenant's SSO connection.
	ErrSSORequired  = errors.New("sso required for this domain")
	ErrTokenExpired = errors.New("token expired")
	// ErrSessionExpired is returned when a still-valid refresh token is
	// rejected because the owning tenant's LoginPolicy idle or absolute
	// session timeout has elapsed.
	ErrSessionExpired    = errors.New("session expired")
	ErrInvalidTotpCode   = errors.New("invalid totp code")
	ErrQrLoginExpired    = errors.New("qr login session expired")
	ErrQrLoginNotPending = errors.New("qr login session is not pending")
	// ErrOAuthCodeInvalid is returned when a hosted-flow one-time code is
	// missing, expired, or already consumed. The Connect handler maps it
	// to CodeUnauthenticated so replays and expiries look identical to a
	// brute-force attacker.
	ErrOAuthCodeInvalid = errors.New("oauth one-time code is invalid or already used")
	// ErrEmailLoginCodeInvalid is returned when a passwordless OTP is
	// missing, expired, already consumed, the wrong code, or has exhausted
	// its attempt budget. The Connect handler maps it to
	// CodeUnauthenticated so all failure modes look identical to a
	// brute-force attacker.
	ErrEmailLoginCodeInvalid = errors.New("email login code is invalid or expired")
	// ErrMagicLinkInvalid is returned when a passwordless magic-link token
	// is missing, expired, or already consumed. Maps to CodeUnauthenticated.
	ErrMagicLinkInvalid = errors.New("magic link is invalid or already used")
	// ErrPhoneCodeInvalid is returned when an SMS-OTP phone-verification
	// code is missing, expired, already consumed, the wrong code, or has
	// exhausted its attempt budget. The Connect handler maps it to
	// CodeUnauthenticated so all failure modes look identical to a
	// brute-force attacker.
	ErrPhoneCodeInvalid = errors.New("phone verification code is invalid or expired")
	// ErrSMSDisabled is returned by the phone-verification RPCs when
	// GATEWAY_SMS_ENABLED is false. Maps to CodeUnavailable.
	ErrSMSDisabled = errors.New("sms phone verification is not configured")
	// ErrPhoneAlreadyVerified is returned by RequestPhoneVerification when
	// the caller has already verified the same number. Maps to
	// CodeAlreadyExists.
	ErrPhoneAlreadyVerified = errors.New("phone number is already verified")
	ErrInvitationUsed       = errors.New("invitation has already been accepted")
	ErrInvitationExpired    = errors.New("invitation has expired")
	ErrLocalAuthDisabled    = errors.New("local auth disabled")
	ErrOAuthDisabled        = errors.New("oauth login is not configured")
	// ErrNativeOAuthDisabled is returned by NativeOAuthLogin when
	// GATEWAY_NATIVE_OAUTH_ENABLED is false or no native verifier is
	// configured. It maps to FailedPrecondition (the feature is off), distinct
	// from ErrUnauthenticated (a token that failed verification).
	ErrNativeOAuthDisabled = errors.New("native oauth login is not enabled")
	// ErrNativeTokenReplayed is returned by RecordNativeTokenRedemption when a
	// native ID token's replay key has already been recorded — the bearer
	// token is being presented a second time. NativeOAuthLogin maps it to
	// CodeUnauthenticated so a replay looks identical to any other rejected
	// token.
	ErrNativeTokenReplayed = errors.New("native id token has already been redeemed")
	ErrSignupDisabled      = errors.New("signup is disabled for this deployment")
	// ErrPasskeySignupDisabled is returned by BeginPasskeySignup /
	// CompletePasskeySignup when GATEWAY_PASSKEY_SIGNUP_ENABLED is false. It
	// is distinct from ErrSignupDisabled (password signup) so the two flows
	// can be toggled independently; both map to FailedPrecondition.
	ErrPasskeySignupDisabled = errors.New("passkey signup is disabled for this deployment")
	// ErrUnimplemented signals that the requested RPC is intentionally
	// disabled for the active repository driver (e.g. the redesign
	// Domain/Tenant RPCs are postgres-only; memory returns this).
	// The Connect handler layer maps it to CodeUnimplemented.
	ErrUnimplemented = errors.New("operation unimplemented for this repository driver")
	// ErrLastOwner is returned by RemoveTenantMember when removing the target
	// would strand the tenant with no active owner. The caller is permitted
	// to remove members (so PermissionDenied is wrong); this is a state
	// precondition, mapped to CodeFailedPrecondition.
	ErrLastOwner = errors.New("cannot remove the last owner of a tenant")
	// ErrPlatformAdminExists is returned by CreateFirstPlatformAdmin once any
	// platform admin already exists: the zero-config bootstrap is a one-time
	// path that permanently closes after the first admin is created, so a
	// later call cannot escalate to operator. It is a state precondition (not
	// an authorization failure), mapped to CodeFailedPrecondition.
	ErrPlatformAdminExists = errors.New("a platform admin already exists; bootstrap is closed")
	// ErrFirstAdminBootstrapDisabled is returned by CreateFirstPlatformAdmin
	// when GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP is true: an operator who
	// bootstraps the first platform admin out-of-band can close the RPC
	// entirely, so it is rejected regardless of whether any admin exists yet.
	// It is a deployment-posture precondition (the feature is turned off), not
	// an authorization failure, mapped to CodeFailedPrecondition.
	ErrFirstAdminBootstrapDisabled = errors.New("first-admin bootstrap is disabled for this deployment")
	// ErrAuthDomainNotVerified is returned by SetPrimaryAuthDomain when the
	// target custom auth-domain has not proven ownership (verified_at_ms == 0).
	// Only a DNS-verified domain may be promoted to a project's primary serving
	// host, so this is a state precondition mapped to CodeFailedPrecondition.
	ErrAuthDomainNotVerified = errors.New("auth domain is not verified")
	// ErrLastCredential is returned by UnlinkIdentity when removing the
	// requested provider link would leave the user with no remaining way to
	// sign in (no password, no passkey, and no other linked provider). The
	// caller is allowed to unlink their own identities, so this is a state
	// precondition (not an authorization failure), mapped to
	// CodeFailedPrecondition.
	ErrLastCredential = errors.New("cannot remove the last sign-in credential")
	// ErrProjectConfigConflict is returned by the control-plane project store
	// when an optimistic-concurrency config_json write loses its version
	// compare-and-swap — a concurrent writer advanced the row's config_version
	// between the read and the write. The service retries the read-modify-write a
	// bounded number of times, so a caller only observes it when retries are
	// exhausted under sustained contention. The Connect layer maps it to
	// CodeAborted — gRPC's documented, retryable code for a concurrency/sequencer
	// conflict.
	ErrProjectConfigConflict = errors.New("project config write conflicted with a concurrent update")
)

// ── AuthService ────────────────────────────────────────────────────────

// AuthService implements authentication and token management business logic.
type AuthService struct {
	defaultRepo        Repository
	defaultTenantID    string
	signer             jwt.Signer
	passkeys           *passkeys.WebAuthnService
	audit              *audit.Logger
	cfg                *config.Config
	totpKey            []byte
	totpRecoveryPepper []byte
	mailer             email.Transport
	smsSender          sms.Sender
	logger             *zap.Logger
	// oauthResolver resolves the OAuth Exchanger for a request's project and
	// provider (per-project providers from config_json, env providers for the
	// default project). Always non-nil once the constructor runs; OAuthLogin
	// returns ErrOAuthDisabled when no provider is available for the project.
	oauthResolver *OAuthResolver
	// nativeVerifier verifies native mobile-SDK ID tokens (Google idToken /
	// Apple identityToken) for NativeOAuthLogin. nil disables the RPC
	// (FailedPrecondition) — the constructor leaves it nil; app.New sets it via
	// WithNativeOAuth when GATEWAY_NATIVE_OAUTH_ENABLED and at least one
	// provider's audiences are configured. Held behind the
	// NativeIDTokenVerifier seam (satisfied by *oauth.NativeVerifier) so the
	// login flow's verification-result branches are unit-testable.
	nativeVerifier NativeIDTokenVerifier
	// nativeProjects validates that a native login's resolved product→project
	// id names a real, active control-plane project. nil on drivers without a
	// control plane (memory), where NativeOAuthLogin accepts only the product
	// that resolves to cfg.DefaultProjectID. Set alongside nativeVerifier.
	nativeProjects NativeOAuthProjectStore
	// nativeProductProjects is the parsed GATEWAY_NATIVE_OAUTH_PRODUCT_PROJECTS
	// map (lower-cased product → verbatim project id), precomputed once at
	// wiring so a native login does not re-split the CSV and allocate a map per
	// request (mirrors the verifier's precomputed audience sets). Set in
	// WithNativeOAuth.
	nativeProductProjects map[string]string
	// assuranceResolver resolves per-project attestation verifiers and
	// webAssurance is the deployment-global captcha verifier; both are set
	// via WithAssurance when GATEWAY_ASSURANCE_ENABLED. nil resolver/web
	// disables the corresponding assurance surface (ErrAssuranceDisabled).
	assuranceResolver *AssuranceResolver
	webAssurance      assurance.Verifier
	emailThrottle     *emailSendThrottle
	signupThrottle    *emailSendThrottle
	phoneThrottle     *emailSendThrottle
	// returnAllow validates the magic-link return_to against
	// GATEWAY_OAUTH_ALLOWED_RETURN_URLS — the same allowlist the hosted
	// OAuth flow uses. Parsed once at construction.
	returnAllow ReturnAllowlist
	nowFunc     func() time.Time // overridable for testing

	// defaultProjectAccess is the env-configured default project's access policy
	// (GATEWAY_DEFAULT_PROJECT_ACCESS_MODE + allowlists), parsed and canonicalized
	// ONCE at construction. It backs the native-login default-project fallback
	// (which has no config_json to carry a mode). An invalid spec fails closed to
	// AccessModeClosed at construction (with a WARN); app.New validates it at boot,
	// so a served deployment surfaces the error there.
	defaultProjectAccess ProjectAccessConfig

	// runEmailSend runs a request-phase credential-email send. It defaults to
	// SYNCHRONOUS (run inline); app.New swaps in an asynchronous dispatcher via
	// WithAsyncEmailDispatch so the RPC response time cannot depend on — and thus
	// leak — the gated send/no-send decision (a timing oracle that, in invite
	// mode, would reveal account existence). Kept injectable so tests observe
	// sends deterministically without polling.
	runEmailSend func(func())

	// autoFormer, when set (postgres driver only), auto-forms a tenant from
	// a new user's company email domain at signup. nil disables the
	// behaviour — the constructor leaves it nil; app.New sets it via
	// WithTenantAutoFormer. It is an optional, set-once dependency, kept off
	// the already-wide constructor.
	autoFormer TenantAutoFormStore

	// governance, when set (postgres driver only), is the read-side bundle
	// the login path consults to enforce a claimed tenant's LoginPolicy. nil
	// disables enforcement — the constructor leaves it nil; app.New sets it
	// via WithLoginGovernance. Like autoFormer it is an optional, set-once
	// dependency kept off the already-wide constructor. Enforcement fails
	// safe: any nil store, miss, or lookup error imposes no restriction.
	governance *LoginGovernance

	// publisher emits user-lifecycle events (create/update/deactivate) to
	// downstream subscribers. nil disables emission (treated as the no-op
	// events.Discard) — the constructor leaves it nil; app.New sets it via
	// WithEventPublisher (the outbox-backed publisher when
	// GATEWAY_WEBHOOKS_ENABLED, else left nil). Emission is best-effort and
	// never fails the originating RPC.
	publisher events.Publisher

	// ageGate determines a user's age band from their date of birth. It is
	// always non-nil: the constructor wires the no-op determiner when
	// age-gating is disabled (everyone classifies as adult) and the
	// threshold determiner when GATEWAY_AGEGATE_ENABLED is set.
	ageGate agegate.Determiner

	// minorData decides whether a child account's optional PII must be
	// suppressed (COPPA data-minimization). Built from the age gate and
	// GATEWAY_MINOR_DATA_MINIMIZATION; a no-op when either is off.
	minorData MinorDataMinimizer

	// passkeyRPCache memoises per-project WebAuthn relying-party instances
	// keyed by their (rp_id, rp_name, origin) tuple. A project whose
	// config_json sets a passkey block needs a WebAuthn instance bound to
	// that RP-ID so a passkey registered under one product's domain validates
	// under that product's RP-ID; building one per request is wasteful, so we
	// cache them. Projects with no override share the global s.passkeys.
	passkeyRPCache   map[string]*passkeys.WebAuthnService
	passkeyRPCacheMu sync.RWMutex

	// purger runs the hard-delete erasure cascade for one account. It is the
	// AdminService (the owner of the cascade the admin DeleteUser RPC and the
	// account-deletion sweeper already share), injected rather than
	// reimplemented so guardian-initiated erasure of a child account cannot
	// drift from it. nil disables DeleteManagedChildAccount
	// (ErrServiceUnavailable) — the same shape every other optional
	// dependency takes.
	purger AccountPurger
}

// AccountPurger runs the hard-delete erasure cascade for a single, already
// authorized account: session and refresh-token revocation, graph-edge
// cleanup, the Repository delete, and the audit + lifecycle events that go
// with it. *AdminService implements it; the caller owns authorization.
type AccountPurger interface {
	PurgeAccount(ctx context.Context, actorUserID string, u *User) error
}

// WithAccountPurger wires the account-erasure cascade (the AdminService) and
// returns the service for chaining. app.New calls it once at construction,
// after the AdminService exists.
func (s *AuthService) WithAccountPurger(p AccountPurger) *AuthService {
	s.purger = p
	return s
}

// WithEventPublisher wires the optional user-lifecycle event publisher and
// returns the service for chaining. app.New calls it once at construction
// (with the outbox-backed publisher when outbound eventing is enabled, or
// nil to disable emission).
func (s *AuthService) WithEventPublisher(p events.Publisher) *AuthService {
	s.publisher = p
	return s
}

// WithTenantAutoFormer wires the optional tenant auto-formation store and
// returns the service for chaining. app.New calls it once at construction
// (with the postgres store, or nil for drivers without a control plane).
func (s *AuthService) WithTenantAutoFormer(af TenantAutoFormStore) *AuthService {
	s.autoFormer = af
	return s
}

// WithLoginGovernance wires the optional login-governance bundle (the
// Domain/Tenant/LoginPolicy read stores) the login path consults to enforce
// a claimed tenant's LoginPolicy, and returns the service for chaining.
// app.New calls it once at construction (with the postgres stores, or nil
// for drivers without a governance plane). A nil bundle disables enforcement.
func (s *AuthService) WithLoginGovernance(g *LoginGovernance) *AuthService {
	s.governance = g
	return s
}

// WithProjectOAuthSecrets wires the per-project OAuth secret-decryption key and
// the Exchanger observability wrapper into the OAuth resolver, and returns the
// service for chaining. app.New calls it once at construction with the decoded
// GATEWAY_PROJECT_SECRETS_KEY and observability.WrapOAuthExchanger. Without it,
// a project that stores encrypted provider secrets cannot be built (only the
// default project's env providers work).
func (s *AuthService) WithProjectOAuthSecrets(secretsKey []byte, wrap func(provider string, e oauth.Exchanger) oauth.Exchanger) *AuthService {
	s.oauthResolver.withSecrets(secretsKey, wrap)
	return s
}

// WithNativeOAuth wires the native mobile sign-in dependencies (the ID-token
// verifier and the optional control-plane project lookup) and returns the
// service for chaining. app.New calls it once at construction: with a non-nil
// verifier when native login is enabled and audiences are configured, and with
// the postgres project store (nil on drivers without a control plane). A nil
// verifier leaves NativeOAuthLogin disabled.
func (s *AuthService) WithNativeOAuth(v NativeIDTokenVerifier, projects NativeOAuthProjectStore) *AuthService {
	s.nativeVerifier = v
	s.nativeProjects = projects
	s.nativeProductProjects = s.cfg.NativeOAuthProductProjectMap()
	return s
}

// WithAssurance wires the client-assurance layer: the per-project
// attestation resolver and the deployment-global web verifier. Called by
// app wiring when GATEWAY_ASSURANCE_ENABLED; without it every assurance
// RPC returns ErrAssuranceDisabled.
func (s *AuthService) WithAssurance(resolver *AssuranceResolver, web assurance.Verifier) *AuthService {
	s.assuranceResolver = resolver
	s.webAssurance = web
	return s
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
	signer jwt.Signer,
	passkeysSvc *passkeys.WebAuthnService,
	auditLogger *audit.Logger,
	totpKey []byte,
	totpRecoveryPepper []byte,
	mailer email.Transport,
	smsSender sms.Sender,
	logger *zap.Logger,
) *AuthService {
	return NewAuthServiceWithOAuth(repo, cfg, signer, passkeysSvc, auditLogger, totpKey, totpRecoveryPepper, mailer, smsSender, logger, nil)
}

// NewAuthServiceWithOAuth is the extended constructor that injects an
// oauth.Registry. Pass nil to disable OAuth login.
func NewAuthServiceWithOAuth(
	repo Repository,
	cfg *config.Config,
	signer jwt.Signer,
	passkeysSvc *passkeys.WebAuthnService,
	auditLogger *audit.Logger,
	totpKey []byte,
	totpRecoveryPepper []byte,
	mailer email.Transport,
	smsSender sms.Sender,
	logger *zap.Logger,
	oauthRegistry *oauth.Registry,
) *AuthService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if mailer == nil {
		mailer = email.NewLogOnly(logger)
	}
	if smsSender == nil {
		smsSender = sms.NewLogOnly(logger)
	}
	if !cfg.PasswordSignupEnabled {
		logger.Warn("password_signup_disabled")
	}
	if !cfg.PasswordResetEnabled {
		logger.Warn("password_reset_disabled")
	}
	if len(totpRecoveryPepper) < totp.MinRecoveryPepperBytes {
		// Refuse to construct an AuthService with a too-short pepper:
		// any recovery-code path would silently fail, which is worse
		// than a panic at boot.
		panic(fmt.Sprintf(
			"totp recovery pepper too short: got %d bytes, need >= %d",
			len(totpRecoveryPepper), totp.MinRecoveryPepperBytes,
		))
	}
	ageGate := BuildAgeGate(cfg, logger)
	return &AuthService{
		defaultRepo:          repo,
		defaultTenantID:      cfg.DefaultTenantID,
		defaultProjectAccess: buildDefaultProjectAccess(cfg, logger),
		ageGate:              ageGate,
		minorData:            NewMinorDataMinimizer(cfg.MinorDataMinimization, ageGate, time.Now),
		signer:               signer,
		passkeys:             passkeysSvc,
		audit:                auditLogger,
		cfg:                  cfg,
		totpKey:              totpKey,
		totpRecoveryPepper:   totpRecoveryPepper,
		mailer:               mailer,
		smsSender:            smsSender,
		logger:               logger,
		oauthResolver:        newOAuthResolver(cfg.DefaultProjectID, oauthRegistry, cfg.OAuthHubSharing, logger),
		emailThrottle:        newEmailSendThrottle(int64(cfg.EmailSendCooldownSeconds)*1000, 0),
		signupThrottle:       newEmailSendThrottle(int64(cfg.SignupEmailCooldownSeconds)*1000, 0),
		phoneThrottle:        newEmailSendThrottle(int64(cfg.PhoneCodeCooldownSeconds)*1000, 0),
		returnAllow:          ParseReturnAllowlist(cfg.OAuthAllowedReturnURLs),
		nowFunc:              time.Now,
		// Default to synchronous sends; app.New opts into async via
		// WithAsyncEmailDispatch. A synchronous default keeps every
		// directly-constructed service (tests, embedders) deterministic.
		runEmailSend: func(fn func()) { fn() },
	}
}

// WithAsyncEmailDispatch switches request-phase credential-email sends to run
// on a detached background goroutine, so the RPC response time is independent
// of the gated send/no-send decision (closing the timing oracle). app.New
// enables this for the served deployment; it is a set-once option that returns
// the receiver for chaining. One goroutine per permitted send is acceptable
// because the per-IP rate limiter and captcha upstream already bound this path.
func (s *AuthService) WithAsyncEmailDispatch() *AuthService {
	s.runEmailSend = func(fn func()) { go fn() }
	return s
}

// asyncEmailSendTimeout caps a detached background send so a stuck SMTP dial
// cannot leak a goroutine indefinitely.
const asyncEmailSendTimeout = 30 * time.Second

// dispatchEmailSend runs send via runEmailSend (sync or async per construction).
// It hands send a DETACHED context — context.WithoutCancel(ctx) with a bounded
// timeout — NOT the request ctx, which is cancelled when the RPC returns and
// would abort an async send mid-flight; the detached copy still carries
// request-scoped values (the resolved project scope, etc.). Panics in the
// background goroutine are recovered and logged, since the send is now
// fire-and-forget.
func (s *AuthService) dispatchEmailSend(ctx context.Context, op string, send func(context.Context)) {
	detached := context.WithoutCancel(ctx)
	s.runEmailSend(func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("email_send_panic", zap.String("op", op), zap.Any("panic", r))
			}
		}()
		sendCtx, cancel := context.WithTimeout(detached, asyncEmailSendTimeout)
		defer cancel()
		send(sendCtx)
	})
}

// buildDefaultProjectAccess parses the env-configured default project's access
// policy (GATEWAY_DEFAULT_PROJECT_ACCESS_MODE + allowlists) ONCE, so the value
// is canonicalized a single time rather than re-split and re-punycoded per use.
// It fails CLOSED: an invalid spec yields a deny-all closed policy rather than
// an open one, and logs a WARN so the misconfiguration is visible.
func buildDefaultProjectAccess(cfg *config.Config, logger *zap.Logger) ProjectAccessConfig {
	access, err := NewProjectAccessConfig(
		cfg.DefaultProjectAccessMode,
		cfg.DefaultProjectAllowedEmailList(),
		cfg.DefaultProjectAllowedDomainList(),
	)
	if err != nil {
		logger.Warn("default_project_access_invalid_failing_closed", zap.Error(err))
		return ProjectAccessConfig{Mode: AccessModeClosed}
	}
	return access
}

// BuildAgeGate selects the age-determination provider from config. When
// age-gating is off the no-op determiner is returned (everyone is an adult).
// When on, the threshold determiner is built from the configured boundaries;
// config.Validate already guarantees they are well-formed, but if a caller
// bypassed validation we fail safe to the no-op rather than panic.
func BuildAgeGate(cfg *config.Config, logger *zap.Logger) agegate.Determiner {
	if !cfg.AgeGateEnabled {
		return agegate.NewNoop()
	}
	d, err := agegate.NewThreshold(cfg.AgeGateChildMaxAge, cfg.AgeGateAdultAge)
	if err != nil {
		logger.Error("agegate_config_invalid_falling_back_to_noop", zap.Error(err))
		return agegate.NewNoop()
	}
	return d
}

// stampAgeBand derives IsMinor / AgeBand for a user from their stored date of
// birth and the age-gate determiner their market resolves to (see
// determinerForUser), mutating the user in place. It is a no-op (leaves the
// zero-values) when age-gating is disabled or no DOB is on file.
func (s *AuthService) stampAgeBand(ctx context.Context, u *User) {
	if u == nil {
		return
	}
	u.IsMinor = false
	u.AgeBand = ""
	gate := s.determinerForUser(ctx, u)
	if !gate.Enabled() {
		return
	}
	dec := gate.Determine(u.DateOfBirthMs, s.nowFunc())
	u.IsMinor = dec.IsMinor
	u.AgeBand = string(dec.Band)
}

// ── Storage tenant + project scoping ────────────────────────────────────

// tenantID returns the internal storage tenant key (DefaultTenantID).
func (s *AuthService) tenantID(context.Context) string {
	return s.defaultTenantID
}

// projectID returns the control-plane project the request resolved to (set
// by the project-resolution middleware), falling back to the configured
// default project. Empty only when no default project is configured (the
// memory deployments with no control plane), in which case the token
// simply carries no project claim.
func (s *AuthService) projectID(ctx context.Context) string {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.ProjectID != "" {
		return scope.ProjectID
	}
	return s.cfg.DefaultProjectID
}

// maybeAutoFormTenant auto-forms a company tenant from a newly-created
// user's email domain, when auto-formation is wired (postgres driver). It
// is a no-op for a personal/public email domain (gmail, outlook, …), since
// those never imply a company. Auto-formation is best-effort: a failure is
// logged but never fails the signup — the user's account already exists.
func (s *AuthService) maybeAutoFormTenant(ctx context.Context, user *User) {
	if s.autoFormer == nil || user == nil {
		return
	}
	projectID := s.projectID(ctx)
	if projectID == "" {
		return
	}
	// Split on the last '@' (via emailDomain) so the auto-formed tenant keys on
	// the same domain canonicalizeEmail produced — a quoted local part with '@'
	// must not yield a bogus domain and spawn a spurious tenant.
	domain := emailDomain(user.Email)
	if domain == "" || s.cfg.IsPublicEmailDomain(domain) {
		return
	}
	if _, err := s.autoFormer.EnsureTenantForDomain(ctx, projectID, domain, user.ID); err != nil {
		s.logger.Warn("tenant_autoform_failed",
			zap.String("project_id", projectID),
			zap.String("user_id", user.ID),
			zap.Error(err))
	}
}

// repo returns the Repository bound to the request's project (ADR-0002):
// the per-request ProjectScope when the project-resolution middleware
// injected one, else the boot-default project. Every data-plane read/write
// is filtered by the resolved project's id at the repository boundary.
func (s *AuthService) repo(ctx context.Context) Repository {
	return scopedRepository(ctx, s.defaultRepo, s.cfg.DefaultProjectID)
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

// issueTokens creates a JWT access token and a refresh token stored
// in the repo. When the configured revocation mode is `session`, the
// access token also carries a `sid` claim referencing a freshly
// minted Session row; the verification middleware looks the row up on
// every authenticated request.
//
// This is the initial-login entry point: it anchors the new session's
// absolute lifetime at now. The refresh path calls issueTokensWithSessionStart
// directly so the anchor propagates unchanged across rotations.
func (s *AuthService) issueTokens(ctx context.Context, user *User, ipAddr, userAgent string) (string, string, error) {
	// issueTokens is the single chokepoint every INTERACTIVE login funnels
	// through (the refresh path calls issueTokensWithSessionStart directly), so
	// it is the one place to auto-cancel a pending self-service deletion: an
	// owner who signs back in during the grace window has reclaimed the account.
	s.cancelPendingDeletionOnLogin(ctx, user)
	return s.issueTokensWithSessionStart(ctx, user, ipAddr, userAgent, 0)
}

// issueTokensWithSessionStart mints a token pair, anchoring the session's
// absolute lifetime at sessionStartedAtMs. A value <= 0 anchors a brand-new
// session at now (the initial-login case); the refresh path passes the consumed
// token's SessionStartedAt so the per-tenant absolute timeout is measured from
// the original login rather than re-set on every rotation.
func (s *AuthService) issueTokensWithSessionStart(ctx context.Context, user *User, ipAddr, userAgent string, sessionStartedAtMs int64) (string, string, error) {
	now := s.nowMs()
	sessionStart := sessionStartedAtMs
	if sessionStart <= 0 {
		sessionStart = now
	}

	// Stamp the derived minor flag from the stored DOB so the token carries
	// an authoritative is_minor claim when age-gating is on. No-op (false)
	// when the gate is off or no DOB is on file.
	s.stampAgeBand(ctx, user)

	// The requested product's age guardrail, checked on the derived band the
	// stamp above produced and before any session state is written.
	if err := s.enforceProductAgeGate(ctx, user); err != nil {
		return "", "", err
	}

	// The required-DOB completion gate, checked before any session state is
	// written. Like the product gate it lives here, at the chokepoint, so
	// every session-issuing path — initial login, refresh, and any path
	// added later — is covered by construction.
	if err := s.enforceDOBRequired(ctx, user, ipAddr, userAgent); err != nil {
		return "", "", err
	}

	claims := jwt.Claims{
		Sub:       user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Role:      user.Role,
		Tenant:    s.tenantID(ctx),
		Project:   s.projectID(ctx),
		AvatarURL: user.AvatarURL,
		IsMinor:   user.IsMinor,
		Anonymous: user.IsAnonymous,
	}
	if s.cfg.JWTAudience != "" {
		claims.Audience = []string{s.cfg.JWTAudience}
	}

	var sid string
	if s.cfg.RevocationMode == config.RevocationModeSession {
		sid = generateSessionID()
		if _, err := s.repo(ctx).CreateSession(ctx, &SessionRecord{
			SID:         sid,
			UserID:      user.ID,
			CreatedAtMs: now,
		}); err != nil {
			return "", "", fmt.Errorf("creating session: %w", err)
		}
		claims.SID = sid
	}

	accessToken, err := s.signer.SignAccessToken(ctx, claims, s.cfg.JWTExpiry())
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	rawRefresh, refreshHash := generateRefreshToken()
	devName := friendlyDeviceName(userAgent)

	_, err = s.repo(ctx).CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash:        refreshHash,
		UserID:           user.ID,
		DeviceInfo:       devName,
		DeviceName:       devName,
		IPAddress:        ipAddr,
		UserAgent:        truncate(userAgent, 512),
		ExpiresAt:        now + int64(s.cfg.RefreshExpirySeconds)*1000,
		CreatedAt:        now,
		LastUsedAt:       now,
		SessionStartedAt: sessionStart,
		SID:              sid,
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
	newCount, err = s.repo(ctx).IncrementFailedLoginCount(ctx, user.ID)
	if err != nil {
		s.logger.Warn("failed_login_increment_failed",
			zap.String("user_id", user.ID), zap.Error(err))
		return 0, false, err
	}
	if int(newCount) >= s.cfg.LoginMaxFailedAttempts {
		now := s.nowMs()
		lockedUntil := now + int64(s.cfg.LoginLockoutSeconds)*1000
		if lockErr := s.repo(ctx).SetUserLockedUntil(ctx, user.ID, lockedUntil); lockErr != nil {
			s.logger.Warn("set_locked_until_failed",
				zap.String("user_id", user.ID), zap.Error(lockErr))
			return newCount, false, lockErr
		}
		s.logger.Warn(
			"account_locked",
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
	if err := s.repo(ctx).ResetFailedLoginCount(ctx, user.ID); err != nil {
		s.logger.Warn("failed_login_reset_failed", zap.String("user_id", user.ID), zap.Error(err))
	}
}

// revokeUserSessionsIfModeSession invokes RevokeSessionsForUser when
// the configured revocation mode is `session`. Callers pair this with
// DeleteRefreshTokensForUser at credential-change / replay-detection
// sites so the existing access tokens stop working immediately rather
// than after the natural JWT expiry. Failures are logged but not
// propagated: the caller has already invalidated refresh tokens, so a
// failed session revocation only widens the access-token validity to
// the cache TTL — not a complete bypass.
func (s *AuthService) revokeUserSessionsIfModeSession(ctx context.Context, userID, reason string) {
	if s.cfg.RevocationMode != config.RevocationModeSession {
		return
	}
	if err := s.repo(ctx).RevokeSessionsForUser(ctx, userID, s.nowMs()); err != nil {
		s.logger.Warn("session_revoke_for_user_failed",
			zap.String("user_id", userID), zap.String("reason", reason), zap.Error(err))
	}
}

// revokeSessionIfModeSession revokes exactly the access session identified by
// sid when the deployment runs mode=session, leaving the user's other sessions
// untouched. It is paired with every path that invalidates a single refresh
// token — logout, natural-expiry cleanup, and a session-timeout breach — so the
// still-valid access token stops working immediately rather than lingering to
// its natural (uncapped in mode=session) expiry.
//
// A legacy refresh row written before the sid link existed carries an empty
// sid, making the scoped revoke impossible; it fails CLOSED by falling back to
// the user-scoped revoke the replay-detection path uses, at the cost of ending
// the user's other sessions. Best-effort: a failure widens the access-token
// validity to the middleware cache TTL, not a full bypass, so it is logged
// rather than propagated.
func (s *AuthService) revokeSessionIfModeSession(ctx context.Context, sid, userID, reason string) {
	if s.cfg.RevocationMode != config.RevocationModeSession {
		return
	}
	if sid == "" {
		s.revokeUserSessionsIfModeSession(ctx, userID, reason)
		return
	}
	if err := s.repo(ctx).RevokeSession(ctx, sid, s.nowMs()); err != nil {
		s.logger.Warn("session_revoke_failed",
			zap.String("user_id", userID), zap.String("reason", reason), zap.Error(err))
	}
}

// updateLastLogin sets last_login_at for admin visibility (best-effort).
func (s *AuthService) updateLastLogin(ctx context.Context, userID string) {
	now := s.nowMs()
	if err := s.repo(ctx).UpdateUser(ctx, userID, map[string]any{
		"last_login_at": now, "updated_at": now,
	}); err != nil {
		s.logger.Warn("last_login_update_failed", zap.String("user_id", userID), zap.Error(err))
	}
}

// issueLoginChallenge creates a pending 2FA login challenge.
func (s *AuthService) issueLoginChallenge(ctx context.Context, userID string) (string, error) {
	now := s.nowMs()
	challengeID := generateChallengeID()
	_, err := s.repo(ctx).CreateLoginChallenge(ctx, &LoginChallengeRecord{
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
	record, err := s.repo(ctx).GetLoginChallengeByChallengeID(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("%w: invalid or expired login challenge", ErrUnauthenticated)
	}
	if record.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeleteLoginChallenge(ctx, record.NodeID)
		return nil, fmt.Errorf("%w: login challenge expired", ErrUnauthenticated)
	}
	// Single-use: delete before returning success.
	if err := s.repo(ctx).DeleteLoginChallenge(ctx, record.NodeID); err != nil {
		s.logger.Warn("login_challenge_delete_failed", zap.String("challenge_id", challengeID))
	}
	return record, nil
}

// storeRecoveryCodes deletes existing codes for a user and stores fresh hashes.
func (s *AuthService) storeRecoveryCodes(ctx context.Context, userID string, codes []string) error {
	if err := s.repo(ctx).DeleteRecoveryCodesForUser(ctx, userID); err != nil {
		return fmt.Errorf("deleting old recovery codes: %w", err)
	}
	now := s.nowMs()
	for _, code := range codes {
		_, err := s.repo(ctx).CreateRecoveryCode(ctx, &RecoveryCodeRecord{
			UserID:    userID,
			CodeHash:  totp.HashRecoveryCode(code, s.totpRecoveryPepper),
			Used:      false,
			CreatedAt: now,
		})
		if err != nil {
			return fmt.Errorf("creating recovery code: %w", err)
		}
	}
	return nil
}

// validatePasswordStrength checks password requirements against the global
// default policy and returns an error if weak.
func validatePasswordStrength(pw string) error {
	return passwordIssuesToErr(passwords.ValidateStrength(pw))
}

// validatePasswordStrengthForEmail checks password requirements against the
// per-tenant policy for the org that owns email's domain, binding the request's
// project scope to the shared governance validation.
func (s *AuthService) validatePasswordStrengthForEmail(ctx context.Context, email, pw string) error {
	return s.governance.validatePasswordStrength(ctx, s.projectID(ctx), s.logger, email, pw)
}

func passwordIssuesToErr(issues []string) error {
	if len(issues) > 0 {
		return fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(issues, "; "))
	}
	return nil
}

// validateEmailFormat + canonicalizeEmail live in email_canonicalize.go
// so the surface they cover (format, length, reserved TLDs, disposable
// providers, Gmail-style normalization) is in one place.

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
	user, err := s.repo(ctx).GetUser(ctx, userID)
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

	record, err := s.repo(ctx).FindRefreshTokenByHashIncludingConsumed(ctx, tokenHash)
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
		if delErr := s.repo(ctx).DeleteRefreshTokensForUser(ctx, userID); delErr != nil {
			s.logger.Warn("refresh_token_replay_revoke_failed",
				zap.String("user_id", userID), zap.Error(delErr))
		}
		// In mode=session the existing replay-detection path also
		// kills the access tokens — without this step, an attacker
		// who triggered the replay still holds a live JWT until its
		// natural expiry (the bug the two-mode contract exists to
		// fix; see docs/IDENTITY.md decision log §6).
		s.revokeUserSessionsIfModeSession(ctx, userID, "refresh_token_replay")
		s.audit.Log(
			ctx, audit.EventLoginFailure,
			audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": "refresh_token_replay"}),
		)
		return nil, "", "", fmt.Errorf("%w: refresh token replay", ErrUnauthenticated)
	}

	if record.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeleteRefreshToken(ctx, record.NodeID)
		// A deployer may set the JWT expiry longer than the refresh TTL in
		// mode=session, so the access session must die with its refresh token.
		s.revokeSessionIfModeSession(ctx, record.SID, record.UserID, "refresh_token_expired")
		return nil, "", "", fmt.Errorf("%w: refresh token expired", ErrTokenExpired)
	}

	// Per-tenant session timeout (idle / absolute). Enforced BEFORE the
	// token is rotated so an expired session never mints fresh tokens, and
	// the refresh row is deleted so the dead session can't be retried.
	// Requires the user's email to resolve the owning tenant's policy; the
	// lookup fails safe (no policy → no timeout) so a non-governed user is
	// unaffected.
	timeoutUser, err := s.repo(ctx).GetUser(ctx, record.UserID)
	if err != nil {
		return nil, "", "", err
	}
	if timeoutUser == nil {
		return nil, "", "", fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if err := s.enforceSessionTimeout(ctx, timeoutUser.Email, s.nowMs(), record.SessionStartedAt, record.LastUsedAt); err != nil {
		_ = s.repo(ctx).DeleteRefreshToken(ctx, record.NodeID)
		// Under mode=session the deleted refresh row is not enough: the access
		// token minted alongside it is still valid until its natural expiry, so
		// revoke the matching access session (scoped to this sid) too.
		s.revokeSessionIfModeSession(ctx, record.SID, record.UserID, "session_timeout")
		return nil, "", "", err
	}

	// Every check that can refuse an ANONYMOUS account runs BEFORE the token
	// is consumed. A refresh token is an anonymous account's ONLY credential,
	// so consuming it and then refusing burns it: undoing the refusal's cause
	// does not restore the session, and the retry an SDK makes on the error
	// lands on replay detection, leaving the account permanently
	// unreachable — and hard-deleted once the retention window elapses. Every
	// other check on this path guards an account that has some other way back
	// in.
	if timeoutUser.IsAnonymous {
		if !s.anonymousEnabled(ctx) {
			return nil, "", "", ErrAnonymousRefreshDisabled
		}
		// The product age gate denies anonymous accounts outright when the
		// requested product sets a minimum band, and that is reachable
		// mid-session: a product can gain a minimum_age_band between
		// sign-in and the next rotation, or the refresh can carry a
		// different X-Product than the sign-in did. The gate still runs
		// inside issueTokensWithSessionStart; this early pass exists only
		// so the refusal is non-destructive.
		if err := s.enforceProductAgeGate(ctx, timeoutUser); err != nil {
			return nil, "", "", err
		}
	}

	// Same reasoning for the required-DOB gate, and it applies to EVERY
	// account, not only anonymous ones. Enabling GATEWAY_AGEGATE_REQUIRE_DOB
	// makes every pre-existing dob-less session fail its next rotation; if
	// that refusal came after the consume, the token would be burnt, and the
	// retry an SDK makes on a failed rotation would land on replay detection
	// — which deletes every refresh token the user has and signs them out on
	// all their devices. The gate still runs inside
	// issueTokensWithSessionStart (so nothing is bypassed); this early pass
	// exists only so the refusal is non-destructive and the client can
	// complete the step and rotate normally.
	if err := s.enforceDOBRequired(ctx, timeoutUser, ipAddr, userAgent); err != nil {
		return nil, "", "", err
	}

	// Rotation. ConsumeRefreshTokenByHash is the serialization point: it
	// only succeeds when the row's consumed_at is currently 0, so two
	// concurrent rotations of the same token resolve to exactly one
	// winner. The loser observes the now-consumed state on its next read
	// and gets ErrUnauthenticated.
	if err := s.repo(ctx).ConsumeRefreshTokenByHash(ctx, tokenHash, s.nowMs()); err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return nil, "", "", fmt.Errorf("%w: refresh token already consumed", ErrUnauthenticated)
		}
		return nil, "", "", fmt.Errorf("consuming refresh token: %w", err)
	}

	user := timeoutUser

	// Re-enforce account status on every refresh: a user deactivated
	// (or locked, or IDV-revoked) after the original login must not be
	// able to mint fresh access tokens by replaying a still-valid
	// refresh token. A hard-deleted user is already covered above (the
	// refresh row is gone, so the lookup returns nil → unauthenticated).
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, "", "", err
	}

	// Re-enforce the project access mode (login context) on every refresh: a user
	// removed from an allowlist, or a project switched to closed, must stop
	// minting fresh access tokens rather than coast on a still-valid refresh
	// token until it expires. Login context, so invite mode keeps admitting an
	// already-provisioned user. user.Email is the DB-persisted (canonical) account
	// email; wrap once (idempotent, self-heals a legacy non-canonical row).
	//
	// Anonymous users are exempt, and must be. The access mode governs which
	// EMAIL-IDENTIFIED humans may authenticate; an anonymous account has no
	// email, so it would be judged as the empty address and DENIED under
	// every mode except `open` — silently killing anonymous sessions on any
	// allowlist/invite/closed project. That inverts the deliberate
	// orthogonality of the two switches (see ProjectAnonymousConfig): a
	// closed project may still run anonymous sessions. Anonymous traffic is
	// governed by the project's anonymous switch, re-checked here so that
	// turning the feature OFF does stop refreshes.
	if user.IsAnonymous {
		// The kill switch was already checked above, before the token was
		// consumed. Refresh is an anonymous account's only recurring sign of
		// life; stamping it here is what keeps an active one out of the sweep.
		s.touchAnonymousActivity(ctx, user)
	} else if err := s.enforceProjectAccessLogin(ctx, canonicalize(user.Email)); err != nil {
		return nil, "", "", err
	}

	// Propagate the session-start anchor UNCHANGED across the rotation so the
	// absolute timeout keeps measuring from the original login. A legacy row
	// with no anchor (SessionStartedAt == 0) is re-anchored at now by
	// issueTokensWithSessionStart.
	accessToken, newRefresh, err := s.issueTokensWithSessionStart(ctx, user, ipAddr, userAgent, record.SessionStartedAt)
	if err != nil {
		return nil, "", "", err
	}
	return user, accessToken, newRefresh, nil
}

// ── Logout ─────────────────────────────────────────────────────────────

// Logout deletes the refresh token identified by the raw token value. Under
// mode=session it also revokes the matching access session — an explicitly
// logged-out user must not keep a working access token until its natural
// (uncapped in mode=session) expiry.
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	if rawRefreshToken == "" {
		return nil
	}
	tokenHash := hashRefreshToken(rawRefreshToken)
	record, err := s.repo(ctx).FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("querying refresh token: %w", err)
	}
	if record == nil {
		return nil
	}
	userID := record.UserID
	_ = s.repo(ctx).DeleteRefreshToken(ctx, record.NodeID)
	s.revokeSessionIfModeSession(ctx, record.SID, userID, "logout")

	if userID != "" {
		s.audit.Log(ctx, audit.EventLogout, audit.WithActor(userID))
	}
	return nil
}
