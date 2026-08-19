// Package service — stub implementations for Repository and DB.
//
// These stubs return ErrServiceUnavailable for every operation. They
// exist so the identity service binary can start and serve health
// checks / JWKS even when the persistence adapter has not yet
// been wired up. Any RPC that touches persistence will receive a
// clean "service unavailable" error instead of a nil-pointer panic.
package service

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/graph"
)

// ErrServiceUnavailable is returned by stub implementations.
var ErrServiceUnavailable = errors.New("identity: persistence layer not configured")

// ── StubRepository ────────────────────────────────────────────────────

// StubRepository implements Repository but returns ErrServiceUnavailable
// for every method. Use it as a placeholder until the real
// repository is implemented.
type StubRepository struct{}

var _ Repository = (*StubRepository)(nil)

func (StubRepository) FindUserByEmail(context.Context, string) (*User, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) GetUser(context.Context, string) (*User, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreateUser(context.Context, *User) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) UpdateUser(context.Context, string, map[string]any) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteUser(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) ListUsersPendingDeletionBefore(context.Context, int64, int) ([]*User, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) ListUsers(context.Context, UserListFilter) ([]*User, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CountUsers(context.Context, UserListFilter) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) IncrementFailedLoginCount(context.Context, string) (int32, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) ResetFailedLoginCount(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) SetUserLockedUntil(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindRefreshTokenByHash(context.Context, string) (*RefreshTokenRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) FindRefreshTokenByHashIncludingConsumed(context.Context, string) (*RefreshTokenRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreateRefreshToken(context.Context, *RefreshTokenRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) DeleteRefreshToken(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteRefreshTokensForUser(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) ConsumeRefreshTokenByHash(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) ListPasskeyCredentials(context.Context, string) ([]*PasskeyCredRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) GetPasskeyCredentialByCredID(context.Context, string) (*PasskeyCredRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreatePasskeyCredential(context.Context, *PasskeyCredRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) UpdatePasskeyCredential(context.Context, string, map[string]any) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeletePasskeyCredentialsForUser(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) GetPasskeyChallenge(context.Context, string) (*PasskeyChallengeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreatePasskeyChallenge(context.Context, *PasskeyChallengeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) DeletePasskeyChallenge(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindQrLoginSession(context.Context, string) (*QrLoginSessionRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreateQrLoginSession(context.Context, *QrLoginSessionRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) UpdateQrLoginSession(context.Context, string, map[string]any) error {
	return ErrServiceUnavailable
}

func (StubRepository) ConsumeQrLoginSession(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateOAuthOneTimeCode(context.Context, *OAuthOneTimeCodeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) ConsumeOAuthOneTimeCode(context.Context, string, int64) (*OAuthOneTimeCodeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) RecordNativeTokenRedemption(context.Context, *NativeTokenRedemptionRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) UpsertEmailLoginCode(context.Context, *EmailLoginCodeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) FindEmailLoginCodeByEmail(context.Context, string) (*EmailLoginCodeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) IncrementEmailLoginCodeAttempts(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) ConsumeEmailLoginCode(context.Context, string, int64) (*EmailLoginCodeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreateMagicLinkToken(context.Context, *MagicLinkTokenRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) ConsumeMagicLinkToken(context.Context, string, int64) (*MagicLinkTokenRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) UpsertPhoneVerificationCode(context.Context, *PhoneVerificationCodeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) FindPhoneVerificationCodeByUser(context.Context, string) (*PhoneVerificationCodeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) IncrementPhoneVerificationCodeAttempts(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) ConsumePhoneVerificationCode(context.Context, string, int64) (*PhoneVerificationCodeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) SetUserPhoneVerified(context.Context, string, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) GetTotpCredential(context.Context, string) (*TotpCredRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreateTotpCredential(context.Context, *TotpCredRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) UpdateTotpCredential(context.Context, string, map[string]any) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteTotpCredential(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteTotpCredentialsForUser(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateRecoveryCode(context.Context, *RecoveryCodeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) FindRecoveryCodeByHash(context.Context, string, string) (*RecoveryCodeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) UpdateRecoveryCode(context.Context, string, map[string]any) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteRecoveryCodesForUser(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateLoginChallenge(context.Context, *LoginChallengeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) GetLoginChallengeByChallengeID(context.Context, string) (*LoginChallengeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) DeleteLoginChallenge(context.Context, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindInvitationByHash(context.Context, string) (*InvitationRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) UpdateInvitation(context.Context, string, map[string]any) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreatePasswordResetToken(context.Context, *PasswordResetToken) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindPasswordResetTokenByHash(context.Context, string) (*PasswordResetToken, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) MarkPasswordResetTokenConsumed(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateEmailVerificationToken(context.Context, *EmailVerificationToken) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindEmailVerificationTokenByHash(context.Context, string) (*EmailVerificationToken, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) MarkEmailVerificationTokenConsumed(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) SetUserEmailVerified(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) SetUserIDVVerified(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateIdentityVerification(context.Context, *IdentityVerificationRecord) error {
	return ErrServiceUnavailable
}

func (StubRepository) GetIdentityVerification(context.Context, string) (*IdentityVerificationRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) GetLatestIdentityVerificationForUser(context.Context, string) (*IdentityVerificationRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) UpdateIdentityVerificationStatus(context.Context, string, string, string, int64, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateParentalConsent(context.Context, *ParentalConsentRecord) error {
	return ErrServiceUnavailable
}

func (StubRepository) GetActiveParentalConsentForChild(context.Context, string) (*ParentalConsentRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) MarkParentalConsentRevoked(context.Context, string, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateEmailChangeToken(context.Context, *EmailChangeToken) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindEmailChangeTokenByHash(context.Context, string) (*EmailChangeToken, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) MarkEmailChangeTokenConsumed(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) UpdateUserEmail(context.Context, string, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) FindUserByProviderID(context.Context, string, string) (*User, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) CreateOAuthIdentity(context.Context, *OAuthIdentity) error {
	return ErrServiceUnavailable
}

func (StubRepository) ListOAuthIdentitiesForUser(context.Context, string) ([]*OAuthIdentity, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) DeleteOAuthIdentity(context.Context, string, string, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateAuditEvent(context.Context, *AuditEvent) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) ListAuditEventsForUser(context.Context, string, int) ([]*AuditEvent, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) DeleteAuditEventsBefore(context.Context, int64) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredWebAuthnChallenges(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredEmailVerificationTokens(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredPasswordResetTokens(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredEmailChangeTokens(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredLoginChallenges(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredOAuthOneTimeCodes(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredNativeTokenRedemptions(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredEmailLoginCodes(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredMagicLinkTokens(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredPhoneVerificationCodes(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredQrLoginSessions(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredInvitations(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateSession(context.Context, *SessionRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) GetSessionBySid(context.Context, string) (*SessionRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) RevokeSession(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) RevokeSessionsForUser(context.Context, string, int64) error {
	return ErrServiceUnavailable
}

// ── StubDB ────────────────────────────────────────────────────────────

// StubDB implements DB (and audit.NodeWriter) but returns
// ErrServiceUnavailable for every method.
type StubDB struct{}

var _ DB = (*StubDB)(nil)

func (StubDB) GetNode(context.Context, string, string, int, string) (*graph.Node, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) QueryNodes(context.Context, string, string, int, map[string]any) ([]*graph.Node, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) ExecuteAtomic(context.Context, string, string, []graph.Operation) (*graph.CommitResult, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) GetEdgesFrom(context.Context, string, string, string, int) ([]*graph.Edge, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) GetEdgesTo(context.Context, string, string, string, int) ([]*graph.Edge, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) SearchNodes(context.Context, string, string, int, string) ([]*graph.Node, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) RegisterUserInTenant(context.Context, string, string, string, string, string) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateAttestedDevice(context.Context, *AttestedDeviceRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) GetAttestedDeviceByKeyID(context.Context, string) (*AttestedDeviceRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) UpdateAttestedDeviceCounter(context.Context, string, int64, int64, int64) error {
	return ErrServiceUnavailable
}

func (StubRepository) CreateAssuranceChallenge(context.Context, *AssuranceChallengeRecord) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) ConsumeAssuranceChallenge(context.Context, string) (*AssuranceChallengeRecord, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredAssuranceChallenges(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteStaleAttestedDevices(context.Context, int64, int) error {
	return ErrServiceUnavailable
}

func (StubRepository) DeleteStaleAnonymousUsers(context.Context, int64, int) error {
	return ErrServiceUnavailable
}
