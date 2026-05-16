// Package service — stub implementations for Repository and DB.
//
// These stubs return ErrServiceUnavailable for every operation. They
// exist so the identity service binary can start and serve health
// checks / JWKS even when the EntDB persistence adapter has not yet
// been wired up. Any RPC that touches persistence will receive a
// clean "service unavailable" error instead of a nil-pointer panic.
package service

import (
	"context"
	"errors"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
)

// ErrServiceUnavailable is returned by stub implementations.
var ErrServiceUnavailable = errors.New("identity: persistence layer not configured")

// ── StubRepository ────────────────────────────────────────────────────

// StubRepository implements Repository but returns ErrServiceUnavailable
// for every method. Use it as a placeholder until the EntDB-backed
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

func (StubRepository) DeleteExpiredWebAuthnChallenges(context.Context, int64, int) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredEmailVerificationTokens(context.Context, int64, int) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredPasswordResetTokens(context.Context, int64, int) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredEmailChangeTokens(context.Context, int64, int) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) DeleteExpiredLoginChallenges(context.Context, int64, int) (int, error) {
	return 0, ErrServiceUnavailable
}

func (StubRepository) CreateOrganization(context.Context, *Organization) (string, error) {
	return "", ErrServiceUnavailable
}

func (StubRepository) GetOrganization(context.Context, string) (*Organization, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) GetOrganizationBySlug(context.Context, string) (*Organization, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) ListOrganizationsForUser(context.Context, string) ([]*Organization, error) {
	return nil, ErrServiceUnavailable
}

func (StubRepository) AddOrganizationMember(context.Context, *OrganizationMembership) (string, error) {
	return "", ErrServiceUnavailable
}

// ── StubDB ────────────────────────────────────────────────────────────

// StubDB implements DB (and audit.NodeWriter) but returns
// ErrServiceUnavailable for every method.
type StubDB struct{}

var _ DB = (*StubDB)(nil)

func (StubDB) GetNode(context.Context, string, string, int, string) (*entdb.Node, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) QueryNodes(context.Context, string, string, int, map[string]any) ([]*entdb.Node, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) ExecuteAtomic(context.Context, string, string, []entdb.Operation) (*entdb.CommitResult, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) GetEdgesFrom(context.Context, string, string, string, int) ([]*entdb.Edge, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) GetEdgesTo(context.Context, string, string, string, int) ([]*entdb.Edge, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) SearchNodes(context.Context, string, string, int, string) ([]*entdb.Node, error) {
	return nil, ErrServiceUnavailable
}

func (StubDB) RegisterUserInTenant(context.Context, string, string, string, string, string) error {
	return ErrServiceUnavailable
}
