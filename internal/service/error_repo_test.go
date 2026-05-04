// errorRepo wraps fakeRepo and can be configured to return errors from
// specific Repository method calls. Tests use it to exercise error
// branches without modifying the shared fakeRepo helper.
package service

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

var errInjected = errors.New("injected repo error")

type errorRepo struct {
	*fakeRepo
	failFindUserByEmail            bool
	failGetUser                    bool
	failCreateUser                 bool
	failUpdateUser                 bool
	failFindRefreshTokenByHash     bool
	failCreateRefreshToken         bool
	failListPasskeyCredentials     bool
	failGetPasskeyCredentialByCred bool
	failCreatePasskeyChallenge     bool
	failGetPasskeyChallenge        bool
	failCreatePasskeyCredential    bool
	failGetTotpCredential          bool
	failCreateTotpCredential       bool
	failCreateLoginChallenge       bool
	failGetLoginChallenge          bool
	failFindInvitationByHash       bool
	failUpdateInvitation           bool
	failFindQrLoginSession         bool
	failCreateQrLoginSession       bool
	failUpdateQrLoginSession       bool
	failDeleteRecoveryCodesForUser bool
	failCreateRecoveryCode         bool
}

func newErrorRepo() *errorRepo {
	return &errorRepo{fakeRepo: newFakeRepo()}
}

func (r *errorRepo) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	if r.failFindUserByEmail {
		return nil, errInjected
	}
	return r.fakeRepo.FindUserByEmail(ctx, email)
}

func (r *errorRepo) GetUser(ctx context.Context, id string) (*User, error) {
	if r.failGetUser {
		return nil, errInjected
	}
	return r.fakeRepo.GetUser(ctx, id)
}

func (r *errorRepo) CreateUser(ctx context.Context, u *User) (string, error) {
	if r.failCreateUser {
		return "", errInjected
	}
	return r.fakeRepo.CreateUser(ctx, u)
}

func (r *errorRepo) UpdateUser(ctx context.Context, id string, fields map[string]any) error {
	if r.failUpdateUser {
		return errInjected
	}
	return r.fakeRepo.UpdateUser(ctx, id, fields)
}

func (r *errorRepo) FindRefreshTokenByHash(ctx context.Context, h string) (*RefreshTokenRecord, error) {
	if r.failFindRefreshTokenByHash {
		return nil, errInjected
	}
	return r.fakeRepo.FindRefreshTokenByHash(ctx, h)
}

func (r *errorRepo) CreateRefreshToken(ctx context.Context, rec *RefreshTokenRecord) (string, error) {
	if r.failCreateRefreshToken {
		return "", errInjected
	}
	return r.fakeRepo.CreateRefreshToken(ctx, rec)
}

func (r *errorRepo) ListPasskeyCredentials(ctx context.Context, uid string) ([]*PasskeyCredRecord, error) {
	if r.failListPasskeyCredentials {
		return nil, errInjected
	}
	return r.fakeRepo.ListPasskeyCredentials(ctx, uid)
}

func (r *errorRepo) GetPasskeyCredentialByCredID(ctx context.Context, cid string) (*PasskeyCredRecord, error) {
	if r.failGetPasskeyCredentialByCred {
		return nil, errInjected
	}
	return r.fakeRepo.GetPasskeyCredentialByCredID(ctx, cid)
}

func (r *errorRepo) CreatePasskeyChallenge(ctx context.Context, rec *PasskeyChallengeRecord) (string, error) {
	if r.failCreatePasskeyChallenge {
		return "", errInjected
	}
	return r.fakeRepo.CreatePasskeyChallenge(ctx, rec)
}

func (r *errorRepo) GetPasskeyChallenge(ctx context.Context, id string) (*PasskeyChallengeRecord, error) {
	if r.failGetPasskeyChallenge {
		return nil, errInjected
	}
	return r.fakeRepo.GetPasskeyChallenge(ctx, id)
}

func (r *errorRepo) CreatePasskeyCredential(ctx context.Context, rec *PasskeyCredRecord) (string, error) {
	if r.failCreatePasskeyCredential {
		return "", errInjected
	}
	return r.fakeRepo.CreatePasskeyCredential(ctx, rec)
}

func (r *errorRepo) GetTotpCredential(ctx context.Context, uid string) (*TotpCredRecord, error) {
	if r.failGetTotpCredential {
		return nil, errInjected
	}
	return r.fakeRepo.GetTotpCredential(ctx, uid)
}

func (r *errorRepo) CreateTotpCredential(ctx context.Context, rec *TotpCredRecord) (string, error) {
	if r.failCreateTotpCredential {
		return "", errInjected
	}
	return r.fakeRepo.CreateTotpCredential(ctx, rec)
}

func (r *errorRepo) CreateLoginChallenge(ctx context.Context, rec *LoginChallengeRecord) (string, error) {
	if r.failCreateLoginChallenge {
		return "", errInjected
	}
	return r.fakeRepo.CreateLoginChallenge(ctx, rec)
}

func (r *errorRepo) GetLoginChallengeByChallengeID(ctx context.Context, id string) (*LoginChallengeRecord, error) {
	if r.failGetLoginChallenge {
		return nil, errInjected
	}
	return r.fakeRepo.GetLoginChallengeByChallengeID(ctx, id)
}

func (r *errorRepo) FindInvitationByHash(ctx context.Context, h string) (*InvitationRecord, error) {
	if r.failFindInvitationByHash {
		return nil, errInjected
	}
	return r.fakeRepo.FindInvitationByHash(ctx, h)
}

func (r *errorRepo) UpdateInvitation(ctx context.Context, id string, fields map[string]any) error {
	if r.failUpdateInvitation {
		return errInjected
	}
	return r.fakeRepo.UpdateInvitation(ctx, id, fields)
}

func (r *errorRepo) FindQrLoginSession(ctx context.Context, sid string) (*QrLoginSessionRecord, error) {
	if r.failFindQrLoginSession {
		return nil, errInjected
	}
	return r.fakeRepo.FindQrLoginSession(ctx, sid)
}

func (r *errorRepo) CreateQrLoginSession(ctx context.Context, rec *QrLoginSessionRecord) (string, error) {
	if r.failCreateQrLoginSession {
		return "", errInjected
	}
	return r.fakeRepo.CreateQrLoginSession(ctx, rec)
}

func (r *errorRepo) UpdateQrLoginSession(ctx context.Context, nid string, fields map[string]any) error {
	if r.failUpdateQrLoginSession {
		return errInjected
	}
	return r.fakeRepo.UpdateQrLoginSession(ctx, nid, fields)
}

func (r *errorRepo) DeleteRecoveryCodesForUser(ctx context.Context, uid string) error {
	if r.failDeleteRecoveryCodesForUser {
		return errInjected
	}
	return r.fakeRepo.DeleteRecoveryCodesForUser(ctx, uid)
}

func (r *errorRepo) CreateRecoveryCode(ctx context.Context, rec *RecoveryCodeRecord) (string, error) {
	if r.failCreateRecoveryCode {
		return "", errInjected
	}
	return r.fakeRepo.CreateRecoveryCode(ctx, rec)
}

// newTestAuthServiceErr builds an AuthService backed by errorRepo so
// tests can exercise repository error branches.
func newTestAuthServiceErr(t *testing.T, repo *errorRepo) *AuthService {
	t.Helper()
	cfg := testConfig()
	kr := testKeyRing(t)
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	return NewAuthService(repo, cfg, kr, passkeysSvc, audit.NewLogger(nil, "test", nil), testTotpKey(), nil, zap.NewNop())
}
