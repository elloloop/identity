package connect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identityconnect "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/captcha"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
)

// EntDB type IDs (mirrored from internal/service/entdb.go to avoid relying on
// unexported package symbols). Keep in sync.
const (
	tTypeUser            = 1
	tTypeWorkingGroup    = 2
	tTypeRefreshToken    = 5
	tTypePasswordReset   = 19
	tTypePasskeyCredCred = 20
	tTypeAuditEvent      = 26
	tTypeUserInvitation  = 27
	tTypeAdminHelpReq    = 28
)

// User payload field IDs.
const (
	tUfEmail         = "1"
	tUfName          = "2"
	tUfRole          = "3"
	tUfAvatarURL     = "4"
	tUfPasswordHash  = "7"
	tUfStatus        = "11"
	tUfRecoveryEmail = "12"
)

// RefreshToken payload field IDs.
const (
	tRfUserID    = "2"
	tRfExpiresAt = "4"
	tRfCreatedAt = "5"
)

// Passkey payload field IDs.
const (
	tPkfCredentialID = "1"
	tPkfUserID       = "2"
	tPkfDeviceName   = "5"
)

// HelpRequest payload field IDs.
const (
	tHfEmail     = "1"
	tHfStatus    = "5"
	tHfCreatedAt = "9"
)

// ──────────────────────────────────────────────────────────────────────
// fakeRepo implements service.Repository.
// ──────────────────────────────────────────────────────────────────────

var nodeIDSeq atomic.Int64

func nextID() string { return fmt.Sprintf("n-%d", nodeIDSeq.Add(1)) }

type fakeRepo struct {
	mu sync.Mutex

	users              map[string]*service.User
	refreshTokens      map[string]*service.RefreshTokenRecord
	passkeyCreds       map[string]*service.PasskeyCredRecord
	passkeyChallenges  map[string]*service.PasskeyChallengeRecord
	qrSessions         map[string]*service.QrLoginSessionRecord
	oauthOneTimeCodes  map[string]*service.OAuthOneTimeCodeRecord
	emailLoginCodes    map[string]*service.EmailLoginCodeRecord
	magicLinkTokens    map[string]*service.MagicLinkTokenRecord
	phoneVerifyCodes   map[string]*service.PhoneVerificationCodeRecord
	totpCreds          map[string]*service.TotpCredRecord
	recoveryCodes      map[string]*service.RecoveryCodeRecord
	loginChallenges    map[string]*service.LoginChallengeRecord
	invitations        map[string]*service.InvitationRecord
	passwordResets     map[string]*service.PasswordResetToken
	emailVerifications map[string]*service.EmailVerificationToken
	emailChanges       map[string]*service.EmailChangeToken
	oauthIdentities    map[string]*service.OAuthIdentity
	idvRecords         map[string]*service.IdentityVerificationRecord
	orgs               map[string]*service.Organization
	orgMembers         map[string]*service.OrganizationMembership
	sessions           map[string]*service.SessionRecord

	// Optional error injections for specific calls.
	errFindUser   error
	errCreateUser error
	errIssueToken error // makes CreateRefreshToken fail
	errGetUser    error // makes GetUser fail
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:              make(map[string]*service.User),
		refreshTokens:      make(map[string]*service.RefreshTokenRecord),
		passkeyCreds:       make(map[string]*service.PasskeyCredRecord),
		passkeyChallenges:  make(map[string]*service.PasskeyChallengeRecord),
		qrSessions:         make(map[string]*service.QrLoginSessionRecord),
		oauthOneTimeCodes:  make(map[string]*service.OAuthOneTimeCodeRecord),
		emailLoginCodes:    make(map[string]*service.EmailLoginCodeRecord),
		magicLinkTokens:    make(map[string]*service.MagicLinkTokenRecord),
		phoneVerifyCodes:   make(map[string]*service.PhoneVerificationCodeRecord),
		totpCreds:          make(map[string]*service.TotpCredRecord),
		recoveryCodes:      make(map[string]*service.RecoveryCodeRecord),
		loginChallenges:    make(map[string]*service.LoginChallengeRecord),
		invitations:        make(map[string]*service.InvitationRecord),
		passwordResets:     make(map[string]*service.PasswordResetToken),
		emailVerifications: make(map[string]*service.EmailVerificationToken),
		emailChanges:       make(map[string]*service.EmailChangeToken),
		oauthIdentities:    make(map[string]*service.OAuthIdentity),
		orgs:               make(map[string]*service.Organization),
		orgMembers:         make(map[string]*service.OrganizationMembership),
		sessions:           make(map[string]*service.SessionRecord),
	}
}

func (r *fakeRepo) FindUserByEmail(_ context.Context, email string) (*service.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errFindUser != nil {
		return nil, r.errFindUser
	}
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) GetUser(_ context.Context, userID string) (*service.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errGetUser != nil {
		return nil, r.errGetUser
	}
	u, ok := r.users[userID]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (r *fakeRepo) CreateUser(_ context.Context, u *service.User) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errCreateUser != nil {
		return "", r.errCreateUser
	}
	for _, e := range r.users {
		if e.Email == u.Email {
			return "", fmt.Errorf("user with email %s already exists", u.Email)
		}
	}
	id := nextID()
	u.ID = id
	cp := *u
	r.users[id] = &cp
	return id, nil
}

func (r *fakeRepo) UpdateUser(_ context.Context, userID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	for k, v := range fields {
		switch k {
		case "name":
			u.Name = v.(string)
		case "email":
			u.Email = v.(string)
		case "avatar_url":
			u.AvatarURL = v.(string)
		case "password_hash":
			u.PasswordHash = v.(string)
		case "status":
			u.Status = v.(string)
		case "totp_required":
			u.TotpRequired = v.(bool)
		case "failed_login_count":
			switch x := v.(type) {
			case int:
				u.FailedLoginCount = x
			case int64:
				u.FailedLoginCount = int(x)
			}
		case "locked_until":
			switch x := v.(type) {
			case int64:
				u.LockedUntil = x
			case int:
				u.LockedUntil = int64(x)
			}
		case "updated_at":
			if x, ok := v.(int64); ok {
				u.UpdatedAt = time.UnixMilli(x)
			}
		case "last_login_at":
			if x, ok := v.(int64); ok {
				u.LastLoginAtMs = x
			}
		case "recovery_email":
			u.RecoveryEmail = v.(string)
		}
	}
	return nil
}

func (r *fakeRepo) IncrementFailedLoginCount(_ context.Context, userID string) (int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return 0, fmt.Errorf("user %s not found", userID)
	}
	u.FailedLoginCount++
	return intToProtoInt32(u.FailedLoginCount), nil
}

func (r *fakeRepo) ResetFailedLoginCount(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.FailedLoginCount = 0
	u.LockedUntil = 0
	return nil
}

func (r *fakeRepo) SetUserLockedUntil(_ context.Context, userID string, lockedUntilMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.LockedUntil = lockedUntilMs
	return nil
}

func (r *fakeRepo) FindRefreshTokenByHash(_ context.Context, hash string) (*service.RefreshTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash && t.ConsumedAtMs == 0 {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) FindRefreshTokenByHashIncludingConsumed(_ context.Context, hash string) (*service.RefreshTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) CreateRefreshToken(_ context.Context, rec *service.RefreshTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errIssueToken != nil {
		return "", r.errIssueToken
	}
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.refreshTokens[id] = &cp
	return id, nil
}

func (r *fakeRepo) DeleteRefreshToken(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.refreshTokens, nodeID)
	return nil
}

func (r *fakeRepo) DeleteRefreshTokensForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.refreshTokens {
		if t.UserID == userID {
			delete(r.refreshTokens, id)
		}
	}
	return nil
}

// DeleteUser mirrors the memory cascade over the fake's maps. Audit
// events have no map here; email-keyed codes are left untouched.
func (r *fakeRepo) DeleteUser(_ context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.refreshTokens {
		if t.UserID == userID {
			delete(r.refreshTokens, id)
		}
	}
	for id, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, id)
		}
	}
	for id, c := range r.passkeyCreds {
		if c.UserID == userID {
			delete(r.passkeyCreds, id)
		}
	}
	for id, c := range r.passkeyChallenges {
		if c.UserID == userID {
			delete(r.passkeyChallenges, id)
		}
	}
	for id, s := range r.qrSessions {
		if s.UserID == userID {
			delete(r.qrSessions, id)
		}
	}
	for id, c := range r.oauthOneTimeCodes {
		if c.UserID == userID {
			delete(r.oauthOneTimeCodes, id)
		}
	}
	for id, c := range r.totpCreds {
		if c.UserID == userID {
			delete(r.totpCreds, id)
		}
	}
	for id, c := range r.recoveryCodes {
		if c.UserID == userID {
			delete(r.recoveryCodes, id)
		}
	}
	for id, c := range r.loginChallenges {
		if c.UserID == userID {
			delete(r.loginChallenges, id)
		}
	}
	for id, inv := range r.invitations {
		if inv.UserID == userID {
			delete(r.invitations, id)
		}
	}
	for id, t := range r.passwordResets {
		if t.UserID == userID {
			delete(r.passwordResets, id)
		}
	}
	for id, t := range r.emailVerifications {
		if t.UserID == userID {
			delete(r.emailVerifications, id)
		}
	}
	for id, t := range r.emailChanges {
		if t.UserID == userID {
			delete(r.emailChanges, id)
		}
	}
	for id, oi := range r.oauthIdentities {
		if oi.UserID == userID {
			delete(r.oauthIdentities, id)
		}
	}
	for id, rec := range r.idvRecords {
		if rec.UserID == userID {
			delete(r.idvRecords, id)
		}
	}
	for id, m := range r.orgMembers {
		if m.UserID == userID {
			delete(r.orgMembers, id)
		}
	}
	delete(r.users, userID)
	return nil
}

func (r *fakeRepo) ConsumeRefreshTokenByHash(_ context.Context, hash string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash {
			if t.ConsumedAtMs != 0 {
				return service.ErrUnauthenticated
			}
			t.ConsumedAtMs = atMs
			return nil
		}
	}
	return service.ErrUnauthenticated
}

func (r *fakeRepo) ListPasskeyCredentials(_ context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.PasskeyCredRecord
	for _, c := range r.passkeyCreds {
		if c.UserID == userID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeRepo) GetPasskeyCredentialByCredID(_ context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.passkeyCreds {
		if c.CredentialID == credentialID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) CreatePasskeyCredential(_ context.Context, rec *service.PasskeyCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.passkeyCreds[id] = &cp
	return id, nil
}

func (r *fakeRepo) UpdatePasskeyCredential(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyCreds[nodeID]
	if !ok {
		return fmt.Errorf("passkey cred %s not found", nodeID)
	}
	if v, ok := fields["sign_count"]; ok {
		c.SignCount = v.(int64)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt = v.(int64)
	}
	return nil
}

func (r *fakeRepo) GetPasskeyChallenge(_ context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *fakeRepo) CreatePasskeyChallenge(_ context.Context, rec *service.PasskeyChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.passkeyChallenges[id] = &cp
	return id, nil
}

func (r *fakeRepo) DeletePasskeyChallenge(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.passkeyChallenges, nodeID)
	return nil
}

func (r *fakeRepo) FindQrLoginSession(_ context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.qrSessions {
		if s.SessionID == sessionID {
			cp := *s
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) CreateQrLoginSession(_ context.Context, rec *service.QrLoginSessionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.qrSessions[id] = &cp
	return id, nil
}

func (r *fakeRepo) UpdateQrLoginSession(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.qrSessions[nodeID]
	if !ok {
		return fmt.Errorf("qr session %s not found", nodeID)
	}
	if v, ok := fields["status"]; ok {
		s.Status = v.(string)
	}
	if v, ok := fields["user_id"]; ok {
		s.UserID = v.(string)
	}
	if v, ok := fields["approved_device_info"]; ok {
		s.ApprovedDeviceInfo = v.(string)
	}
	if v, ok := fields["updated_at"]; ok {
		s.UpdatedAt = v.(int64)
	}
	return nil
}

func (r *fakeRepo) ConsumeQrLoginSession(_ context.Context, nodeID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.qrSessions[nodeID]
	if !ok {
		return service.ErrQrLoginNotPending
	}
	if s.Status != "approved" {
		return service.ErrQrLoginNotPending
	}
	s.Status = "consumed"
	s.UpdatedAt = atMs
	return nil
}

func (r *fakeRepo) CreateOAuthOneTimeCode(_ context.Context, rec *service.OAuthOneTimeCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.oauthOneTimeCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) ConsumeOAuthOneTimeCode(_ context.Context, codeHash string, atMs int64) (*service.OAuthOneTimeCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.oauthOneTimeCodes {
		if c.CodeHash != codeHash {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, service.ErrOAuthCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, service.ErrOAuthCodeInvalid
}

func (r *fakeRepo) UpsertEmailLoginCode(_ context.Context, rec *service.EmailLoginCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.emailLoginCodes {
		if c.Email == rec.Email {
			delete(r.emailLoginCodes, id)
		}
	}
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.emailLoginCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) FindEmailLoginCodeByEmail(_ context.Context, email string) (*service.EmailLoginCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.emailLoginCodes {
		if c.Email == email {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) IncrementEmailLoginCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.emailLoginCodes[nodeID]
	if !ok {
		return errors.New("email login code not found")
	}
	c.AttemptCount++
	return nil
}

func (r *fakeRepo) ConsumeEmailLoginCode(_ context.Context, email string, atMs int64) (*service.EmailLoginCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.emailLoginCodes {
		if c.Email != email {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, service.ErrEmailLoginCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, service.ErrEmailLoginCodeInvalid
}

func (r *fakeRepo) CreateMagicLinkToken(_ context.Context, rec *service.MagicLinkTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.magicLinkTokens[id] = &cp
	return id, nil
}

func (r *fakeRepo) ConsumeMagicLinkToken(_ context.Context, tokenHash string, atMs int64) (*service.MagicLinkTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.magicLinkTokens {
		if t.TokenHash != tokenHash {
			continue
		}
		if t.ConsumedAt != 0 || t.ExpiresAt <= atMs {
			return nil, service.ErrMagicLinkInvalid
		}
		t.ConsumedAt = atMs
		cp := *t
		return &cp, nil
	}
	return nil, service.ErrMagicLinkInvalid
}

func (r *fakeRepo) UpsertPhoneVerificationCode(_ context.Context, rec *service.PhoneVerificationCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.phoneVerifyCodes {
		if c.UserID == rec.UserID {
			delete(r.phoneVerifyCodes, id)
		}
	}
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.phoneVerifyCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) FindPhoneVerificationCodeByUser(_ context.Context, userID string) (*service.PhoneVerificationCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.phoneVerifyCodes {
		if c.UserID == userID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) IncrementPhoneVerificationCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.phoneVerifyCodes[nodeID]
	if !ok {
		return errors.New("phone verification code not found")
	}
	c.AttemptCount++
	return nil
}

func (r *fakeRepo) ConsumePhoneVerificationCode(_ context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.phoneVerifyCodes {
		if c.UserID != userID {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, service.ErrPhoneCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, service.ErrPhoneCodeInvalid
}

func (r *fakeRepo) SetUserPhoneVerified(_ context.Context, userID, phoneNumber string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.PhoneNumber = phoneNumber
	u.PhoneVerified = true
	u.PhoneVerifiedAt = atMs
	return nil
}

func (r *fakeRepo) GetTotpCredential(_ context.Context, userID string) (*service.TotpCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.totpCreds {
		if c.UserID == userID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) CreateTotpCredential(_ context.Context, rec *service.TotpCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.totpCreds[id] = &cp
	return id, nil
}

func (r *fakeRepo) UpdateTotpCredential(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.totpCreds[nodeID]
	if !ok {
		return fmt.Errorf("totp cred %s not found", nodeID)
	}
	if v, ok := fields["verified"]; ok {
		c.Verified = v.(bool)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt = v.(int64)
	}
	return nil
}

func (r *fakeRepo) DeleteTotpCredential(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.totpCreds, nodeID)
	return nil
}

func (r *fakeRepo) DeleteTotpCredentialsForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.totpCreds {
		if c.UserID == userID {
			delete(r.totpCreds, id)
		}
	}
	return nil
}

func (r *fakeRepo) CreateRecoveryCode(_ context.Context, rec *service.RecoveryCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.recoveryCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) FindRecoveryCodeByHash(_ context.Context, userID, hash string) (*service.RecoveryCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rc := range r.recoveryCodes {
		if rc.UserID == userID && rc.CodeHash == hash {
			cp := *rc
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) UpdateRecoveryCode(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rc, ok := r.recoveryCodes[nodeID]
	if !ok {
		return fmt.Errorf("recovery code %s not found", nodeID)
	}
	if v, ok := fields["used"]; ok {
		rc.Used = v.(bool)
	}
	if v, ok := fields["used_at"]; ok {
		rc.UsedAt = v.(int64)
	}
	return nil
}

func (r *fakeRepo) DeleteRecoveryCodesForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, rc := range r.recoveryCodes {
		if rc.UserID == userID {
			delete(r.recoveryCodes, id)
		}
	}
	return nil
}

func (r *fakeRepo) CreateLoginChallenge(_ context.Context, rec *service.LoginChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	rec.NodeID = id
	cp := *rec
	r.loginChallenges[id] = &cp
	return id, nil
}

func (r *fakeRepo) GetLoginChallengeByChallengeID(_ context.Context, challengeID string) (*service.LoginChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, lc := range r.loginChallenges {
		if lc.ChallengeID == challengeID {
			cp := *lc
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) DeleteLoginChallenge(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.loginChallenges, nodeID)
	return nil
}

func (r *fakeRepo) FindInvitationByHash(_ context.Context, tokenHash string) (*service.InvitationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inv := range r.invitations {
		if inv.TokenHash == tokenHash {
			cp := *inv
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) UpdateInvitation(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	inv, ok := r.invitations[nodeID]
	if !ok {
		return fmt.Errorf("invitation %s not found", nodeID)
	}
	if v, ok := fields["accepted_at"]; ok {
		inv.AcceptedAt = v.(int64)
	}
	return nil
}

func (r *fakeRepo) CreatePasswordResetToken(_ context.Context, t *service.PasswordResetToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	t.NodeID = id
	cp := *t
	r.passwordResets[id] = &cp
	return nil
}

func (r *fakeRepo) FindPasswordResetTokenByHash(_ context.Context, hash string) (*service.PasswordResetToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.passwordResets {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) MarkPasswordResetTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.passwordResets[id]
	if !ok {
		return fmt.Errorf("password reset token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *fakeRepo) CreateEmailVerificationToken(_ context.Context, t *service.EmailVerificationToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	t.NodeID = id
	cp := *t
	r.emailVerifications[id] = &cp
	return nil
}

func (r *fakeRepo) FindEmailVerificationTokenByHash(_ context.Context, hash string) (*service.EmailVerificationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.emailVerifications {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) MarkEmailVerificationTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.emailVerifications[id]
	if !ok {
		return fmt.Errorf("email verification token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *fakeRepo) SetUserEmailVerified(_ context.Context, userID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.EmailVerified = true
	u.EmailVerifiedAt = atMs
	return nil
}

func (r *fakeRepo) SetUserIDVVerified(_ context.Context, userID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.IDVVerified = true
	u.IDVVerifiedAt = atMs
	return nil
}

func (r *fakeRepo) CreateEmailChangeToken(_ context.Context, t *service.EmailChangeToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextID()
	t.NodeID = id
	cp := *t
	r.emailChanges[id] = &cp
	return nil
}

func (r *fakeRepo) FindEmailChangeTokenByHash(_ context.Context, hash string) (*service.EmailChangeToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.emailChanges {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) FindUserByProviderID(_ context.Context, provider, providerUserID string) (*service.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, oi := range r.oauthIdentities {
		if oi.Provider == provider && oi.ProviderUserID == providerUserID {
			u, ok := r.users[oi.UserID]
			if !ok {
				return nil, nil
			}
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) MarkEmailChangeTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.emailChanges[id]
	if !ok {
		return fmt.Errorf("email change token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *fakeRepo) UpdateUserEmail(_ context.Context, userID, newEmail string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	for id, other := range r.users {
		if id != userID && other.Email == newEmail {
			return fmt.Errorf("email %q already in use", newEmail)
		}
	}
	u.Email = newEmail
	u.EmailVerified = true
	u.EmailVerifiedAt = atMs
	u.UpdatedAt = time.UnixMilli(atMs)
	return nil
}

func (r *fakeRepo) CreateOAuthIdentity(_ context.Context, oi *service.OAuthIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.oauthIdentities {
		if existing.Provider == oi.Provider && existing.ProviderUserID == oi.ProviderUserID {
			return fmt.Errorf("oauth identity already linked: %s/%s", oi.Provider, oi.ProviderUserID)
		}
	}
	id := nextID()
	oi.NodeID = id
	cp := *oi
	r.oauthIdentities[id] = &cp
	return nil
}

func (r *fakeRepo) ListOAuthIdentitiesForUser(_ context.Context, userID string) ([]*service.OAuthIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.OAuthIdentity
	for _, oi := range r.oauthIdentities {
		if oi.UserID == userID {
			cp := *oi
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ── Identity Verification ──────────────────────────────────────────────

func (r *fakeRepo) CreateIdentityVerification(_ context.Context, rec *service.IdentityVerificationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.VerificationID == "" {
		return errors.New("idv: missing verification id")
	}
	if r.idvRecords == nil {
		r.idvRecords = make(map[string]*service.IdentityVerificationRecord)
	}
	if _, ok := r.idvRecords[rec.VerificationID]; ok {
		return fmt.Errorf("idv: %s already exists", rec.VerificationID)
	}
	if rec.NodeID == "" {
		rec.NodeID = nextID()
	}
	cp := *rec
	r.idvRecords[rec.VerificationID] = &cp
	return nil
}

func (r *fakeRepo) GetIdentityVerification(_ context.Context, verificationID string) (*service.IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (r *fakeRepo) GetLatestIdentityVerificationForUser(_ context.Context, userID string) (*service.IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *service.IdentityVerificationRecord
	for _, rec := range r.idvRecords {
		if rec.UserID != userID {
			continue
		}
		if latest == nil || rec.CreatedAt > latest.CreatedAt {
			latest = rec
		}
	}
	if latest == nil {
		return nil, nil
	}
	cp := *latest
	return &cp, nil
}

func (r *fakeRepo) UpdateIdentityVerificationStatus(_ context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return fmt.Errorf("idv: %s not found", verificationID)
	}
	rec.Status = status
	rec.RejectionReason = rejectionReason
	rec.CompletedAt = completedAtMs
	rec.UpdatedAt = updatedAtMs
	return nil
}

func (r *fakeRepo) DeleteExpiredWebAuthnChallenges(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.passkeyChallenges {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.passkeyChallenges, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredEmailVerificationTokens(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.emailVerifications {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.emailVerifications, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredPasswordResetTokens(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.passwordResets {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.passwordResets, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredEmailChangeTokens(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.emailChanges {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.emailChanges, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredLoginChallenges(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.loginChallenges {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.loginChallenges, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredOAuthOneTimeCodes(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.oauthOneTimeCodes {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.oauthOneTimeCodes, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredEmailLoginCodes(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.emailLoginCodes {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.emailLoginCodes, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredMagicLinkTokens(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.magicLinkTokens {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.magicLinkTokens, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredPhoneVerificationCodes(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.phoneVerifyCodes {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.phoneVerifyCodes, id)
			n++
		}
	}
	return nil
}

// ── Organizations ─────────────────────────────────────────────────

func (r *fakeRepo) CreateOrganization(_ context.Context, o *service.Organization) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o == nil || o.Slug == "" {
		return "", fmt.Errorf("%w: missing slug", service.ErrInvalidArgument)
	}
	for _, existing := range r.orgs {
		if existing.Slug == o.Slug {
			return "", fmt.Errorf("%w: slug %q", service.ErrAlreadyExists, o.Slug)
		}
	}
	id := nextID()
	o.ID = id
	cp := *o
	r.orgs[id] = &cp
	return id, nil
}

func (r *fakeRepo) GetOrganization(_ context.Context, orgID string) (*service.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.orgs[orgID]
	if !ok {
		return nil, nil
	}
	cp := *o
	return &cp, nil
}

func (r *fakeRepo) GetOrganizationBySlug(_ context.Context, slug string) (*service.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.orgs {
		if o.Slug == slug {
			cp := *o
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) ListOrganizationsForUser(_ context.Context, userID string) ([]*service.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.Organization
	seen := map[string]struct{}{}
	for _, m := range r.orgMembers {
		if m.UserID != userID {
			continue
		}
		if _, dup := seen[m.OrganizationID]; dup {
			continue
		}
		seen[m.OrganizationID] = struct{}{}
		o, ok := r.orgs[m.OrganizationID]
		if !ok {
			continue
		}
		cp := *o
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeRepo) AddOrganizationMember(_ context.Context, m *service.OrganizationMembership) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m == nil || m.OrganizationID == "" || m.UserID == "" {
		return "", fmt.Errorf("%w: missing organization_id or user_id", service.ErrInvalidArgument)
	}
	for _, existing := range r.orgMembers {
		if existing.OrganizationID == m.OrganizationID && existing.UserID == m.UserID {
			return "", fmt.Errorf("%w: %s already in %s", service.ErrAlreadyExists, m.UserID, m.OrganizationID)
		}
	}
	id := nextID()
	m.NodeID = id
	cp := *m
	r.orgMembers[id] = &cp
	return id, nil
}

// ── Sessions ──────────────────────────────────────────────────────────

func (r *fakeRepo) CreateSession(_ context.Context, s *service.SessionRecord) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: nil session", service.ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]*service.SessionRecord)
	}
	for _, existing := range r.sessions {
		if existing.SID == s.SID {
			return "", fmt.Errorf("%w: sid %q", service.ErrAlreadyExists, s.SID)
		}
	}
	id := nextID()
	s.NodeID = id
	cp := *s
	r.sessions[id] = &cp
	return id, nil
}

func (r *fakeRepo) GetSessionBySid(_ context.Context, sid string) (*service.SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.SID == sid {
			cp := *s
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) RevokeSession(_ context.Context, sid string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.SID == sid && s.RevokedAtMs == 0 {
			s.RevokedAtMs = atMs
		}
	}
	return nil
}

func (r *fakeRepo) RevokeSessionsForUser(_ context.Context, userID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.UserID == userID && s.RevokedAtMs == 0 {
			s.RevokedAtMs = atMs
		}
	}
	return nil
}

// seedUser inserts a user directly.
func (r *fakeRepo) seedUser(u *service.User) *service.User {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u.ID == "" {
		u.ID = nextID()
	}
	cp := *u
	r.users[u.ID] = &cp
	return &cp
}

func (r *fakeRepo) seedInvitation(inv *service.InvitationRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if inv.NodeID == "" {
		inv.NodeID = nextID()
	}
	cp := *inv
	r.invitations[inv.NodeID] = &cp
}

// ──────────────────────────────────────────────────────────────────────
// fakeDB implements service.DB.
// ──────────────────────────────────────────────────────────────────────

type fakeDB struct {
	mu    sync.Mutex
	nodes map[string]*entdb.Node
	edges []*entdb.Edge
	seq   int64
	err   error // global fault injection
}

func newFakeDB() *fakeDB {
	return &fakeDB{nodes: make(map[string]*entdb.Node)}
}

func (f *fakeDB) nextID() string {
	f.seq++
	return fmt.Sprintf("fdb-%d", f.seq)
}

func (f *fakeDB) GetNode(_ context.Context, _, _ string, typeID int, nodeID string) (*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	n, ok := f.nodes[nodeID]
	if !ok || n.TypeID != typeID {
		return nil, nil
	}
	return n, nil
}

func (f *fakeDB) QueryNodes(_ context.Context, _, _ string, typeID int, filter map[string]any) ([]*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []*entdb.Node
	for _, n := range f.nodes {
		if n.TypeID != typeID {
			continue
		}
		if matchFilter(n.Payload, filter) {
			out = append(out, n)
		}
	}
	return out, nil
}

func matchFilter(payload, filter map[string]any) bool {
	if filter == nil {
		return true
	}
	for k, v := range filter {
		pv, ok := payload[k]
		if !ok {
			return false
		}
		if fmt.Sprint(pv) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}

func (f *fakeDB) ExecuteAtomic(_ context.Context, _, _ string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var created []string
	for _, op := range ops {
		switch op.Type {
		case entdb.OpCreateNode:
			id := f.nextID()
			f.nodes[id] = &entdb.Node{
				NodeID:  id,
				TypeID:  op.TypeID,
				Payload: copyMap(op.Data),
			}
			created = append(created, id)
		case entdb.OpUpdateNode:
			n, ok := f.nodes[op.NodeID]
			if ok && n.TypeID == op.TypeID {
				for k, v := range op.Patch {
					n.Payload[k] = v
				}
			}
		case entdb.OpDeleteNode:
			delete(f.nodes, op.NodeID)
		case entdb.OpCreateEdge:
			f.edges = append(f.edges, &entdb.Edge{
				EdgeTypeID: op.EdgeTypeID,
				FromNodeID: op.FromNodeID,
				ToNodeID:   op.ToNodeID,
			})
		case entdb.OpDeleteEdge:
			var keep []*entdb.Edge
			for _, e := range f.edges {
				if e.EdgeTypeID != op.EdgeTypeID || e.FromNodeID != op.FromNodeID || e.ToNodeID != op.ToNodeID {
					keep = append(keep, e)
				}
			}
			f.edges = keep
		}
	}
	return &entdb.CommitResult{Success: true, Applied: true, CreatedNodeIDs: created}, nil
}

func (f *fakeDB) GetEdgesFrom(_ context.Context, _, _, fromNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []*entdb.Edge
	for _, e := range f.edges {
		if e.EdgeTypeID == edgeTypeID && e.FromNodeID == fromNodeID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeDB) GetEdgesTo(_ context.Context, _, _, toNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []*entdb.Edge
	for _, e := range f.edges {
		if e.EdgeTypeID == edgeTypeID && e.ToNodeID == toNodeID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeDB) SearchNodes(_ context.Context, _, _ string, typeID int, query string) ([]*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	q := strings.ToLower(query)
	var out []*entdb.Node
	for _, n := range f.nodes {
		if n.TypeID != typeID {
			continue
		}
		for _, v := range n.Payload {
			if s, ok := v.(string); ok && strings.Contains(strings.ToLower(s), q) {
				out = append(out, n)
				break
			}
		}
	}
	return out, nil
}

// RegisterUserInTenant is a no-op on the in-memory fake.
func (f *fakeDB) RegisterUserInTenant(_ context.Context, _, _, _, _, _ string) error {
	return nil
}

// ── seed helpers ──

func (f *fakeDB) addUser(id, email, name, role, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id,
		TypeID: tTypeUser,
		Payload: map[string]any{
			tUfEmail:  email,
			tUfName:   name,
			tUfRole:   role,
			tUfStatus: status,
		},
	}
}

func (f *fakeDB) addUserWithPassword(id, email, name, role, status, pwHash string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id,
		TypeID: tTypeUser,
		Payload: map[string]any{
			tUfEmail:        email,
			tUfName:         name,
			tUfRole:         role,
			tUfStatus:       status,
			tUfPasswordHash: pwHash,
		},
	}
}

func (f *fakeDB) addHelpRequest(id, email, status string, createdAt int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id,
		TypeID: tTypeAdminHelpReq,
		Payload: map[string]any{
			tHfEmail:     email,
			tHfStatus:    status,
			tHfCreatedAt: createdAt,
		},
	}
}

func (f *fakeDB) addRefreshToken(id, userID string, expiresAt int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id,
		TypeID: tTypeRefreshToken,
		Payload: map[string]any{
			tRfUserID:    userID,
			tRfExpiresAt: expiresAt,
			tRfCreatedAt: time.Now().UnixMilli(),
		},
	}
}

func (f *fakeDB) addPasskey(id, userID, credentialID, deviceName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id,
		TypeID: tTypePasskeyCredCred,
		Payload: map[string]any{
			tPkfCredentialID: credentialID,
			tPkfUserID:       userID,
			tPkfDeviceName:   deviceName,
		},
	}
}

func copyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ──────────────────────────────────────────────────────────────────────
// Test harness — wires real services + fakes behind a Connect HTTP server.
// ──────────────────────────────────────────────────────────────────────

type testHarness struct {
	repo   *fakeRepo
	db     *fakeDB
	auth   *service.AuthService
	admin  *service.AdminService
	groups *service.GroupService
	help   *service.HelpService
	prof   *service.ProfileService
	cfg    *config.Config

	server *httptest.Server
	client identityconnect.IdentityServiceClient
}

func testConfig() *config.Config {
	// #nosec G101 -- test configuration field names contain password/passkey labels.
	return &config.Config{
		DefaultTenantID:                 "test-tenant",
		IdentityMode:                    config.IdentityModeSingle,
		AuthAllowLocal:                  true,
		PasswordSignupEnabled:           true,
		PasswordResetEnabled:            true,
		PasswordlessSignupEnabled:       true,
		PasswordlessCodeTTLSeconds:      300,
		PasswordlessCodeMaxAttempts:     5,
		PasswordlessMagicLinkTTLSeconds: 900,
		OAuthAllowedReturnURLs:          "https://app.test/",
		JWTExpirySeconds:                900,
		RefreshExpirySeconds:            604800,
		LoginMaxFailedAttempts:          5,
		LoginLockoutSeconds:             900,
		LoginChallengeExpirySeconds:     300,
		PasskeyRPID:                     "localhost",
		PasskeyRPName:                   "Test",
		PasskeyOrigin:                   "http://localhost:9002",
		PasskeyChallengeExpirySeconds:   300,
		QRLoginBaseURL:                  "http://localhost:9002",
		QRLoginExpirySeconds:            300,
		TOTPIssuer:                      "Test",
		PasswordResetExpirySeconds:      3600,
	}
}

func testKeyRing(t *testing.T) *jwttest.Signer {
	t.Helper()
	return jwttest.NewSigner(t, "test-kid")
}

// newHarness builds a complete handler stack and exposes both an in-process
// connect client and the underlying fakes for assertions.
func newHarness(t *testing.T) *testHarness {
	t.Helper()
	return newHarnessWith(t, nil, nil, nil)
}

func newHarnessWithOAuthRegistry(t *testing.T, registry *oauth.Registry) *testHarness {
	t.Helper()
	return newHarnessWith(t, registry, nil, nil)
}

// newHarnessWithCaptcha builds a harness whose handler enforces CAPTCHA via
// the supplied verifier and a config produced by mutating testConfig (so a
// test can flip CaptchaEnabled and the per-endpoint toggles). A nil mutate
// leaves the default config; a nil verifier exercises the disabled path.
func newHarnessWithCaptcha(t *testing.T, verifier captcha.Verifier, mutate func(*config.Config)) *testHarness {
	t.Helper()
	return newHarnessWith(t, nil, verifier, mutate)
}

func newHarnessWith(
	t *testing.T,
	registry *oauth.Registry,
	captchaVerifier captcha.Verifier,
	mutate func(*config.Config),
) *testHarness {
	t.Helper()

	repo := newFakeRepo()
	db := newFakeDB()
	cfg := testConfig()
	if mutate != nil {
		mutate(cfg)
	}
	kr := testKeyRing(t)

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("passkey svc: %v", err)
	}

	auditLog := audit.NewLogger(nil, "test", zap.NewNop())
	totpKey := []byte("01234567890123456789012345678901")
	totpRecoveryPepper := []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH")

	authSvc := service.NewAuthServiceWithOAuth(repo, cfg, kr, pkSvc, auditLog, totpKey, totpRecoveryPepper, nil, nil, zap.NewNop(), registry)
	adminSvc := service.NewAdminService(repo, db, cfg.DefaultTenantID, auditLog, cfg, nil, zap.NewNop())
	groupSvc := service.NewGroupService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	helpSvc := service.NewHelpService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	profSvc := service.NewProfileService(repo, db, cfg.DefaultTenantID, auditLog, zap.NewNop())

	h := NewIdentityHandler(authSvc, adminSvc, groupSvc, helpSvc, profSvc, nil, nil, captchaVerifier, cfg)

	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL)

	return &testHarness{
		repo:   repo,
		db:     db,
		auth:   authSvc,
		admin:  adminSvc,
		groups: groupSvc,
		help:   helpSvc,
		prof:   profSvc,
		cfg:    cfg,
		server: srv,
		client: client,
	}
}

// authedReq attaches the X-Authenticated-User-Id header to a connect request.
func authedReq[T any](r *connect.Request[T], userID string) *connect.Request[T] {
	r.Header().Set("X-Authenticated-User-Id", userID)
	return r
}

// withClientHeaders attaches IP / UA headers (used by handlers that read them).
func withClientHeaders[T any](r *connect.Request[T]) *connect.Request[T] {
	r.Header().Set("X-Forwarded-For", "10.0.0.1")
	r.Header().Set("User-Agent", "test-agent/1.0")
	return r
}

// Simple sanity helpers used across tests.

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hashInvitation matches service.hashInvitationToken (sha-256 hex of raw).
func hashInvitation(raw string) string { return sha256Hex(raw) }

// connectCodeOf returns the connect code of err, or 0 when err is nil
// (helpful to assert on non-connect errors as well).
func connectCodeOf(err error) connect.Code {
	if err == nil {
		return 0
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return connect.CodeUnknown
}
