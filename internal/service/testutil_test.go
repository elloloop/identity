package service

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passkeys"
)

// ── fakeRepo ───────────────────────────────────────────────────────────
// In-memory implementation of Repository for testing.

var nodeIDCounter atomic.Int64

func nextNodeID() string {
	return "node-" + strconv.FormatInt(nodeIDCounter.Add(1), 10)
}

type fakeRepo struct {
	mu sync.Mutex

	users             map[string]*User
	refreshTokens     map[string]*RefreshTokenRecord
	passkeyCreds      map[string]*PasskeyCredRecord
	passkeyChallenges map[string]*PasskeyChallengeRecord
	qrSessions        map[string]*QrLoginSessionRecord
	totpCreds         map[string]*TotpCredRecord
	recoveryCodes     map[string]*RecoveryCodeRecord
	loginChallenges   map[string]*LoginChallengeRecord
	invitations       map[string]*InvitationRecord
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:             make(map[string]*User),
		refreshTokens:     make(map[string]*RefreshTokenRecord),
		passkeyCreds:      make(map[string]*PasskeyCredRecord),
		passkeyChallenges: make(map[string]*PasskeyChallengeRecord),
		qrSessions:        make(map[string]*QrLoginSessionRecord),
		totpCreds:         make(map[string]*TotpCredRecord),
		recoveryCodes:     make(map[string]*RecoveryCodeRecord),
		loginChallenges:   make(map[string]*LoginChallengeRecord),
		invitations:       make(map[string]*InvitationRecord),
	}
}

// ── Users ──────────────────────────────────────────────────────────────

func (r *fakeRepo) FindUserByEmail(_ context.Context, email string) (*User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) GetUser(_ context.Context, userID string) (*User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (r *fakeRepo) CreateUser(_ context.Context, u *User) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.users {
		if existing.Email == u.Email {
			return "", fmt.Errorf("user with email %s already exists", u.Email)
		}
	}
	id := nextNodeID()
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
	applyUserFields(u, fields)
	return nil
}

func applyUserFields(u *User, fields map[string]any) {
	for k, v := range fields {
		switch k {
		case "name":
			u.Name = v.(string)
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
			switch x := v.(type) {
			case int64:
				u.UpdatedAt = time.UnixMilli(x)
			}
		case "last_login_at":
			switch x := v.(type) {
			case int64:
				u.LastLoginAtMs = x
			}
		case "recovery_email":
			u.RecoveryEmail = v.(string)
		}
	}
}

// ── Refresh Tokens ─────────────────────────────────────────────────────

func (r *fakeRepo) FindRefreshTokenByHash(_ context.Context, hash string) (*RefreshTokenRecord, error) {
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

func (r *fakeRepo) CreateRefreshToken(_ context.Context, rec *RefreshTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
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

// ── Passkey Credentials ────────────────────────────────────────────────

func (r *fakeRepo) ListPasskeyCredentials(_ context.Context, userID string) ([]*PasskeyCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*PasskeyCredRecord
	for _, c := range r.passkeyCreds {
		if c.UserID == userID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeRepo) GetPasskeyCredentialByCredID(_ context.Context, credentialID string) (*PasskeyCredRecord, error) {
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

func (r *fakeRepo) CreatePasskeyCredential(_ context.Context, rec *PasskeyCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
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
		return fmt.Errorf("passkey credential %s not found", nodeID)
	}
	if v, ok := fields["sign_count"]; ok {
		c.SignCount = v.(int64)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt = v.(int64)
	}
	return nil
}

// ── Passkey Challenges ─────────────────────────────────────────────────

func (r *fakeRepo) GetPasskeyChallenge(_ context.Context, nodeID string) (*PasskeyChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *fakeRepo) CreatePasskeyChallenge(_ context.Context, rec *PasskeyChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
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

// ── QR Login Sessions ──────────────────────────────────────────────────

func (r *fakeRepo) FindQrLoginSession(_ context.Context, sessionID string) (*QrLoginSessionRecord, error) {
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

func (r *fakeRepo) CreateQrLoginSession(_ context.Context, rec *QrLoginSessionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
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

// ── TOTP Credentials ───────────────────────────────────────────────────

func (r *fakeRepo) GetTotpCredential(_ context.Context, userID string) (*TotpCredRecord, error) {
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

func (r *fakeRepo) CreateTotpCredential(_ context.Context, rec *TotpCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
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
		return fmt.Errorf("totp credential %s not found", nodeID)
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

// ── Recovery Codes ─────────────────────────────────────────────────────

func (r *fakeRepo) CreateRecoveryCode(_ context.Context, rec *RecoveryCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.recoveryCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) FindRecoveryCodeByHash(_ context.Context, userID, hash string) (*RecoveryCodeRecord, error) {
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

// ── Login Challenges ───────────────────────────────────────────────────

func (r *fakeRepo) CreateLoginChallenge(_ context.Context, rec *LoginChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.loginChallenges[id] = &cp
	return id, nil
}

func (r *fakeRepo) GetLoginChallengeByChallengeID(_ context.Context, challengeID string) (*LoginChallengeRecord, error) {
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

// ── Invitations ────────────────────────────────────────────────────────

func (r *fakeRepo) FindInvitationByHash(_ context.Context, tokenHash string) (*InvitationRecord, error) {
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

// ── Test helpers ───────────────────────────────────────────────────────

func testConfig() *config.Config {
	return &config.Config{
		DefaultTenantID:               "test-tenant",
		AuthAllowLocal:                true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "Test",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Glassa Test",
	}
}

func testKeyRing(t *testing.T) *jwt.KeyRing {
	t.Helper()
	sk, err := jwt.GenerateKey("test-kid")
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	kr, err := jwt.NewKeyRing([]jwt.SigningKey{sk})
	if err != nil {
		t.Fatalf("creating test key ring: %v", err)
	}
	return kr
}

func testTotpKey() []byte {
	return []byte("01234567890123456789012345678901") // 32 bytes
}

func newTestAuthService(t *testing.T, repo *fakeRepo) *AuthService {
	t.Helper()
	cfg := testConfig()
	kr := testKeyRing(t)

	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})

	return NewAuthService(repo, cfg, kr, passkeysSvc, audit.NewLogger(nil, "test", nil), testTotpKey(), zap.NewNop())
}

func newTestAuthServiceWithTime(t *testing.T, repo *fakeRepo, nowFn func() time.Time) *AuthService {
	t.Helper()
	svc := newTestAuthService(t, repo)
	svc.nowFunc = nowFn
	return svc
}

// seedUser creates a user directly in the fake repo.
func seedUser(repo *fakeRepo, email, passwordHash, status string) *User {
	id := nextNodeID()
	u := &User{
		ID:           id,
		Email:        email,
		Name:         email,
		Role:         "member",
		Status:       status,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	repo.mu.Lock()
	repo.users[id] = u
	repo.mu.Unlock()
	return u
}

// seedUserFull creates a user with all fields populated.
func seedUserFull(repo *fakeRepo, u *User) {
	repo.mu.Lock()
	if u.ID == "" {
		u.ID = nextNodeID()
	}
	cp := *u
	repo.users[u.ID] = &cp
	repo.mu.Unlock()
}

// seedInvitation creates an invitation directly in the fake repo.
func seedInvitation(repo *fakeRepo, inv *InvitationRecord) {
	repo.mu.Lock()
	if inv.NodeID == "" {
		inv.NodeID = nextNodeID()
	}
	cp := *inv
	repo.invitations[inv.NodeID] = &cp
	repo.mu.Unlock()
}
