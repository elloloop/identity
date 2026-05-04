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

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// recordingAuditWriter implements audit.NodeWriter and captures the
// audit events emitted by the service so tests can assert on them.
// Event type lives at field "1" of the Data map (see pkg/audit/logger.go).
type recordingAuditWriter struct {
	mu     sync.Mutex
	events []string
}

func newRecordingAuditWriter() *recordingAuditWriter {
	return &recordingAuditWriter{}
}

func (w *recordingAuditWriter) ExecuteAtomic(
	_ context.Context, _, _, _ string, ops []entdb.Operation,
) (*entdb.CommitResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, op := range ops {
		if et, ok := op.Data["1"].(string); ok {
			w.events = append(w.events, et)
		}
	}
	return &entdb.CommitResult{}, nil
}

func (w *recordingAuditWriter) countByEventType(eventType string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, et := range w.events {
		if et == eventType {
			n++
		}
	}
	return n
}

// newTestAuthServiceWithAudit builds an AuthService whose audit logger
// writes to the supplied recordingAuditWriter so tests can assert on
// emitted audit events.
func newTestAuthServiceWithAudit(t *testing.T, repo *fakeRepo, writer *recordingAuditWriter) *AuthService {
	t.Helper()
	cfg := testConfig()
	kr := testKeyRing(t)
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, kr, passkeysSvc,
		audit.NewLogger(writer, "test-tenant", nil),
		testTotpKey(), email.NewLogOnly(zap.NewNop()), zap.NewNop(),
		defaultTestOAuthRegistry(),
	)
}

// ── fakeRepo ───────────────────────────────────────────────────────────
// In-memory implementation of Repository for testing.

var nodeIDCounter atomic.Int64

func nextNodeID() string {
	return "node-" + strconv.FormatInt(nodeIDCounter.Add(1), 10)
}

type fakeRepo struct {
	mu sync.Mutex

	// incrementErrCount, when > 0, causes the next N
	// IncrementFailedLoginCount calls to return an error. Set this
	// from a test to exercise the fail-closed path; subsequent calls
	// (after the counter decrements to 0) succeed normally.
	incrementErrCount int

	users              map[string]*User
	refreshTokens      map[string]*RefreshTokenRecord
	passkeyCreds       map[string]*PasskeyCredRecord
	passkeyChallenges  map[string]*PasskeyChallengeRecord
	qrSessions         map[string]*QrLoginSessionRecord
	totpCreds          map[string]*TotpCredRecord
	recoveryCodes      map[string]*RecoveryCodeRecord
	loginChallenges    map[string]*LoginChallengeRecord
	invitations        map[string]*InvitationRecord
	passwordResets     map[string]*PasswordResetToken
	emailVerifications map[string]*EmailVerificationToken
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:              make(map[string]*User),
		refreshTokens:      make(map[string]*RefreshTokenRecord),
		passkeyCreds:       make(map[string]*PasskeyCredRecord),
		passkeyChallenges:  make(map[string]*PasskeyChallengeRecord),
		qrSessions:         make(map[string]*QrLoginSessionRecord),
		totpCreds:          make(map[string]*TotpCredRecord),
		recoveryCodes:      make(map[string]*RecoveryCodeRecord),
		loginChallenges:    make(map[string]*LoginChallengeRecord),
		invitations:        make(map[string]*InvitationRecord),
		passwordResets:     make(map[string]*PasswordResetToken),
		emailVerifications: make(map[string]*EmailVerificationToken),
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

// failOnceFailedLoginIncrement, when non-zero, makes the next N
// IncrementFailedLoginCount calls return an error. Used by tests to
// exercise the fail-closed path.
func (r *fakeRepo) IncrementFailedLoginCount(_ context.Context, userID string) (int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.incrementErrCount > 0 {
		r.incrementErrCount--
		return 0, fmt.Errorf("simulated increment failure")
	}
	u, ok := r.users[userID]
	if !ok {
		return 0, fmt.Errorf("user %s not found", userID)
	}
	u.FailedLoginCount++
	return int32(u.FailedLoginCount), nil
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
		case "email_verified":
			if b, ok := v.(bool); ok {
				u.EmailVerified = b
			}
		case "email_verified_at":
			switch x := v.(type) {
			case int64:
				u.EmailVerifiedAt = x
			case int:
				u.EmailVerifiedAt = int64(x)
			}
		}
	}
}

// ── Refresh Tokens ─────────────────────────────────────────────────────

func (r *fakeRepo) FindRefreshTokenByHash(_ context.Context, hash string) (*RefreshTokenRecord, error) {
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

func (r *fakeRepo) FindRefreshTokenByHashIncludingConsumed(_ context.Context, hash string) (*RefreshTokenRecord, error) {
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

// ConsumeRefreshTokenByHash atomically marks the row consumed; returns
// ErrUnauthenticated if the row is absent or already consumed so
// concurrent rotations resolve to exactly one winner.
func (r *fakeRepo) ConsumeRefreshTokenByHash(_ context.Context, hash string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash {
			if t.ConsumedAtMs != 0 {
				return ErrUnauthenticated
			}
			t.ConsumedAtMs = atMs
			return nil
		}
	}
	return ErrUnauthenticated
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
	return newTestAuthServiceWithRegistry(t, repo, defaultTestOAuthRegistry())
}

// newTestAuthServiceNoOAuth builds an AuthService without an OAuth
// registry — used to exercise the ErrOAuthDisabled path.
func newTestAuthServiceNoOAuth(t *testing.T, repo *fakeRepo) *AuthService {
	t.Helper()
	return newTestAuthServiceWithRegistry(t, repo, nil)
}

func newTestAuthServiceWithRegistry(t *testing.T, repo *fakeRepo, reg *oauth.Registry) *AuthService {
	t.Helper()
	cfg := testConfig()
	kr := testKeyRing(t)

	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})

	return NewAuthServiceWithOAuth(
		repo, cfg, kr, passkeysSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), email.NewLogOnly(zap.NewNop()), zap.NewNop(),
		reg,
	)
}

// fakeOAuthExchanger is a deterministic Exchanger used in service-layer
// tests. It encodes the desired Identity in the authorization code so
// each test can express different scenarios without setting up an HTTP
// fake. Codes can take these forms:
//
//	"ok|<email>|<name>|<avatar>|<provider>"  → success
//	"err|<reason>"                            → returns ErrCodeExchangeFailed
//	"unverified|<email>"                      → returns ErrEmailNotVerified
type fakeOAuthExchanger struct {
	provider string
	calls    atomic.Int32
}

func (f *fakeOAuthExchanger) Exchange(_ context.Context, code, _ string) (*oauth.Identity, error) {
	f.calls.Add(1)
	parts := splitCode(code)
	switch parts[0] {
	case "ok":
		return &oauth.Identity{
			ProviderUserID: "sub-" + parts[1],
			Email:          parts[1],
			EmailVerified:  true,
			Name:           parts[2],
			AvatarURL:      parts[3],
			Provider:       parts[4],
		}, nil
	case "unverified":
		return nil, oauth.ErrEmailNotVerified
	case "err":
		return nil, oauth.ErrCodeExchangeFailed
	default:
		return nil, oauth.ErrCodeExchangeFailed
	}
}

func splitCode(code string) []string {
	out := []string{"", "", "", "", ""}
	cur := 0
	last := 0
	for i := 0; i < len(code); i++ {
		if code[i] == '|' {
			if cur < len(out) {
				out[cur] = code[last:i]
				cur++
				last = i + 1
			}
		}
	}
	if cur < len(out) {
		out[cur] = code[last:]
	}
	return out
}

// defaultTestOAuthRegistry returns a registry pre-populated with a
// fakeOAuthExchanger for "google", "microsoft", and "github" so the
// existing test suite continues to work after the OAuthLogin signature
// change.
func defaultTestOAuthRegistry() *oauth.Registry {
	r := oauth.NewRegistry()
	for _, p := range []string{"google", "microsoft", "github"} {
		r.Register(p, &fakeOAuthExchanger{provider: p})
	}
	return r
}

// fakeOAuthCode builds a code string matching fakeOAuthExchanger's
// "ok" form. Helper for test readability.
func fakeOAuthCode(email, name, avatar, provider string) string {
	return "ok|" + email + "|" + name + "|" + avatar + "|" + provider
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

// ── Password Reset Tokens ──────────────────────────────────────────────

func (r *fakeRepo) CreatePasswordResetToken(_ context.Context, t *PasswordResetToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	t.NodeID = id
	cp := *t
	r.passwordResets[id] = &cp
	return nil
}

func (r *fakeRepo) FindPasswordResetTokenByHash(_ context.Context, hash string) (*PasswordResetToken, error) {
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

// ── Email Verification Tokens ──────────────────────────────────────────

func (r *fakeRepo) CreateEmailVerificationToken(_ context.Context, t *EmailVerificationToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	t.NodeID = id
	cp := *t
	r.emailVerifications[id] = &cp
	return nil
}

func (r *fakeRepo) FindEmailVerificationTokenByHash(_ context.Context, hash string) (*EmailVerificationToken, error) {
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
