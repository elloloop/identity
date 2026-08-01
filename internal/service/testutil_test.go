package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/graph"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// recordingAuditWriter implements audit.NodeWriter and captures the
// audit events emitted by the service so tests can assert on them.
// Event type lives at field "1" of the Data map, and the JSON-encoded
// WithDetails map at field "7" (see pkg/audit/logger.go).
type recordingAuditWriter struct {
	mu      sync.Mutex
	events  []string
	details []string // JSON details ("7"), index-aligned with events
}

func newRecordingAuditWriter() *recordingAuditWriter {
	return &recordingAuditWriter{}
}

func (w *recordingAuditWriter) ExecuteAtomic(
	_ context.Context, _, _ string, ops []graph.Operation,
) (*graph.CommitResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, op := range ops {
		if et, ok := op.Data["1"].(string); ok {
			w.events = append(w.events, et)
			detail, _ := op.Data["7"].(string)
			w.details = append(w.details, detail)
		}
	}
	return &graph.CommitResult{}, nil
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

// countByEventTypeAndDetail counts recorded events of eventType whose
// JSON-encoded WithDetails map maps key to want (a string value).
func (w *recordingAuditWriter) countByEventTypeAndDetail(eventType, key, want string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for i, et := range w.events {
		if et != eventType {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(w.details[i]), &m) != nil {
			continue
		}
		if v, ok := m[key].(string); ok && v == want {
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
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
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

	// createUserHook, when set, runs at the very start of CreateUser
	// (before the duplicate-email check). A test uses it to inject a
	// concurrent insert and exercise the lost-create-race path: seeding a
	// user with the same email here makes the subsequent insert fail the
	// uniqueness check exactly as a racing winner would.
	createUserHook func()

	// The following, when non-nil, make the corresponding read/write return
	// that error so a test can exercise the caller's repo-error-propagation
	// path. Default nil (success).
	getPasskeyChallengeErr error
	updateCounterErr       error
	consumeChallengeErr    error
	createChallengeErr     error
	findUserByEmailErr     error
	createPasskeyCredErr   error
	getUserErr             error
	getTotpCredentialErr   error

	users               map[string]*User
	refreshTokens       map[string]*RefreshTokenRecord
	passkeyCreds        map[string]*PasskeyCredRecord
	passkeyChallenges   map[string]*PasskeyChallengeRecord
	attestedDevices     map[string]*AttestedDeviceRecord
	assuranceChallenges map[string]*AssuranceChallengeRecord
	qrSessions          map[string]*QrLoginSessionRecord
	oauthOneTimeCodes   map[string]*OAuthOneTimeCodeRecord
	nativeRedemptions   map[string]*NativeTokenRedemptionRecord
	emailLoginCodes     map[string]*EmailLoginCodeRecord
	magicLinkTokens     map[string]*MagicLinkTokenRecord
	phoneVerifyCodes    map[string]*PhoneVerificationCodeRecord
	totpCreds           map[string]*TotpCredRecord
	recoveryCodes       map[string]*RecoveryCodeRecord
	loginChallenges     map[string]*LoginChallengeRecord
	invitations         map[string]*InvitationRecord
	passwordResets      map[string]*PasswordResetToken
	emailVerifications  map[string]*EmailVerificationToken
	emailChanges        map[string]*EmailChangeToken
	oauthIdentities     map[string]*OAuthIdentity
	idvRecords          map[string]*IdentityVerificationRecord
	sessions            map[string]*SessionRecord
	auditEvents         []*AuditEvent
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:              make(map[string]*User),
		refreshTokens:      make(map[string]*RefreshTokenRecord),
		passkeyCreds:       make(map[string]*PasskeyCredRecord),
		passkeyChallenges:  make(map[string]*PasskeyChallengeRecord),
		qrSessions:         make(map[string]*QrLoginSessionRecord),
		oauthOneTimeCodes:  make(map[string]*OAuthOneTimeCodeRecord),
		nativeRedemptions:  make(map[string]*NativeTokenRedemptionRecord),
		emailLoginCodes:    make(map[string]*EmailLoginCodeRecord),
		magicLinkTokens:    make(map[string]*MagicLinkTokenRecord),
		phoneVerifyCodes:   make(map[string]*PhoneVerificationCodeRecord),
		totpCreds:          make(map[string]*TotpCredRecord),
		recoveryCodes:      make(map[string]*RecoveryCodeRecord),
		loginChallenges:    make(map[string]*LoginChallengeRecord),
		invitations:        make(map[string]*InvitationRecord),
		passwordResets:     make(map[string]*PasswordResetToken),
		emailVerifications: make(map[string]*EmailVerificationToken),
		emailChanges:       make(map[string]*EmailChangeToken),
		oauthIdentities:    make(map[string]*OAuthIdentity),
		idvRecords:         make(map[string]*IdentityVerificationRecord),
		sessions:           make(map[string]*SessionRecord),
	}
}

// ── Users ──────────────────────────────────────────────────────────────

func (r *fakeRepo) FindUserByEmail(_ context.Context, email string) (*User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.findUserByEmailErr != nil {
		return nil, r.findUserByEmailErr
	}
	// The empty address matches nobody, mirroring every real driver's early
	// return. Without it an anonymous user (Email == "") is resolvable by a
	// lookup for "".
	if email == "" {
		return nil, nil
	}
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
	if r.getUserErr != nil {
		return nil, r.getUserErr
	}
	u, ok := r.users[userID]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (r *fakeRepo) ListUsers(_ context.Context, filter UserListFilter) ([]*User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*User
	for _, u := range r.users {
		if filter.Email != "" && !strings.EqualFold(u.Email, filter.Email) {
			continue
		}
		if filter.ExternalID != "" && u.ExternalID != filter.ExternalID {
			continue
		}
		cp := *u
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeRepo) ListUsersPendingDeletionBefore(_ context.Context, cutoffMs int64, limit int) ([]*User, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("fakeRepo: ListUsersPendingDeletionBefore: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	matched := make([]*User, 0)
	for _, u := range r.users {
		if u.Status != StatusPendingDeletion {
			continue
		}
		if u.DeletionScheduledAtMs <= 0 || u.DeletionScheduledAtMs > cutoffMs {
			continue
		}
		cp := *u
		matched = append(matched, &cp)
	}
	r.mu.Unlock()
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].DeletionScheduledAtMs != matched[j].DeletionScheduledAtMs {
			return matched[i].DeletionScheduledAtMs < matched[j].DeletionScheduledAtMs
		}
		return matched[i].ID < matched[j].ID
	})
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, nil
}

func (r *fakeRepo) CountUsers(_ context.Context, filter UserListFilter) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, u := range r.users {
		if filter.Email != "" && !strings.EqualFold(u.Email, filter.Email) {
			continue
		}
		if filter.ExternalID != "" && u.ExternalID != filter.ExternalID {
			continue
		}
		n++
	}
	return n, nil
}

func (r *fakeRepo) CreateUser(_ context.Context, u *User) (string, error) {
	if r.createUserHook != nil {
		r.createUserHook()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.users {
		// Mirrors the drivers' PARTIAL unique index (WHERE email <> ''):
		// users without an address — every anonymous user — never collide.
		if u.Email != "" && existing.Email == u.Email {
			return "", fmt.Errorf("%w: user with email %s already exists", ErrAlreadyExists, u.Email)
		}
	}
	id := u.ID
	if id == "" {
		id = nextNodeID()
	}
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
		return 0, errors.New("simulated increment failure")
	}
	u, ok := r.users[userID]
	if !ok {
		return 0, fmt.Errorf("user %s not found", userID)
	}
	if u.FailedLoginCount >= int(maxInt32) {
		return 0, fmt.Errorf("failed login count overflow for user %s", userID)
	}
	u.FailedLoginCount++
	return int32(u.FailedLoginCount), nil // #nosec G115 -- bounds checked above.
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
		case "email":
			u.Email = v.(string)
		case "avatar_url":
			u.AvatarURL = v.(string)
		case "is_anonymous":
			if b, ok := v.(bool); ok {
				u.IsAnonymous = b
			}
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
		case "deletion_scheduled_at_ms":
			switch x := v.(type) {
			case int64:
				u.DeletionScheduledAtMs = x
			case int:
				u.DeletionScheduledAtMs = int64(x)
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

// DeleteUser mirrors the memory cascade over the fake's maps so the
// service-layer DeleteUser tests can assert the cascade ran. Audit
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
	delete(r.users, userID)
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
	if r.createPasskeyCredErr != nil {
		return "", r.createPasskeyCredErr
	}
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

func (r *fakeRepo) DeletePasskeyCredentialsForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.passkeyCreds {
		if c.UserID == userID {
			delete(r.passkeyCreds, id)
		}
	}
	return nil
}

// ── Passkey Challenges ─────────────────────────────────────────────────

func (r *fakeRepo) GetPasskeyChallenge(_ context.Context, nodeID string) (*PasskeyChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getPasskeyChallengeErr != nil {
		return nil, r.getPasskeyChallengeErr
	}
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

func (r *fakeRepo) ConsumeQrLoginSession(_ context.Context, nodeID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.qrSessions[nodeID]
	if !ok {
		return ErrQrLoginNotPending
	}
	if s.Status != "approved" {
		return ErrQrLoginNotPending
	}
	s.Status = "consumed"
	s.UpdatedAt = atMs
	return nil
}

func (r *fakeRepo) CreateOAuthOneTimeCode(_ context.Context, rec *OAuthOneTimeCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.oauthOneTimeCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) ConsumeOAuthOneTimeCode(_ context.Context, codeHash string, atMs int64) (*OAuthOneTimeCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.oauthOneTimeCodes {
		if c.CodeHash != codeHash {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, ErrOAuthCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, ErrOAuthCodeInvalid
}

func (r *fakeRepo) RecordNativeTokenRedemption(_ context.Context, rec *NativeTokenRedemptionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.nativeRedemptions {
		if e.ReplayKey == rec.ReplayKey {
			return "", ErrNativeTokenReplayed
		}
	}
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.nativeRedemptions[id] = &cp
	return id, nil
}

func (r *fakeRepo) UpsertEmailLoginCode(_ context.Context, rec *EmailLoginCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.emailLoginCodes {
		if c.Email == rec.Email {
			delete(r.emailLoginCodes, id)
		}
	}
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.emailLoginCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) FindEmailLoginCodeByEmail(_ context.Context, email string) (*EmailLoginCodeRecord, error) {
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

func (r *fakeRepo) ConsumeEmailLoginCode(_ context.Context, email string, atMs int64) (*EmailLoginCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.emailLoginCodes {
		if c.Email != email {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, ErrEmailLoginCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, ErrEmailLoginCodeInvalid
}

func (r *fakeRepo) CreateMagicLinkToken(_ context.Context, rec *MagicLinkTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.magicLinkTokens[id] = &cp
	return id, nil
}

func (r *fakeRepo) ConsumeMagicLinkToken(_ context.Context, tokenHash string, atMs int64) (*MagicLinkTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.magicLinkTokens {
		if t.TokenHash != tokenHash {
			continue
		}
		if t.ConsumedAt != 0 || t.ExpiresAt <= atMs {
			return nil, ErrMagicLinkInvalid
		}
		t.ConsumedAt = atMs
		cp := *t
		return &cp, nil
	}
	return nil, ErrMagicLinkInvalid
}

func (r *fakeRepo) UpsertPhoneVerificationCode(_ context.Context, rec *PhoneVerificationCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.phoneVerifyCodes {
		if c.UserID == rec.UserID {
			delete(r.phoneVerifyCodes, id)
		}
	}
	id := nextNodeID()
	rec.NodeID = id
	cp := *rec
	r.phoneVerifyCodes[id] = &cp
	return id, nil
}

func (r *fakeRepo) FindPhoneVerificationCodeByUser(_ context.Context, userID string) (*PhoneVerificationCodeRecord, error) {
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

func (r *fakeRepo) ConsumePhoneVerificationCode(_ context.Context, userID string, atMs int64) (*PhoneVerificationCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.phoneVerifyCodes {
		if c.UserID != userID {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, ErrPhoneCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, ErrPhoneCodeInvalid
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

// ── TOTP Credentials ───────────────────────────────────────────────────

func (r *fakeRepo) GetTotpCredential(_ context.Context, userID string) (*TotpCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getTotpCredentialErr != nil {
		return nil, r.getTotpCredentialErr
	}
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
	// #nosec G101 -- test configuration field names contain password/passkey labels.
	return &config.Config{
		DefaultTenantID:                 "test-tenant",
		AuthAllowLocal:                  true,
		PasswordSignupEnabled:           true,
		PasswordResetEnabled:            true,
		PasswordlessSignupEnabled:       true,
		PasswordlessCodeTTLSeconds:      300,
		PasswordlessCodeMaxAttempts:     5,
		PasswordlessMagicLinkTTLSeconds: 900,
		JWTExpirySeconds:                900,
		RefreshExpirySeconds:            604800,
		LoginMaxFailedAttempts:          5,
		LoginLockoutSeconds:             900,
		LoginChallengeExpirySeconds:     300,
		PasskeyRPID:                     "localhost",
		PasskeyRPName:                   "Test",
		PasskeyOrigin:                   "http://localhost:9002",
		PasskeyChallengeExpirySeconds:   300,
		PasskeySignupEnabled:            true,
		QRLoginBaseURL:                  "http://localhost:9002",
		QRLoginExpirySeconds:            300,
		TOTPIssuer:                      "Glassa Test",
	}
}

func testKeyRing(t *testing.T) *jwttest.Signer {
	t.Helper()
	return jwttest.NewSigner(t, "test-kid")
}

func testTotpKey() []byte {
	return []byte("01234567890123456789012345678901") // 32 bytes
}

// testTotpRecoveryPepper returns a 32-byte deterministic pepper used
// in unit tests. Recovery-code hashes computed with this pepper are
// stable across runs so fixtures can hard-code them.
func testTotpRecoveryPepper() []byte {
	return []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH") // 40 bytes
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
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
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

func (f *fakeOAuthExchanger) Exchange(_ context.Context, params oauth.ExchangeParams) (*oauth.Identity, error) {
	f.calls.Add(1)
	parts := splitCode(params.Code)
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

func (f *fakeOAuthExchanger) AuthorizationURL(_ context.Context, redirectURI, state, codeChallenge string) (string, error) {
	params := url.Values{}
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("provider", f.provider)
	return "https://oauth.test/authorize?" + params.Encode(), nil
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

// defaultTestOAuthRegistry returns the providers exercised by service tests.
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

// ── Email Change Tokens ────────────────────────────────────────────────

func (r *fakeRepo) CreateEmailChangeToken(_ context.Context, t *EmailChangeToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := nextNodeID()
	t.NodeID = id
	cp := *t
	r.emailChanges[id] = &cp
	return nil
}

func (r *fakeRepo) FindEmailChangeTokenByHash(_ context.Context, hash string) (*EmailChangeToken, error) {
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

// ── OAuth Identities ───────────────────────────────────────────────────

func (r *fakeRepo) FindUserByProviderID(_ context.Context, provider, providerUserID string) (*User, error) {
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

func (r *fakeRepo) CreateOAuthIdentity(_ context.Context, oi *OAuthIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Application-enforced uniqueness: (provider, provider_user_id).
	for _, existing := range r.oauthIdentities {
		if existing.Provider == oi.Provider && existing.ProviderUserID == oi.ProviderUserID {
			return fmt.Errorf("oauth identity already linked: %s/%s", oi.Provider, oi.ProviderUserID)
		}
	}
	id := nextNodeID()
	oi.NodeID = id
	cp := *oi
	r.oauthIdentities[id] = &cp
	return nil
}

func (r *fakeRepo) ListOAuthIdentitiesForUser(_ context.Context, userID string) ([]*OAuthIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*OAuthIdentity
	for _, oi := range r.oauthIdentities {
		if oi.UserID == userID {
			cp := *oi
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeRepo) DeleteOAuthIdentity(_ context.Context, userID, provider, providerUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, oi := range r.oauthIdentities {
		if oi.UserID == userID && oi.Provider == provider && oi.ProviderUserID == providerUserID {
			delete(r.oauthIdentities, id)
			return nil
		}
	}
	return ErrNotFound
}

// ── Audit Events ────────────────────────────────────────────────────────

func (r *fakeRepo) CreateAuditEvent(_ context.Context, e *AuditEvent) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := e.ID
	if id == "" {
		id = nextNodeID()
	}
	cp := *e
	cp.ID = id
	r.auditEvents = append(r.auditEvents, &cp)
	return id, nil
}

func (r *fakeRepo) ListAuditEventsForUser(_ context.Context, userID string, limit int) ([]*AuditEvent, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("fakeRepo: ListAuditEventsForUser: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*AuditEvent, 0)
	for _, e := range r.auditEvents {
		if e.ActorUserID == userID || e.TargetUserID == userID {
			cp := *e
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *fakeRepo) DeleteAuditEventsBefore(_ context.Context, cutoffMs int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.auditEvents[:0]
	deleted := 0
	for _, e := range r.auditEvents {
		if e.CreatedAt < cutoffMs {
			deleted++
			continue
		}
		kept = append(kept, e)
	}
	r.auditEvents = kept
	return deleted, nil
}

// ── Identity Verification ──────────────────────────────────────────────

func (r *fakeRepo) CreateIdentityVerification(_ context.Context, rec *IdentityVerificationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.VerificationID == "" {
		return errors.New("idv: missing verification id")
	}
	if _, ok := r.idvRecords[rec.VerificationID]; ok {
		return fmt.Errorf("idv: %s already exists", rec.VerificationID)
	}
	if rec.NodeID == "" {
		rec.NodeID = nextNodeID()
	}
	cp := *rec
	r.idvRecords[rec.VerificationID] = &cp
	return nil
}

func (r *fakeRepo) GetIdentityVerification(_ context.Context, verificationID string) (*IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (r *fakeRepo) GetLatestIdentityVerificationForUser(_ context.Context, userID string) (*IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *IdentityVerificationRecord
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

func (r *fakeRepo) DeleteExpiredNativeTokenRedemptions(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, e := range r.nativeRedemptions {
		if limit > 0 && n >= limit {
			break
		}
		if e.ExpiresAt < beforeMs {
			delete(r.nativeRedemptions, id)
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

func (r *fakeRepo) DeleteExpiredQrLoginSessions(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, s := range r.qrSessions {
		if limit > 0 && n >= limit {
			break
		}
		if s.ExpiresAt < beforeMs {
			delete(r.qrSessions, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteExpiredInvitations(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, inv := range r.invitations {
		if limit > 0 && n >= limit {
			break
		}
		if inv.ExpiresAt < beforeMs {
			delete(r.invitations, id)
			n++
		}
	}
	return nil
}

// ── Sessions ──────────────────────────────────────────────────────────

func (r *fakeRepo) CreateSession(_ context.Context, s *SessionRecord) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: nil session", ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]*SessionRecord)
	}
	for _, existing := range r.sessions {
		if existing.SID == s.SID {
			return "", fmt.Errorf("%w: sid %q", ErrAlreadyExists, s.SID)
		}
	}
	id := nextNodeID()
	s.NodeID = id
	cp := *s
	r.sessions[id] = &cp
	return id, nil
}

func (r *fakeRepo) GetSessionBySid(_ context.Context, sid string) (*SessionRecord, error) {
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

// ── Assurance (attested devices + one-shot challenges) ────────────────

func (r *fakeRepo) CreateAttestedDevice(_ context.Context, d *AttestedDeviceRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attestedDevices == nil {
		r.attestedDevices = make(map[string]*AttestedDeviceRecord)
	}
	for _, existing := range r.attestedDevices {
		if existing.KeyID == d.KeyID {
			return "", fmt.Errorf("fake: CreateAttestedDevice: %w", ErrAlreadyExists)
		}
	}
	id := d.NodeID
	if id == "" {
		id = nextNodeID()
	}
	cp := *d
	cp.NodeID = id
	r.attestedDevices[id] = &cp
	d.NodeID = id
	return id, nil
}

func (r *fakeRepo) GetAttestedDeviceByKeyID(_ context.Context, keyID string) (*AttestedDeviceRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.attestedDevices {
		if d.KeyID == keyID {
			cp := *d
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *fakeRepo) UpdateAttestedDeviceCounter(_ context.Context, nodeID string, fromCount, toCount, lastUsedAtMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// updateCounterErr lets a test drive the CAS outcomes the service must
	// collapse to a replay rejection (ErrCounterStale / ErrNotFound) without
	// racing a real concurrent assertion.
	if r.updateCounterErr != nil {
		return r.updateCounterErr
	}
	d, ok := r.attestedDevices[nodeID]
	if !ok {
		return fmt.Errorf("%w: attested device", ErrNotFound)
	}
	if d.SignCount != fromCount {
		return ErrCounterStale
	}
	d.SignCount = toCount
	d.LastUsedAt = lastUsedAtMs
	return nil
}

func (r *fakeRepo) CreateAssuranceChallenge(_ context.Context, c *AssuranceChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createChallengeErr != nil {
		return "", r.createChallengeErr
	}
	if r.assuranceChallenges == nil {
		r.assuranceChallenges = make(map[string]*AssuranceChallengeRecord)
	}
	id := c.NodeID
	if id == "" {
		id = nextNodeID()
	}
	cp := *c
	cp.NodeID = id
	r.assuranceChallenges[id] = &cp
	c.NodeID = id
	return id, nil
}

func (r *fakeRepo) ConsumeAssuranceChallenge(_ context.Context, nodeID string) (*AssuranceChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.consumeChallengeErr != nil {
		return nil, r.consumeChallengeErr
	}
	c, ok := r.assuranceChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	delete(r.assuranceChallenges, nodeID)
	cp := *c
	return &cp, nil
}

func (r *fakeRepo) DeleteExpiredAssuranceChallenges(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.assuranceChallenges {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.assuranceChallenges, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteStaleAttestedDevices(_ context.Context, beforeMs int64, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, d := range r.attestedDevices {
		if n >= limit {
			break
		}
		if d.LastUsedAt < beforeMs {
			delete(r.attestedDevices, id)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) DeleteStaleAnonymousUsers(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("fakerepo: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, u := range r.users {
		if n >= limit {
			break
		}
		if u.IsAnonymous && u.LastLoginAtMs < beforeMs {
			delete(r.users, id)
			n++
		}
	}
	return nil
}
