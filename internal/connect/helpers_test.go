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
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
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

// Group payload field IDs.
const (
	tGfName        = "1"
	tGfDescription = "2"
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
	totpCreds          map[string]*service.TotpCredRecord
	recoveryCodes      map[string]*service.RecoveryCodeRecord
	loginChallenges    map[string]*service.LoginChallengeRecord
	invitations        map[string]*service.InvitationRecord
	passwordResets     map[string]*service.PasswordResetToken
	emailVerifications map[string]*service.EmailVerificationToken

	// Optional error injections for specific calls.
	errFindUser   error
	errCreateUser error
	errIssueToken error // makes CreateRefreshToken fail
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:              make(map[string]*service.User),
		refreshTokens:      make(map[string]*service.RefreshTokenRecord),
		passkeyCreds:       make(map[string]*service.PasskeyCredRecord),
		passkeyChallenges:  make(map[string]*service.PasskeyChallengeRecord),
		qrSessions:         make(map[string]*service.QrLoginSessionRecord),
		totpCreds:          make(map[string]*service.TotpCredRecord),
		recoveryCodes:      make(map[string]*service.RecoveryCodeRecord),
		loginChallenges:    make(map[string]*service.LoginChallengeRecord),
		invitations:        make(map[string]*service.InvitationRecord),
		passwordResets:     make(map[string]*service.PasswordResetToken),
		emailVerifications: make(map[string]*service.EmailVerificationToken),
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

func (f *fakeDB) ExecuteAtomic(_ context.Context, _, _, _ string, ops []entdb.Operation) (*entdb.CommitResult, error) {
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
				if !(e.EdgeTypeID == op.EdgeTypeID && e.FromNodeID == op.FromNodeID && e.ToNodeID == op.ToNodeID) {
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

func (f *fakeDB) addGroup(id, name, description string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id,
		TypeID: tTypeWorkingGroup,
		Payload: map[string]any{
			tGfName:        name,
			tGfDescription: description,
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
		TOTPIssuer:                    "Test",
		PasswordResetExpirySeconds:    3600,
	}
}

func testKeyRing(t *testing.T) *jwt.KeyRing {
	t.Helper()
	sk, err := jwt.GenerateKey("test-kid")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kr, err := jwt.NewKeyRing([]jwt.SigningKey{sk})
	if err != nil {
		t.Fatalf("new key ring: %v", err)
	}
	return kr
}

// newHarness builds a complete handler stack and exposes both an in-process
// connect client and the underlying fakes for assertions.
func newHarness(t *testing.T) *testHarness {
	t.Helper()

	repo := newFakeRepo()
	db := newFakeDB()
	cfg := testConfig()
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

	authSvc := service.NewAuthService(repo, cfg, kr, pkSvc, auditLog, totpKey, nil, zap.NewNop())
	adminSvc := service.NewAdminService(db, cfg.DefaultTenantID, auditLog, cfg, nil, zap.NewNop())
	groupSvc := service.NewGroupService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	helpSvc := service.NewHelpService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	profSvc := service.NewProfileService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())

	h := NewIdentityHandler(authSvc, adminSvc, groupSvc, helpSvc, profSvc)

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
