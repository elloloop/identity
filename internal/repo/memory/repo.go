// Package memory is the in-process Repository driver. It backs both
// fast unit tests (no gRPC, no docker) and local-development runs
// where a full datastore is overkill.
//
// All operations are mutex-protected so tests using t.Parallel() are
// race-free. The driver keeps the same surface as the postgres-backed
// driver — service.Repository plus a no-op service.DB — so the
// driver-selection helper in internal/repo/driver.go can hand it
// back from Build like any other backend.
package memory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elloloop/identity/internal/graph"

	"github.com/elloloop/identity/internal/service"
)

// Repo is the in-memory implementation of service.Repository.
//
// Project isolation (ADR-0002): each Repo instance owns an independent set
// of data-plane maps, so two projects share no rows and uniqueness (e.g.
// email) is per-project, mirroring the postgres `WHERE project_id = $1`
// boundary and the graph per-project partition. WithProject returns the
// sibling Repo for a given project, lazily created and memoised in a shared
// registry so repeated lookups of the same project reuse one store.
type Repo struct {
	// projectID is the storage shard this Repo instance is bound to. The
	// boot-default instance carries the empty string; siblings carry the
	// resolved project id.
	projectID string
	// registry is shared by every sibling produced via WithProject so they
	// can find one another by project id. The boot Repo creates it; each
	// sibling points at the same map.
	registry *projectRegistry

	mu sync.Mutex

	seq                int64
	users              map[string]*service.User
	refreshTokens      map[string]*service.RefreshTokenRecord
	passkeyCreds       map[string]*service.PasskeyCredRecord
	attestedDevices    map[string]*service.AttestedDeviceRecord
	assuranceChallenges map[string]*service.AssuranceChallengeRecord
	passkeyChallenges  map[string]*service.PasskeyChallengeRecord
	qrSessions         map[string]*service.QrLoginSessionRecord
	oauthOneTimeCodes  map[string]*service.OAuthOneTimeCodeRecord
	nativeRedemptions  map[string]*service.NativeTokenRedemptionRecord
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
	sessions           map[string]*service.SessionRecord
	auditEvents        map[string]*service.AuditEvent
}

// projectRegistry memoises the per-project Repo siblings produced by
// WithProject so repeated lookups of one project reuse a single store. It
// is shared (by pointer) across every sibling of a New()-rooted Repo.
type projectRegistry struct {
	mu       sync.Mutex
	byID     map[string]*Repo
	makeRepo func(projectID string) *Repo
}

// New returns an empty Repo bound to the boot-default project (the empty
// project id). Data written without an explicit project scope lands here;
// WithProject derives isolated siblings for other projects.
func New() *Repo {
	reg := &projectRegistry{byID: make(map[string]*Repo)}
	reg.makeRepo = func(projectID string) *Repo {
		r := newStore()
		r.projectID = projectID
		r.registry = reg
		return r
	}
	root := reg.makeRepo("")
	reg.byID[""] = root
	return root
}

// newStore allocates a Repo with empty, independent data-plane maps. It
// carries no project binding or registry; New / WithProject set those.
func newStore() *Repo {
	return &Repo{
		users:              make(map[string]*service.User),
		refreshTokens:      make(map[string]*service.RefreshTokenRecord),
		passkeyCreds:       make(map[string]*service.PasskeyCredRecord),
		attestedDevices:    make(map[string]*service.AttestedDeviceRecord),
		assuranceChallenges: make(map[string]*service.AssuranceChallengeRecord),
		passkeyChallenges:  make(map[string]*service.PasskeyChallengeRecord),
		qrSessions:         make(map[string]*service.QrLoginSessionRecord),
		oauthOneTimeCodes:  make(map[string]*service.OAuthOneTimeCodeRecord),
		nativeRedemptions:  make(map[string]*service.NativeTokenRedemptionRecord),
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
		idvRecords:         make(map[string]*service.IdentityVerificationRecord),
		sessions:           make(map[string]*service.SessionRecord),
		auditEvents:        make(map[string]*service.AuditEvent),
	}
}

// WithProject returns the Repo bound to projectID, mirroring the postgres
// `WHERE project_id = $1` boundary and the graph per-project partition
// (ADR-0002). Each project gets a fully independent store, so two projects
// never see each other's rows and a unique key (email) is scoped per
// project. The sibling is memoised so repeated calls for one project return
// the same store; passing this Repo's own project id returns itself.
func (r *Repo) WithProject(projectID string) service.Repository {
	if projectID == r.projectID {
		return r
	}
	reg := r.registry
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if sibling, ok := reg.byID[projectID]; ok {
		return sibling
	}
	sibling := reg.makeRepo(projectID)
	reg.byID[projectID] = sibling
	return sibling
}

func (r *Repo) nextID() string {
	r.seq++
	return fmt.Sprintf("mem-%d", r.seq)
}

// CountRefreshTokensForUser is a test helper for assertions about
// session count.
func (r *Repo) CountRefreshTokensForUser(userID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.refreshTokens {
		if t.UserID == userID {
			n++
		}
	}
	return n
}

// CountPasswordResetTokens is a test helper used by the sweeper
// regression to infer "rows deleted" from "rows still present" after
// the v1.14.0 contract dropped the row-count return.
func (r *Repo) CountPasswordResetTokens() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.passwordResets)
}

// CountEmailVerificationTokens is a test helper; see CountPasswordResetTokens.
func (r *Repo) CountEmailVerificationTokens() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.emailVerifications)
}

// CountEmailChangeTokens is a test helper; see CountPasswordResetTokens.
func (r *Repo) CountEmailChangeTokens() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.emailChanges)
}

// CountLoginChallenges is a test helper; see CountPasswordResetTokens.
func (r *Repo) CountLoginChallenges() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.loginChallenges)
}

// CountPasskeyChallenges is a test helper; see CountPasswordResetTokens.
func (r *Repo) CountPasskeyChallenges() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.passkeyChallenges)
}

// ── Users ─────────────────────────────────────────────────────────

func (r *Repo) FindUserByEmail(_ context.Context, email string) (*service.User, error) {
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

func (r *Repo) GetUser(_ context.Context, userID string) (*service.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (r *Repo) ListUsers(_ context.Context, filter service.UserListFilter) ([]*service.User, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = service.DefaultUserListLimit
	}
	if limit > service.MaxUserListLimit {
		limit = service.MaxUserListLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	r.mu.Lock()
	matched := make([]*service.User, 0, len(r.users))
	for _, u := range r.users {
		if filter.Email != "" && !strings.EqualFold(u.Email, filter.Email) {
			continue
		}
		if filter.ExternalID != "" && u.ExternalID != filter.ExternalID {
			continue
		}
		cp := *u
		matched = append(matched, &cp)
	}
	r.mu.Unlock()

	// Stable ordering identical to the SQL drivers: created_at asc, then id.
	sort.Slice(matched, func(i, j int) bool {
		ti, tj := matched[i].CreatedAt.UnixMilli(), matched[j].CreatedAt.UnixMilli()
		if ti != tj {
			return ti < tj
		}
		return matched[i].ID < matched[j].ID
	})

	if offset >= len(matched) {
		return nil, nil
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[offset:end], nil
}

// ListUsersPendingDeletionBefore returns users whose self-service deletion
// grace window has elapsed (status = pending_deletion, deletion_scheduled_at_ms
// in (0, cutoffMs]), ordered by deletion_scheduled_at_ms then id, capped at
// limit. It backs the account-deletion sweeper. limit <= 0 is rejected so the
// contract matches the SQL drivers, which refuse an uncapped scan.
func (r *Repo) ListUsersPendingDeletionBefore(_ context.Context, cutoffMs int64, limit int) ([]*service.User, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("memory: ListUsersPendingDeletionBefore: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	matched := make([]*service.User, 0)
	for _, u := range r.users {
		if u.Status != service.StatusPendingDeletion {
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

// CountUsers returns the total number of users matching filter's equality
// predicates (Email/ExternalID), ignoring Offset/Limit. It backs the SCIM
// /Users totalResults so a page reports the true match count rather than the
// page size. Mirrors the SQL drivers.
func (r *Repo) CountUsers(_ context.Context, filter service.UserListFilter) (int, error) {
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

func (r *Repo) CreateUser(_ context.Context, u *service.User) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.users {
		// Case-insensitive, mirroring the SQL drivers' lower(email) unique
		// index: every backend signals a duplicate identically (the SCIM
		// server maps this sentinel to HTTP 409 Conflict).
		if strings.EqualFold(existing.Email, u.Email) {
			return "", fmt.Errorf("user %q: %w", u.Email, service.ErrAlreadyExists)
		}
		if u.ExternalID != "" && existing.ExternalID == u.ExternalID {
			return "", fmt.Errorf("external_id %q: %w", u.ExternalID, service.ErrAlreadyExists)
		}
	}
	// Honour a caller-provided id (matching the postgres/sqlite drivers).
	// Passkey-first signup mints the user id during the Begin step and binds
	// it as the WebAuthn user handle; CreateUser must persist that exact id so
	// the credential's handle matches the stored user at login time.
	id := u.ID
	if id == "" {
		id = r.nextID()
	} else if _, clash := r.users[id]; clash {
		return "", fmt.Errorf("user id %q: %w", id, service.ErrAlreadyExists)
	}
	u.ID = id
	cp := *u
	r.users[id] = &cp
	return id, nil
}

func (r *Repo) UpdateUser(_ context.Context, userID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	if v, ok := fields["external_id"]; ok {
		if ext, _ := v.(string); ext != "" {
			for id, other := range r.users {
				if id != userID && other.ExternalID == ext {
					return fmt.Errorf("external_id %q: %w", ext, service.ErrAlreadyExists)
				}
			}
		}
	}
	// Mirror the SQL drivers' per-project unique (lower(email)) index: an
	// email change that collides with another user is a conflict, so a SCIM
	// PUT/PATCH that reuses an address fails identically across backends.
	if v, ok := fields["email"]; ok {
		if email, _ := v.(string); email != "" {
			for id, other := range r.users {
				if id != userID && strings.EqualFold(other.Email, email) {
					return fmt.Errorf("email %q: %w", email, service.ErrAlreadyExists)
				}
			}
		}
	}
	applyUserFields(u, fields)
	return nil
}

// DeleteUser physically removes the user and every user-owned row. It
// is idempotent (a missing user is a no-op). The email-keyed login
// codes / magic-link tokens are intentionally left untouched (they
// carry no user_id and are short-lived pre-account artifacts); the
// audit store has no in-memory equivalent so nothing to retain. The
// phone-verification codes are user-keyed and durable, so they are
// drained here like the other user-owned types.
func (r *Repo) DeleteUser(_ context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	deleteByUser(r.refreshTokens, userID, func(t *service.RefreshTokenRecord) string { return t.UserID })
	deleteByUser(r.sessions, userID, func(s *service.SessionRecord) string { return s.UserID })
	deleteByUser(r.passkeyCreds, userID, func(c *service.PasskeyCredRecord) string { return c.UserID })
	deleteByUser(r.passkeyChallenges, userID, func(c *service.PasskeyChallengeRecord) string { return c.UserID })
	deleteByUser(r.qrSessions, userID, func(s *service.QrLoginSessionRecord) string { return s.UserID })
	deleteByUser(r.oauthOneTimeCodes, userID, func(c *service.OAuthOneTimeCodeRecord) string { return c.UserID })
	deleteByUser(r.totpCreds, userID, func(c *service.TotpCredRecord) string { return c.UserID })
	deleteByUser(r.recoveryCodes, userID, func(c *service.RecoveryCodeRecord) string { return c.UserID })
	deleteByUser(r.loginChallenges, userID, func(c *service.LoginChallengeRecord) string { return c.UserID })
	deleteByUser(r.invitations, userID, func(i *service.InvitationRecord) string { return i.UserID })
	deleteByUser(r.passwordResets, userID, func(t *service.PasswordResetToken) string { return t.UserID })
	deleteByUser(r.emailVerifications, userID, func(t *service.EmailVerificationToken) string { return t.UserID })
	deleteByUser(r.emailChanges, userID, func(t *service.EmailChangeToken) string { return t.UserID })
	deleteByUser(r.oauthIdentities, userID, func(o *service.OAuthIdentity) string { return o.UserID })
	deleteByUser(r.idvRecords, userID, func(rec *service.IdentityVerificationRecord) string { return rec.UserID })
	deleteByUser(r.phoneVerifyCodes, userID, func(c *service.PhoneVerificationCodeRecord) string { return c.UserID })
	delete(r.users, userID)
	return nil
}

// deleteByUser removes every entry of m whose record's user id (read via
// userID) equals want. Shared by DeleteUser so each user-owned map drains
// with one call instead of an inline loop per type.
func deleteByUser[V any](m map[string]V, want string, userID func(V) string) {
	for id, v := range m {
		if userID(v) == want {
			delete(m, id)
		}
	}
}

func (r *Repo) IncrementFailedLoginCount(_ context.Context, userID string) (int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return 0, fmt.Errorf("user %s not found", userID)
	}
	if u.FailedLoginCount >= math.MaxInt32 {
		return 0, fmt.Errorf("failed login count overflow for user %s", userID)
	}
	u.FailedLoginCount++
	return int32(u.FailedLoginCount), nil // #nosec G115 -- bounds checked above.
}

func (r *Repo) ResetFailedLoginCount(_ context.Context, userID string) error {
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

func (r *Repo) SetUserLockedUntil(_ context.Context, userID string, lockedUntilMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.LockedUntil = lockedUntilMs
	return nil
}

// fieldInt64 coerces a fields-map numeric value to int64. Production
// callers pass timestamps and counters as int64; plain int literals reach
// the map from tests and helpers, so both are accepted.
func fieldInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	}
	return 0, false
}

func applyUserFields(u *service.User, fields map[string]any) {
	for k, v := range fields {
		switch k {
		case "name":
			u.Name, _ = v.(string)
		case "email":
			u.Email, _ = v.(string)
		case "avatar_url":
			u.AvatarURL, _ = v.(string)
		case "password_hash":
			u.PasswordHash, _ = v.(string)
		case "status":
			u.Status, _ = v.(string)
		case "totp_required":
			u.TotpRequired, _ = v.(bool)
		case "failed_login_count":
			if x, ok := fieldInt64(v); ok {
				u.FailedLoginCount = int(x)
			}
		case "locked_until":
			if x, ok := fieldInt64(v); ok {
				u.LockedUntil = x
			}
		case "updated_at":
			if x, ok := fieldInt64(v); ok {
				u.UpdatedAt = time.UnixMilli(x)
			}
		case "last_login_at":
			if x, ok := fieldInt64(v); ok {
				u.LastLoginAtMs = x
			}
		case "recovery_email":
			u.RecoveryEmail, _ = v.(string)
		case "email_verified":
			if b, ok := v.(bool); ok {
				u.EmailVerified = b
			}
		case "email_verified_at":
			if x, ok := fieldInt64(v); ok {
				u.EmailVerifiedAt = x
			}
		case "external_id":
			u.ExternalID, _ = v.(string)
		case "phone_number":
			u.PhoneNumber, _ = v.(string)
		case "phone_verified":
			if b, ok := v.(bool); ok {
				u.PhoneVerified = b
			}
		case "phone_verified_at":
			if x, ok := fieldInt64(v); ok {
				u.PhoneVerifiedAt = x
			}
		case "date_of_birth_ms":
			if x, ok := fieldInt64(v); ok {
				u.DateOfBirthMs = x
			}
		case "deletion_scheduled_at_ms":
			if x, ok := fieldInt64(v); ok {
				u.DeletionScheduledAtMs = x
			}
		}
	}
}

// ── Refresh Tokens ────────────────────────────────────────────────

func (r *Repo) FindRefreshTokenByHash(_ context.Context, hash string) (*service.RefreshTokenRecord, error) {
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

func (r *Repo) FindRefreshTokenByHashIncludingConsumed(_ context.Context, hash string) (*service.RefreshTokenRecord, error) {
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

func (r *Repo) CreateRefreshToken(_ context.Context, rec *service.RefreshTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.refreshTokens[id] = &cp
	return id, nil
}

func (r *Repo) DeleteRefreshToken(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.refreshTokens, nodeID)
	return nil
}

func (r *Repo) DeleteRefreshTokensForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.refreshTokens {
		if t.UserID == userID {
			delete(r.refreshTokens, id)
		}
	}
	return nil
}

// ConsumeRefreshTokenByHash atomically marks the row consumed. Returns
// service.ErrUnauthenticated if the row is missing or already consumed,
// so concurrent rotations resolve to exactly one winner.
func (r *Repo) ConsumeRefreshTokenByHash(_ context.Context, hash string, atMs int64) error {
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

// ── Passkey Credentials ───────────────────────────────────────────

func (r *Repo) ListPasskeyCredentials(_ context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
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

func (r *Repo) GetPasskeyCredentialByCredID(_ context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
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

func (r *Repo) CreatePasskeyCredential(_ context.Context, rec *service.PasskeyCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.passkeyCreds[id] = &cp
	return id, nil
}

func (r *Repo) UpdatePasskeyCredential(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyCreds[nodeID]
	if !ok {
		return fmt.Errorf("passkey credential %s not found", nodeID)
	}
	if v, ok := fields["sign_count"]; ok {
		c.SignCount, _ = v.(int64)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt, _ = v.(int64)
	}
	return nil
}

func (r *Repo) DeletePasskeyCredentialsForUser(_ context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	deleteByUser(r.passkeyCreds, userID, func(c *service.PasskeyCredRecord) string { return c.UserID })
	return nil
}

// ── Passkey Challenges ────────────────────────────────────────────

func (r *Repo) GetPasskeyChallenge(_ context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *Repo) CreatePasskeyChallenge(_ context.Context, rec *service.PasskeyChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.passkeyChallenges[id] = &cp
	return id, nil
}

func (r *Repo) DeletePasskeyChallenge(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.passkeyChallenges, nodeID)
	return nil
}

// ── QR Login Sessions ─────────────────────────────────────────────

func (r *Repo) FindQrLoginSession(_ context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
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

func (r *Repo) CreateQrLoginSession(_ context.Context, rec *service.QrLoginSessionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.qrSessions[id] = &cp
	return id, nil
}

func (r *Repo) UpdateQrLoginSession(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.qrSessions[nodeID]
	if !ok {
		return fmt.Errorf("qr session %s not found", nodeID)
	}
	if v, ok := fields["status"]; ok {
		s.Status, _ = v.(string)
	}
	if v, ok := fields["user_id"]; ok {
		s.UserID, _ = v.(string)
	}
	if v, ok := fields["approved_device_info"]; ok {
		s.ApprovedDeviceInfo, _ = v.(string)
	}
	if v, ok := fields["updated_at"]; ok {
		s.UpdatedAt, _ = v.(int64)
	}
	return nil
}

// ConsumeQrLoginSession atomically transitions an approved session to
// consumed. The mutex held across read+check+write makes this CAS
// trivially correct for the in-process driver: any second caller sees
// status != "approved" and returns ErrQrLoginNotPending.
func (r *Repo) ConsumeQrLoginSession(_ context.Context, nodeID string, atMs int64) error {
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

// ── OAuth One-Time Codes ──────────────────────────────────────────

func (r *Repo) CreateOAuthOneTimeCode(_ context.Context, rec *service.OAuthOneTimeCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("memory: CreateOAuthOneTimeCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.oauthOneTimeCodes[id] = &cp
	return id, nil
}

// ConsumeOAuthOneTimeCode atomically marks an unconsumed, unexpired
// code consumed and returns its record. The mutex held across
// read+check+write makes this CAS trivially correct for the in-process
// driver: any second caller (or an expired code) returns
// ErrOAuthCodeInvalid.
func (r *Repo) ConsumeOAuthOneTimeCode(_ context.Context, codeHash string, atMs int64) (*service.OAuthOneTimeCodeRecord, error) {
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

// RecordNativeTokenRedemption records a redeemed native ID token's replay
// key, enforcing single-use. The mutex held across scan+insert makes the
// insert-or-reject trivially atomic for the in-process driver: the first
// call for a key inserts and returns nil; any second call with the same key
// (a replay of the same bearer token) returns ErrNativeTokenReplayed —
// matching the postgres/sqlite unique-index semantics.
func (r *Repo) RecordNativeTokenRedemption(_ context.Context, rec *service.NativeTokenRedemptionRecord) (string, error) {
	if rec == nil {
		return "", errors.New("memory: RecordNativeTokenRedemption: nil record")
	}
	if rec.ReplayKey == "" {
		return "", fmt.Errorf("%w: missing replay key", service.ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.nativeRedemptions {
		if e.ReplayKey == rec.ReplayKey {
			return "", service.ErrNativeTokenReplayed
		}
	}
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.nativeRedemptions[id] = &cp
	return id, nil
}

// ── Email Login Codes (passwordless OTP) ──────────────────────────

// UpsertEmailLoginCode replaces any existing code for the email so at
// most one is live per address. Keyed by email (the unique field).
func (r *Repo) UpsertEmailLoginCode(_ context.Context, rec *service.EmailLoginCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("memory: UpsertEmailLoginCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.emailLoginCodes {
		if c.Email == rec.Email {
			delete(r.emailLoginCodes, id)
		}
	}
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.emailLoginCodes[id] = &cp
	return id, nil
}

func (r *Repo) FindEmailLoginCodeByEmail(_ context.Context, email string) (*service.EmailLoginCodeRecord, error) {
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

func (r *Repo) IncrementEmailLoginCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.emailLoginCodes[nodeID]
	if !ok {
		return fmt.Errorf("memory: IncrementEmailLoginCodeAttempts: %s not found", nodeID)
	}
	c.AttemptCount++
	return nil
}

// ConsumeEmailLoginCode atomically marks the email's unconsumed,
// unexpired code consumed and returns it. Any second caller, an expired
// code, or a missing code returns ErrEmailLoginCodeInvalid.
func (r *Repo) ConsumeEmailLoginCode(_ context.Context, email string, atMs int64) (*service.EmailLoginCodeRecord, error) {
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

// ── Magic Link Tokens (passwordless) ──────────────────────────────

func (r *Repo) CreateMagicLinkToken(_ context.Context, rec *service.MagicLinkTokenRecord) (string, error) {
	if rec == nil {
		return "", errors.New("memory: CreateMagicLinkToken: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.magicLinkTokens[id] = &cp
	return id, nil
}

// ConsumeMagicLinkToken atomically marks an unconsumed, unexpired token
// consumed and returns it. A replay, an expired token, or a missing
// token returns ErrMagicLinkInvalid.
func (r *Repo) ConsumeMagicLinkToken(_ context.Context, tokenHash string, atMs int64) (*service.MagicLinkTokenRecord, error) {
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

// ── Phone Verification Codes (SMS OTP) ─────────────────────────────

// UpsertPhoneVerificationCode replaces any existing code for the user so
// at most one is live per user. Keyed by user_id.
func (r *Repo) UpsertPhoneVerificationCode(_ context.Context, rec *service.PhoneVerificationCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("memory: UpsertPhoneVerificationCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.phoneVerifyCodes {
		if c.UserID == rec.UserID {
			delete(r.phoneVerifyCodes, id)
		}
	}
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.phoneVerifyCodes[id] = &cp
	return id, nil
}

func (r *Repo) FindPhoneVerificationCodeByUser(_ context.Context, userID string) (*service.PhoneVerificationCodeRecord, error) {
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

func (r *Repo) IncrementPhoneVerificationCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.phoneVerifyCodes[nodeID]
	if !ok {
		return fmt.Errorf("memory: IncrementPhoneVerificationCodeAttempts: %s not found", nodeID)
	}
	c.AttemptCount++
	return nil
}

// ConsumePhoneVerificationCode atomically marks the user's unconsumed,
// unexpired code consumed and returns it. Any second caller, an expired
// code, or a missing code returns ErrPhoneCodeInvalid.
func (r *Repo) ConsumePhoneVerificationCode(_ context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
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

func (r *Repo) SetUserPhoneVerified(_ context.Context, userID, phoneNumber string, atMs int64) error {
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

// ── TOTP Credentials ──────────────────────────────────────────────

func (r *Repo) GetTotpCredential(_ context.Context, userID string) (*service.TotpCredRecord, error) {
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

func (r *Repo) CreateTotpCredential(_ context.Context, rec *service.TotpCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.totpCreds[id] = &cp
	return id, nil
}

func (r *Repo) UpdateTotpCredential(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.totpCreds[nodeID]
	if !ok {
		return fmt.Errorf("totp credential %s not found", nodeID)
	}
	if v, ok := fields["verified"]; ok {
		c.Verified, _ = v.(bool)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt, _ = v.(int64)
	}
	return nil
}

func (r *Repo) DeleteTotpCredential(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.totpCreds, nodeID)
	return nil
}

func (r *Repo) DeleteTotpCredentialsForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.totpCreds {
		if c.UserID == userID {
			delete(r.totpCreds, id)
		}
	}
	return nil
}

// ── Recovery Codes ────────────────────────────────────────────────

func (r *Repo) CreateRecoveryCode(_ context.Context, rec *service.RecoveryCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.recoveryCodes[id] = &cp
	return id, nil
}

func (r *Repo) FindRecoveryCodeByHash(_ context.Context, userID, hash string) (*service.RecoveryCodeRecord, error) {
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

func (r *Repo) UpdateRecoveryCode(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rc, ok := r.recoveryCodes[nodeID]
	if !ok {
		return fmt.Errorf("recovery code %s not found", nodeID)
	}
	if v, ok := fields["used"]; ok {
		rc.Used, _ = v.(bool)
	}
	if v, ok := fields["used_at"]; ok {
		rc.UsedAt, _ = v.(int64)
	}
	return nil
}

func (r *Repo) DeleteRecoveryCodesForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, rc := range r.recoveryCodes {
		if rc.UserID == userID {
			delete(r.recoveryCodes, id)
		}
	}
	return nil
}

// ── Login Challenges ──────────────────────────────────────────────

func (r *Repo) CreateLoginChallenge(_ context.Context, rec *service.LoginChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.loginChallenges[id] = &cp
	return id, nil
}

func (r *Repo) GetLoginChallengeByChallengeID(_ context.Context, challengeID string) (*service.LoginChallengeRecord, error) {
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

func (r *Repo) DeleteLoginChallenge(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.loginChallenges, nodeID)
	return nil
}

// ── Invitations ───────────────────────────────────────────────────

func (r *Repo) FindInvitationByHash(_ context.Context, tokenHash string) (*service.InvitationRecord, error) {
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

func (r *Repo) UpdateInvitation(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	inv, ok := r.invitations[nodeID]
	if !ok {
		return fmt.Errorf("invitation %s not found", nodeID)
	}
	if v, ok := fields["accepted_at"]; ok {
		inv.AcceptedAt, _ = v.(int64)
	}
	return nil
}

// ── Password Reset Tokens ─────────────────────────────────────────

func (r *Repo) CreatePasswordResetToken(_ context.Context, t *service.PasswordResetToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	t.NodeID = id
	cp := *t
	r.passwordResets[id] = &cp
	return nil
}

func (r *Repo) FindPasswordResetTokenByHash(_ context.Context, hash string) (*service.PasswordResetToken, error) {
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

func (r *Repo) MarkPasswordResetTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.passwordResets[id]
	if !ok {
		return fmt.Errorf("password reset token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

// ── Email Verification Tokens ─────────────────────────────────────

func (r *Repo) CreateEmailVerificationToken(_ context.Context, t *service.EmailVerificationToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	t.NodeID = id
	cp := *t
	r.emailVerifications[id] = &cp
	return nil
}

func (r *Repo) FindEmailVerificationTokenByHash(_ context.Context, hash string) (*service.EmailVerificationToken, error) {
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

func (r *Repo) MarkEmailVerificationTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.emailVerifications[id]
	if !ok {
		return fmt.Errorf("email verification token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *Repo) SetUserEmailVerified(_ context.Context, userID string, atMs int64) error {
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

func (r *Repo) SetUserIDVVerified(_ context.Context, userID string, atMs int64) error {
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

// ── Email Change Tokens ───────────────────────────────────────────

func (r *Repo) CreateEmailChangeToken(_ context.Context, t *service.EmailChangeToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	t.NodeID = id
	cp := *t
	r.emailChanges[id] = &cp
	return nil
}

func (r *Repo) FindEmailChangeTokenByHash(_ context.Context, hash string) (*service.EmailChangeToken, error) {
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

func (r *Repo) FindUserByProviderID(_ context.Context, provider, providerUserID string) (*service.User, error) {
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

func (r *Repo) MarkEmailChangeTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.emailChanges[id]
	if !ok {
		return fmt.Errorf("email change token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *Repo) UpdateUserEmail(_ context.Context, userID, newEmail string, atMs int64) error {
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

func (r *Repo) CreateOAuthIdentity(_ context.Context, oi *service.OAuthIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.oauthIdentities {
		if existing.Provider == oi.Provider && existing.ProviderUserID == oi.ProviderUserID {
			return fmt.Errorf("oauth identity already linked: %s/%s", oi.Provider, oi.ProviderUserID)
		}
	}
	id := r.nextID()
	oi.NodeID = id
	cp := *oi
	r.oauthIdentities[id] = &cp
	return nil
}

func (r *Repo) ListOAuthIdentitiesForUser(_ context.Context, userID string) ([]*service.OAuthIdentity, error) {
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

func (r *Repo) DeleteOAuthIdentity(_ context.Context, userID, provider, providerUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, oi := range r.oauthIdentities {
		if oi.UserID == userID && oi.Provider == provider && oi.ProviderUserID == providerUserID {
			delete(r.oauthIdentities, id)
			return nil
		}
	}
	return service.ErrNotFound
}

// ── Audit Events ──────────────────────────────────────────────────

// CreateAuditEvent stores a copy of the event and returns its id. A blank
// Event.ID is server-minted; a non-empty one is honoured (so a caller can
// pin an id). The stored Details map is deep-copied so a later mutation of
// the caller's map cannot alter the persisted event.
func (r *Repo) CreateAuditEvent(_ context.Context, e *service.AuditEvent) (string, error) {
	if e == nil {
		return "", errors.New("memory: CreateAuditEvent: nil event")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := e.ID
	if id == "" {
		id = r.nextID()
	}
	cp := *e
	cp.ID = id
	cp.Details = copyDetails(e.Details)
	r.auditEvents[id] = &cp
	return id, nil
}

// ListAuditEventsForUser returns the events where userID is the actor OR the
// target, newest first (created-at desc, then id desc), capped at limit.
func (r *Repo) ListAuditEventsForUser(_ context.Context, userID string, limit int) ([]*service.AuditEvent, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("memory: ListAuditEventsForUser: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*service.AuditEvent, 0)
	for _, e := range r.auditEvents {
		if e.ActorUserID != userID && e.TargetUserID != userID {
			continue
		}
		cp := *e
		cp.Details = copyDetails(e.Details)
		out = append(out, &cp)
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

// DeleteAuditEventsBefore removes every stored audit event whose occurred-at
// instant (CreatedAt) is strictly older than cutoffMs, returning the number
// removed. It is the in-memory equivalent of the storage-limitation sweep the
// postgres/sqlite drivers run in batches; the map fits in memory, so it deletes
// the whole eligible set in one pass.
func (r *Repo) DeleteAuditEventsBefore(_ context.Context, cutoffMs int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	deleted := 0
	for id, e := range r.auditEvents {
		if e.CreatedAt < cutoffMs {
			delete(r.auditEvents, id)
			deleted++
		}
	}
	return deleted, nil
}

// copyDetails returns a shallow copy of an audit event's details map so the
// stored/returned event does not alias the caller's map. Nil in, nil out.
func copyDetails(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ── Identity Verification Records ─────────────────────────────────

func (r *Repo) CreateIdentityVerification(_ context.Context, rec *service.IdentityVerificationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.VerificationID == "" {
		return errors.New("identity verification: missing verification id")
	}
	if _, exists := r.idvRecords[rec.VerificationID]; exists {
		return fmt.Errorf("identity verification %s already exists", rec.VerificationID)
	}
	rec.NodeID = r.nextID()
	cp := *rec
	r.idvRecords[rec.VerificationID] = &cp
	return nil
}

func (r *Repo) GetIdentityVerification(_ context.Context, verificationID string) (*service.IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (r *Repo) GetLatestIdentityVerificationForUser(_ context.Context, userID string) (*service.IdentityVerificationRecord, error) {
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

func (r *Repo) UpdateIdentityVerificationStatus(_ context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return fmt.Errorf("identity verification %s not found", verificationID)
	}
	rec.Status = status
	rec.RejectionReason = rejectionReason
	rec.CompletedAt = completedAtMs
	rec.UpdatedAt = updatedAtMs
	return nil
}

// ── Sweepers ──────────────────────────────────────────────────────
//
// Each sweeper walks its map deleting rows whose ExpiresAt is
// strictly less than beforeMs, up to `limit` rows. limit <= 0 is
// rejected — the Repository contract requires implementations to
// refuse an unbounded delete batch so a buggy caller cannot stall
// the in-process map under the package lock.

func (r *Repo) DeleteExpiredWebAuthnChallenges(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredWebAuthnChallenges: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.passkeyChallenges {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.passkeyChallenges, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredEmailVerificationTokens(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredEmailVerificationTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.emailVerifications {
		if n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.emailVerifications, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredPasswordResetTokens(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredPasswordResetTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.passwordResets {
		if n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.passwordResets, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredEmailChangeTokens(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredEmailChangeTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.emailChanges {
		if n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.emailChanges, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredLoginChallenges(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredLoginChallenges: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.loginChallenges {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.loginChallenges, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredOAuthOneTimeCodes(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredOAuthOneTimeCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.oauthOneTimeCodes {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.oauthOneTimeCodes, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredNativeTokenRedemptions(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredNativeTokenRedemptions: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, e := range r.nativeRedemptions {
		if n >= limit {
			break
		}
		if e.ExpiresAt < beforeMs {
			delete(r.nativeRedemptions, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredEmailLoginCodes(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredEmailLoginCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.emailLoginCodes {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.emailLoginCodes, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredMagicLinkTokens(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredMagicLinkTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.magicLinkTokens {
		if n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.magicLinkTokens, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredPhoneVerificationCodes(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredPhoneVerificationCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.phoneVerifyCodes {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.phoneVerifyCodes, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredQrLoginSessions(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredQrLoginSessions: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, s := range r.qrSessions {
		if n >= limit {
			break
		}
		if s.ExpiresAt < beforeMs {
			delete(r.qrSessions, id)
			n++
		}
	}
	return nil
}

func (r *Repo) DeleteExpiredInvitations(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredInvitations: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, inv := range r.invitations {
		if n >= limit {
			break
		}
		if inv.ExpiresAt < beforeMs {
			delete(r.invitations, id)
			n++
		}
	}
	return nil
}

// ── Sessions ──────────────────────────────────────────────────────

func (r *Repo) CreateSession(_ context.Context, s *service.SessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("memory: CreateSession: nil session")
	}
	if s.SID == "" {
		return "", fmt.Errorf("%w: missing sid", service.ErrInvalidArgument)
	}
	if s.UserID == "" {
		return "", fmt.Errorf("%w: missing user_id", service.ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.sessions {
		if existing.SID == s.SID {
			return "", fmt.Errorf("%w: sid %q", service.ErrAlreadyExists, s.SID)
		}
	}
	id := r.nextID()
	s.NodeID = id
	cp := *s
	r.sessions[id] = &cp
	return id, nil
}

func (r *Repo) GetSessionBySid(_ context.Context, sid string) (*service.SessionRecord, error) {
	if sid == "" {
		return nil, nil
	}
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

// RevokeSession is idempotent: a no-op if the session does not exist
// or is already revoked. Concurrent revoke calls converge on the same
// final state rather than racing each other into failure.
func (r *Repo) RevokeSession(_ context.Context, sid string, atMs int64) error {
	if sid == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.SID == sid {
			if s.RevokedAtMs == 0 {
				s.RevokedAtMs = atMs
			}
			return nil
		}
	}
	return nil
}

// RevokeSessionsForUser revokes every active session for the user.
// Existing revoked rows are left alone so the original revoke
// timestamp survives.
func (r *Repo) RevokeSessionsForUser(_ context.Context, userID string, atMs int64) error {
	if userID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.UserID == userID && s.RevokedAtMs == 0 {
			s.RevokedAtMs = atMs
		}
	}
	return nil
}

// ── service.DB stub ───────────────────────────────────────────────
//
// The memory driver is Repository-first; raw-node access is not
// meaningful for the in-process map store. The DB stub returns
// service.ErrServiceUnavailable so services that do call into DB
// surface a clear error rather than silent corruption.

var errMemoryDBUnsupported = service.ErrServiceUnavailable

func (r *Repo) GetNode(context.Context, string, string, int, string) (*graph.Node, error) {
	return nil, errMemoryDBUnsupported
}

func (r *Repo) QueryNodes(context.Context, string, string, int, map[string]any) ([]*graph.Node, error) {
	return nil, errMemoryDBUnsupported
}

func (r *Repo) ExecuteAtomic(context.Context, string, string, []graph.Operation) (*graph.CommitResult, error) {
	return &graph.CommitResult{Success: true, Applied: true}, nil
}

func (r *Repo) GetEdgesFrom(context.Context, string, string, string, int) ([]*graph.Edge, error) {
	return nil, nil
}

func (r *Repo) GetEdgesTo(context.Context, string, string, string, int) ([]*graph.Edge, error) {
	return nil, nil
}

func (r *Repo) SearchNodes(context.Context, string, string, int, string) ([]*graph.Node, error) {
	return nil, errMemoryDBUnsupported
}

// RegisterUserInTenant is a no-op on the in-memory driver. The
// in-memory store bypasses the graph two-tier model entirely, so
// there is no global registry / tenant-membership to enforce.
func (r *Repo) RegisterUserInTenant(_ context.Context, _, _, _, _, _ string) error {
	return nil
}

// compile-time interface assertion
var (
	_ service.Repository = (*Repo)(nil)
	_ service.DB         = (*Repo)(nil)
)
