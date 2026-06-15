// Package entdb is the EntDB-backed implementation of
// service.Repository.
//
// Writes and point reads go through the upstream SDK's typed API.
// List-style reads go through the raw node transport because the
// current typed query path drops node ids and misbehaves for several
// auth-state filters this repository depends on.
package entdb

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"google.golang.org/protobuf/proto"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
	"github.com/elloloop/identity/internal/service"
)

// systemActor is the actor used for cross-user lookups (uniqueness
// queries, system bookkeeping) where there is no specific user.
//
// tenant-shard-db enforces actor-scoped row visibility: a `user:X`
// actor only sees rows X created. Cross-user reads (e.g.
// FindUserByEmail, the OAuth composite-uniqueness pre-check, the
// duplicate-user cleanup wait) MUST use a tenant-admin actor.
// `system:admin` is the upstream's tenant-admin namespace: it does
// not need to be a registered user, has tenant-wide read/write, and
// is the actor identity already passes to global-registry admin
// RPCs.
const systemActor = "system:admin"

// entRepository is the EntDB-backed implementation of
// service.Repository.
type entRepository struct {
	client   entClient
	tenantID string
}

type rawUpdateClient interface {
	rawUpdate(ctx context.Context, actor string, typeID int, nodeID string, patch map[string]any) error
}

// bulkDrainMaxIterations bounds the per-call bulk-delete drain loop
// for the DeleteXxxForUser sweeps. tenant-shard-db v1.14.0 (#530,
// SEC-4) clamps QueryNodes server-side at 1000 rows per call, so
// identity's user-scoped deletes that previously trusted "query
// returns every match" now silently truncate at the cap. Each
// delete-for-user method now loops query→delete until the query
// returns no rows; this constant is a sanity ceiling on the loop so
// a buggy backend that keeps returning the same row id forever
// cannot pin a goroutine. 100 iterations × 1000 rows/iter = 100_000
// per-user max, far above any plausible legitimate count for any of
// the four bulk-cleanup paths.
const bulkDrainMaxIterations = 100

// NewRepository constructs an EntDB-backed Repository using the SDK's
// public typed surface. The returned repository wraps every entClient
// call in an OpenTelemetry span (no-op when OTel is disabled).
func NewRepository(client *sdk.DbClient, tenantID string) service.Repository {
	return &entRepository{
		client:   newTracedClient(newSDKScope(client, tenantID)),
		tenantID: tenantID,
	}
}

func actorStr(userID string) string {
	if userID == "" {
		return systemActor
	}
	return "user:" + userID
}

// ── Users ──────────────────────────────────────────────────────────

func userFromProto(id string, p *schemapb.User) *service.User {
	if p == nil {
		return nil
	}
	return &service.User{
		ID:               id,
		Email:            p.GetEmail(),
		Name:             p.GetName(),
		Role:             p.GetRole(),
		AvatarURL:        p.GetAvatarUrl(),
		Status:           p.GetStatus(),
		RecoveryEmail:    p.GetRecoveryEmail(),
		QuotaBytes:       p.GetQuotaBytes(),
		TotpRequired:     p.GetTotpRequired(),
		PasswordHash:     p.GetPasswordHash(),
		FailedLoginCount: int(p.GetFailedLoginCount()),
		LockedUntil:      p.GetLockedUntil(),
		EmailVerified:    p.GetEmailVerified(),
		EmailVerifiedAt:  p.GetEmailVerifiedAt(),
		IDVVerified:      p.GetIdvVerified(),
		IDVVerifiedAt:    p.GetIdvVerifiedAt(),
		PhoneNumber:      p.GetPhoneNumber(),
		PhoneVerified:    p.GetPhoneVerified(),
		PhoneVerifiedAt:  p.GetPhoneVerifiedAt(),
		LastLoginAtMs:    p.GetLastLoginAt(),
		CreatedAt:        time.UnixMilli(p.GetCreatedAt()),
		UpdatedAt:        time.UnixMilli(p.GetUpdatedAt()),
	}
}

func (r *entRepository) FindUserByEmail(ctx context.Context, email string) (*service.User, error) {
	if email == "" {
		return nil, nil
	}
	dst := &schemapb.User{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.UserEmail, email, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindUserByEmail: %w", err)
	}
	return userFromProto(id, dst), nil
}

func (r *entRepository) GetUser(ctx context.Context, userID string) (*service.User, error) {
	if userID == "" {
		return nil, nil
	}
	dst := &schemapb.User{}
	// Reads go via systemActor (tenant-admin namespace). A fresh
	// signup's `user:<id>` actor isn't a tenant member until
	// CreateUser's ensureUserTenantMember step commits, so a
	// concurrent read from the same flow can still race with the
	// membership add. systemActor side-steps both the timing and the
	// "lookup id we never minted" cases (e.g. duplicate-signup's
	// fake token id, which should surface as NotFound rather than
	// ACCESS_DENIED).
	if err := r.client.get(ctx, systemActor, dst, userID); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("repo: GetUser: %w", err)
	}
	return userFromProto(userID, dst), nil
}

func (r *entRepository) CreateUser(ctx context.Context, u *service.User) (string, error) {
	if u == nil {
		return "", errors.New("repo: CreateUser: nil user")
	}
	now := time.Now().UnixMilli()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.UnixMilli(now)
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	msg := &schemapb.User{
		Email:            u.Email,
		Name:             u.Name,
		Role:             u.Role,
		AvatarUrl:        u.AvatarURL,
		PasswordHash:     u.PasswordHash,
		Status:           u.Status,
		RecoveryEmail:    u.RecoveryEmail,
		TotpRequired:     u.TotpRequired,
		FailedLoginCount: int64(u.FailedLoginCount),
		LockedUntil:      u.LockedUntil,
		QuotaBytes:       u.QuotaBytes,
		LastLoginAt:      u.LastLoginAtMs,
		EmailVerified:    u.EmailVerified,
		EmailVerifiedAt:  u.EmailVerifiedAt,
		IdvVerified:      u.IDVVerified,
		IdvVerifiedAt:    u.IDVVerifiedAt,
		PhoneNumber:      u.PhoneNumber,
		PhoneVerified:    u.PhoneVerified,
		PhoneVerifiedAt:  u.PhoneVerifiedAt,
		CreatedAt:        u.CreatedAt.UnixMilli(),
		UpdatedAt:        u.UpdatedAt.UnixMilli(),
	}
	id, err := r.client.create(ctx, systemActor, msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateUser: %w", err)
	}
	if err := r.waitForCanonicalUserByEmail(ctx, u.Email, id); err != nil {
		return "", fmt.Errorf("repo: CreateUser: %w", err)
	}
	// tenant-shard-db v1.12+ requires every actor to be a registered
	// user in the global registry AND a member of the tenant before
	// they can issue writes of their own. Identity uses each user's
	// own id as the actor for their refresh tokens, passkeys, audit
	// rows, etc., so without this every post-signup write is denied
	// ACCESS_DENIED. The call is idempotent.
	if err := r.client.ensureUserTenantMember(ctx, id, u.Email, u.Name, "member"); err != nil {
		return "", fmt.Errorf("repo: CreateUser: %w", err)
	}
	u.ID = id
	return id, nil
}

func (r *entRepository) waitForCanonicalUserByEmail(ctx context.Context, email, wantID string) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var lastErr error
	var stableSince time.Time
	for {
		rows, err := r.queryUsersByEmail(waitCtx, email)
		if err == nil && len(rows) > 0 {
			winnerID := canonicalUserNodeID(rows)
			switch {
			case winnerID == wantID && len(rows) == 1:
				if stableSince.IsZero() {
					stableSince = time.Now()
				}
				if time.Since(stableSince) >= 100*time.Millisecond {
					return nil
				}
			case winnerID == wantID:
				stableSince = time.Time{}
				if err := r.deleteOtherUsers(waitCtx, rows, wantID); err != nil {
					lastErr = err
				}
			default:
				if cleanupErr := r.deleteUser(waitCtx, wantID); cleanupErr != nil {
					return fmt.Errorf("duplicate user cleanup for %q: %w", wantID, cleanupErr)
				}
				return fmt.Errorf("email %q already claimed by %s", email, winnerID)
			}
		} else {
			stableSince = time.Time{}
		}
		if err != nil {
			lastErr = err
		}
		if waitCtx.Err() != nil {
			if lastErr != nil {
				return lastErr
			}
			return waitCtx.Err()
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (r *entRepository) queryUsersByEmail(ctx context.Context, email string) ([]queriedNode, error) {
	return r.client.query(ctx, systemActor, &schemapb.User{}, map[string]any{"email": email})
}

func canonicalUserNodeID(rows []queriedNode) string {
	if len(rows) == 0 {
		return ""
	}
	winner := rows[0]
	for _, row := range rows[1:] {
		if compareUserRows(row, winner) < 0 {
			winner = row
		}
	}
	return winner.NodeID
}

func compareUserRows(a, b queriedNode) int {
	ua := a.Message.(*schemapb.User)
	ub := b.Message.(*schemapb.User)
	switch {
	case ua.GetCreatedAt() < ub.GetCreatedAt():
		return -1
	case ua.GetCreatedAt() > ub.GetCreatedAt():
		return 1
	case a.NodeID < b.NodeID:
		return -1
	case a.NodeID > b.NodeID:
		return 1
	default:
		return 0
	}
}

func (r *entRepository) deleteOtherUsers(ctx context.Context, rows []queriedNode, keepID string) error {
	for _, row := range rows {
		if row.NodeID == keepID {
			continue
		}
		if err := r.deleteUser(ctx, row.NodeID); err != nil {
			return err
		}
	}
	return nil
}

func (r *entRepository) deleteUser(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	if err := r.client.delete(ctx, systemActor, &schemapb.User{}, nodeID); err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	return nil
}

// drainDeleteByUser removes every row of the witness type whose
// user_id equals userID, draining in a loop so a user with more than
// the server's per-query row cap (SEC-4, #530) still gets every row
// deleted. A fresh witness instance is allocated per query so the
// caller can pass a zero-value prototype. bulkDrainMaxIterations is the
// safety stop.
func (r *entRepository) drainDeleteByUser(ctx context.Context, userID string, newWitness func() proto.Message, label string) error {
	for i := 0; i < bulkDrainMaxIterations; i++ {
		rows, err := r.client.query(ctx, systemActor, newWitness(), map[string]any{"user_id": userID})
		if err != nil {
			return fmt.Errorf("repo: DeleteUser: %s query: %w", label, err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := r.client.delete(ctx, actorStr(userID), newWitness(), row.NodeID); err != nil &&
				!errors.Is(err, errNotFound) {
				return fmt.Errorf("repo: DeleteUser: %s delete: %w", label, err)
			}
		}
	}
	return fmt.Errorf("repo: DeleteUser: %s exceeded %d-iteration drain ceiling for user %q", label, bulkDrainMaxIterations, userID)
}

// DeleteUser physically removes the user node and drains every
// user-owned record keyed by user_id. Each drained type has its user_id
// field indexed in the schema so it can be enumerated and removed — this
// now covers both the durable identity/auth material (sessions, tokens,
// credentials, linked identities, org memberships) AND the short-lived
// tokens (password-reset, email-verification/change, passkey/login
// challenges, qr sessions, invitations, oauth one-time codes), which are
// indexed by user_id as of #168 so they are drained eagerly rather than
// left to the TTL sweepers. The only ephemeral artifacts NOT drained here
// are the email-keyed login codes / magic-link tokens, which carry no
// user_id; they are reaped by the sweepers (they reference a now-deleted
// user and never block email reuse). Audit events have no user_id edge
// and are retained for accountability. Idempotent: a missing user drains
// zero rows and the node delete is a no-op.
func (r *entRepository) DeleteUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	drains := []struct {
		label      string
		newWitness func() proto.Message
	}{
		{"refresh_token", func() proto.Message { return &schemapb.RefreshToken{} }},
		{"session", func() proto.Message { return &schemapb.Session{} }},
		{"oauth_identity", func() proto.Message { return &schemapb.OAuthIdentity{} }},
		{"passkey_credential", func() proto.Message { return &schemapb.PasskeyCredential{} }},
		{"totp_credential", func() proto.Message { return &schemapb.TotpCredential{} }},
		{"recovery_code", func() proto.Message { return &schemapb.RecoveryCode{} }},
		{"identity_verification", func() proto.Message { return &schemapb.IdentityVerificationRecord{} }},
		{"phone_verification_code", func() proto.Message { return &schemapb.PhoneVerificationCode{} }},
		// Ephemeral tokens, now user_id-indexed (#168) so they drain here
		// instead of waiting for the TTL sweepers. oauth_one_time_code was
		// already user_id-indexed but had been omitted from the drain — the
		// memory and postgres drivers remove it on DeleteUser, so entdb does
		// too.
		{"password_reset_token", func() proto.Message { return &schemapb.PasswordResetToken{} }},
		{"email_verification_token", func() proto.Message { return &schemapb.EmailVerificationToken{} }},
		{"email_change_token", func() proto.Message { return &schemapb.EmailChangeToken{} }},
		{"passkey_challenge", func() proto.Message { return &schemapb.PasskeyChallenge{} }},
		{"qr_login_session", func() proto.Message { return &schemapb.QrLoginSession{} }},
		{"login_challenge", func() proto.Message { return &schemapb.LoginChallenge{} }},
		{"user_invitation", func() proto.Message { return &schemapb.UserInvitation{} }},
		{"oauth_one_time_code", func() proto.Message { return &schemapb.OAuthOneTimeCode{} }},
	}
	for _, d := range drains {
		if err := r.drainDeleteByUser(ctx, userID, d.newWitness, d.label); err != nil {
			return err
		}
	}
	return r.deleteUser(ctx, userID)
}

func (r *entRepository) UpdateUser(ctx context.Context, userID string, fields map[string]any) error {
	if userID == "" {
		return errors.New("repo: UpdateUser: missing user id")
	}
	if needsFullUserRewrite(fields) {
		if raw, ok := r.client.(rawUpdateClient); ok {
			if err := raw.rawUpdate(ctx, actorStr(userID), 1, userID, userFieldPatch(fields)); err != nil {
				return fmt.Errorf("repo: UpdateUser: %w", err)
			}
			return nil
		}
	}
	patch := &schemapb.User{}
	applied := applyUserFields(patch, fields)
	if !applied {
		return nil
	}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return fmt.Errorf("repo: UpdateUser: %w", err)
	}
	return nil
}

func (r *entRepository) SetUserEmailVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("repo: SetUserEmailVerified: missing user id")
	}
	patch := &schemapb.User{
		EmailVerified:   true,
		EmailVerifiedAt: atMs,
		UpdatedAt:       atMs,
	}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return fmt.Errorf("repo: SetUserEmailVerified: %w", err)
	}
	return nil
}

func (r *entRepository) SetUserIDVVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("repo: SetUserIDVVerified: missing user id")
	}
	patch := &schemapb.User{
		IdvVerified:   true,
		IdvVerifiedAt: atMs,
		UpdatedAt:     atMs,
	}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return fmt.Errorf("repo: SetUserIDVVerified: %w", err)
	}
	return nil
}

func (r *entRepository) SetUserPhoneVerified(ctx context.Context, userID, phoneNumber string, atMs int64) error {
	if userID == "" {
		return errors.New("repo: SetUserPhoneVerified: missing user id")
	}
	patch := &schemapb.User{
		PhoneNumber:     phoneNumber,
		PhoneVerified:   true,
		PhoneVerifiedAt: atMs,
		UpdatedAt:       atMs,
	}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return fmt.Errorf("repo: SetUserPhoneVerified: %w", err)
	}
	return nil
}

// IncrementFailedLoginCount atomically bumps the user's failed-login
// counter and returns the new value. It uses a read + compare-and-set
// retry loop so concurrent failed logins on the same account cannot lose
// updates (a plain read-modify-write let several attempts read the same
// base count and write the same +1, undercounting — a lockout-bypass
// risk) and cannot error out (the exact-value visibility wait inside the
// plain update path times out when a sibling increment supersedes the
// written value before it is observed).
func (r *entRepository) IncrementFailedLoginCount(ctx context.Context, userID string) (int32, error) {
	if userID == "" {
		return 0, errors.New("repo: IncrementFailedLoginCount: missing user id")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		user, err := r.GetUser(ctx, userID)
		if err != nil {
			return 0, fmt.Errorf("repo: IncrementFailedLoginCount: %w", err)
		}
		if user == nil {
			return 0, errors.New("repo: IncrementFailedLoginCount: user not found")
		}
		if user.FailedLoginCount >= math.MaxInt32 {
			return 0, errors.New("repo: IncrementFailedLoginCount: count overflow")
		}
		newCount := int32(user.FailedLoginCount + 1) // #nosec G115 -- bounds checked above.

		// CAS on the current count. On entdb a proto3-zero field is absent
		// on disk, so the 0->1 transition (and any increment right after a
		// reset to 0) must match the "field absent" precondition (nil)
		// rather than equals=0.
		var expect any = int64(user.FailedLoginCount)
		if user.FailedLoginCount == 0 {
			expect = nil
		}
		patch := &schemapb.User{FailedLoginCount: int64(newCount)}
		err = r.client.updateIfNoWait(ctx, actorStr(userID), userID, patch, "failed_login_count", expect)
		if errors.Is(err, errPreconditionFailed) {
			// A concurrent increment won this slot; re-read and retry.
			if time.Now().After(deadline) {
				return 0, errors.New("repo: IncrementFailedLoginCount: contention retry deadline exceeded")
			}
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("repo: IncrementFailedLoginCount: %w", err)
		}
		// Read-your-writes: wait until the count is observable as at least
		// our value. A concurrent higher increment also satisfies this, so
		// it can't time out the way an exact-value wait would.
		if err := r.awaitFailedLoginCountAtLeast(ctx, userID, int64(newCount)); err != nil {
			return 0, fmt.Errorf("repo: IncrementFailedLoginCount: %w", err)
		}
		return newCount, nil
	}
}

// awaitFailedLoginCountAtLeast blocks until a read of the user observes
// failed_login_count >= atLeast (the entdb canonical store applies a
// committed CAS asynchronously). Monotonic so concurrent increments only
// help it return sooner.
func (r *entRepository) awaitFailedLoginCountAtLeast(ctx context.Context, userID string, atLeast int64) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		u, err := r.GetUser(ctx, userID)
		if err != nil {
			return err
		}
		if u != nil && int64(u.FailedLoginCount) >= atLeast {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("failed_login_count for %s not visible at >=%d", userID, atLeast)
		}
		if err := sleepOrContextDone(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
}

func (r *entRepository) ResetFailedLoginCount(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("repo: ResetFailedLoginCount: missing user id")
	}
	// SDK Plan.Update walks the patch with proto3 Range, which skips
	// zero scalars. A typed *schemapb.User{FailedLoginCount: 0,
	// LockedUntil: 0} therefore emits nothing — the server applies an
	// empty patch and the lockout state stays set. Go through
	// rawUpdate so the field-id→value map carries the explicit zeros.
	if raw, ok := r.client.(rawUpdateClient); ok {
		patch := map[string]any{"9": int64(0), "10": int64(0)}
		if err := raw.rawUpdate(ctx, actorStr(userID), 1, userID, patch); err != nil {
			return fmt.Errorf("repo: ResetFailedLoginCount: %w", err)
		}
		return nil
	}
	// The in-memory entClient stub does not implement rawUpdate; it
	// uses a heuristic in mergePatch to clear the lockout fields when
	// it sees a "full user rewrite". Preserve that path for unit
	// tests that exercise the stub directly.
	user, err := r.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("repo: ResetFailedLoginCount: %w", err)
	}
	if user == nil {
		return errors.New("repo: ResetFailedLoginCount: user not found")
	}
	full := userProtoFromUser(user)
	if err := r.client.update(ctx, actorStr(userID), userID, full); err != nil {
		return fmt.Errorf("repo: ResetFailedLoginCount: %w", err)
	}
	return nil
}

func userProtoFromUser(user *service.User) *schemapb.User {
	if user == nil {
		return &schemapb.User{}
	}
	return &schemapb.User{
		Email:           user.Email,
		Name:            user.Name,
		Role:            user.Role,
		AvatarUrl:       user.AvatarURL,
		PasswordHash:    user.PasswordHash,
		TotpRequired:    user.TotpRequired,
		Status:          user.Status,
		RecoveryEmail:   user.RecoveryEmail,
		QuotaBytes:      user.QuotaBytes,
		LastLoginAt:     user.LastLoginAtMs,
		EmailVerified:   user.EmailVerified,
		EmailVerifiedAt: user.EmailVerifiedAt,
		IdvVerified:     user.IDVVerified,
		IdvVerifiedAt:   user.IDVVerifiedAt,
		CreatedAt:       user.CreatedAt.UnixMilli(),
		UpdatedAt:       user.UpdatedAt.UnixMilli(),
	}
}

func applyUserFields(dst *schemapb.User, fields map[string]any) bool {
	applied := false
	for k, v := range fields {
		switch k {
		case "email":
			dst.Email = asString(v)
			applied = true
		case "name":
			dst.Name = asString(v)
			applied = true
		case "role":
			dst.Role = asString(v)
			applied = true
		case "avatar_url":
			dst.AvatarUrl = asString(v)
			applied = true
		case "password_hash":
			dst.PasswordHash = asString(v)
			applied = true
		case "totp_required":
			dst.TotpRequired = asBool(v)
			applied = true
		case "failed_login_count":
			dst.FailedLoginCount = asInt64(v)
			applied = true
		case "locked_until":
			dst.LockedUntil = asInt64(v)
			applied = true
		case "status":
			dst.Status = asString(v)
			applied = true
		case "recovery_email":
			dst.RecoveryEmail = asString(v)
			applied = true
		case "quota_bytes":
			dst.QuotaBytes = asInt64(v)
			applied = true
		case "last_login_at":
			dst.LastLoginAt = asInt64(v)
			applied = true
		case "updated_at":
			dst.UpdatedAt = asInt64(v)
			applied = true
		case "email_verified":
			dst.EmailVerified = asBool(v)
			applied = true
		case "email_verified_at":
			dst.EmailVerifiedAt = asInt64(v)
			applied = true
		case "phone_number":
			dst.PhoneNumber = asString(v)
			applied = true
		case "phone_verified":
			dst.PhoneVerified = asBool(v)
			applied = true
		case "phone_verified_at":
			dst.PhoneVerifiedAt = asInt64(v)
			applied = true
		}
	}
	return applied
}

func needsFullUserRewrite(fields map[string]any) bool {
	for _, v := range fields {
		switch x := v.(type) {
		case bool:
			if !x {
				return true
			}
		case int:
			if x == 0 {
				return true
			}
		case int32:
			if x == 0 {
				return true
			}
		case int64:
			if x == 0 {
				return true
			}
		case string:
			if x == "" {
				return true
			}
		}
	}
	return false
}

func userFieldPatch(fields map[string]any) map[string]any {
	patch := make(map[string]any, len(fields))
	for k, v := range fields {
		switch k {
		case "email":
			patch["1"] = asString(v)
		case "name":
			patch["2"] = asString(v)
		case "role":
			patch["3"] = asString(v)
		case "avatar_url":
			patch["4"] = asString(v)
		case "password_hash":
			patch["7"] = asString(v)
		case "totp_required":
			patch["8"] = asBool(v)
		case "failed_login_count":
			patch["9"] = asInt64(v)
		case "locked_until":
			patch["10"] = asInt64(v)
		case "status":
			patch["11"] = asString(v)
		case "recovery_email":
			patch["12"] = asString(v)
		case "quota_bytes":
			patch["15"] = asInt64(v)
		case "last_login_at":
			patch["17"] = asInt64(v)
		case "updated_at":
			patch["6"] = asInt64(v)
		case "email_verified":
			patch["18"] = asBool(v)
		case "email_verified_at":
			patch["19"] = asInt64(v)
		case "phone_number":
			patch["22"] = asString(v)
		case "phone_verified":
			patch["23"] = asBool(v)
		case "phone_verified_at":
			patch["24"] = asInt64(v)
		}
	}
	return patch
}

func (r *entRepository) SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error {
	if userID == "" {
		return errors.New("repo: SetUserLockedUntil: missing user id")
	}
	patch := &schemapb.User{LockedUntil: lockedUntilMs}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return fmt.Errorf("repo: SetUserLockedUntil: %w", err)
	}
	return nil
}

// ── Refresh tokens ────────────────────────────────────────────────

func refreshTokenFromProto(id string, p *schemapb.RefreshToken) *service.RefreshTokenRecord {
	if p == nil {
		return nil
	}
	return &service.RefreshTokenRecord{
		NodeID:       id,
		TokenHash:    p.GetTokenHash(),
		UserID:       p.GetUserId(),
		DeviceInfo:   p.GetDeviceInfo(),
		DeviceName:   p.GetDeviceName(),
		IPAddress:    p.GetIpAddress(),
		UserAgent:    p.GetUserAgent(),
		ExpiresAt:    p.GetExpiresAt(),
		CreatedAt:    p.GetCreatedAt(),
		LastUsedAt:   p.GetLastUsedAt(),
		ConsumedAtMs: p.GetConsumedAt(),
	}
}

func (r *entRepository) FindRefreshTokenByHash(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, hash)
	if err != nil || rec == nil {
		return rec, err
	}
	if rec.ConsumedAtMs > 0 {
		// Consumed rows are surfaced via the IncludingConsumed
		// variant for replay detection only.
		return nil, nil
	}
	return rec, nil
}

func (r *entRepository) FindRefreshTokenByHashIncludingConsumed(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	if hash == "" {
		return nil, nil
	}
	dst := &schemapb.RefreshToken{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.RefreshTokenTokenHash, hash, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindRefreshTokenByHashIncludingConsumed: %w", err)
	}
	return refreshTokenFromProto(id, dst), nil
}

// ConsumeRefreshTokenByHash atomically marks the row consumed iff it
// is currently unconsumed. The CAS precondition is the serialization
// point: two replicas racing to rotate the same refresh token both
// submit UpdateIf(consumed_at is unset); exactly one commits and the
// other observes ErrUnauthenticated. Mirrors the Postgres backend's
// `UPDATE ... WHERE consumed_at_ms = 0` pattern.
//
// The precondition value is nil rather than int64(0) because proto3
// int64 fields with the zero value are not serialized on the wire and
// therefore not present in the EntDB on-disk payload. The server-side
// applier matches an absent field only when the expected value is also
// nil (preconditionMatches in tenant-shard-db's ops_update_node.go);
// passing int64(0) would always fail the precondition even on a
// genuinely unconsumed row. After rotation the field carries the
// commit timestamp, which is non-nil on disk and so also mismatches
// the nil precondition — every later attempt loses the race.
func (r *entRepository) ConsumeRefreshTokenByHash(ctx context.Context, hash string, atMs int64) error {
	if hash == "" {
		return service.ErrUnauthenticated
	}
	rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, hash)
	if err != nil {
		return fmt.Errorf("repo: ConsumeRefreshTokenByHash: %w", err)
	}
	if rec == nil {
		return service.ErrUnauthenticated
	}
	patch := &schemapb.RefreshToken{ConsumedAt: atMs}
	if err := r.client.updateIf(ctx, systemActor, rec.NodeID, patch, "consumed_at", nil); err != nil {
		if errors.Is(err, errPreconditionFailed) {
			// Another replica rotated this token first, or the row was
			// already consumed when we re-read above. Service layer
			// treats both as a replay/race loss.
			return service.ErrUnauthenticated
		}
		return fmt.Errorf("repo: ConsumeRefreshTokenByHash: %w", err)
	}
	return nil
}

func (r *entRepository) CreateRefreshToken(ctx context.Context, t *service.RefreshTokenRecord) (string, error) {
	if t == nil {
		return "", errors.New("repo: CreateRefreshToken: nil record")
	}
	msg := &schemapb.RefreshToken{
		TokenHash:  t.TokenHash,
		UserId:     t.UserID,
		DeviceInfo: t.DeviceInfo,
		DeviceName: t.DeviceName,
		IpAddress:  t.IPAddress,
		UserAgent:  t.UserAgent,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		LastUsedAt: t.LastUsedAt,
		ConsumedAt: t.ConsumedAtMs,
	}
	id, err := r.client.create(ctx, actorStr(t.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateRefreshToken: %w", err)
	}
	t.NodeID = id
	return id, nil
}

func (r *entRepository) DeleteRefreshToken(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	if err := r.client.delete(ctx, systemActor, &schemapb.RefreshToken{}, nodeID); err != nil {
		return fmt.Errorf("repo: DeleteRefreshToken: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteRefreshTokensForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	// tenant-shard-db v1.14.0's SEC-4 (#530) caps QueryNodes at 1000
	// rows per call. Drain in a loop so a user with more than 1000
	// refresh tokens still gets every row deleted; bulkDrainMaxIterations
	// is the safety stop.
	for i := 0; i < bulkDrainMaxIterations; i++ {
		rows, err := r.client.query(ctx, systemActor, &schemapb.RefreshToken{}, map[string]any{"user_id": userID})
		if err != nil {
			return fmt.Errorf("repo: DeleteRefreshTokensForUser query: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := r.client.delete(ctx, actorStr(userID), &schemapb.RefreshToken{}, row.NodeID); err != nil {
				return fmt.Errorf("repo: DeleteRefreshTokensForUser delete: %w", err)
			}
		}
	}
	return fmt.Errorf("repo: DeleteRefreshTokensForUser: exceeded %d-iteration drain ceiling for user %q (server side cap %d×iterations); investigate runaway token issuance", bulkDrainMaxIterations, userID, bulkDrainMaxIterations*1000)
}

// ── Passkey credentials ───────────────────────────────────────────

func passkeyCredFromProto(id string, p *schemapb.PasskeyCredential) *service.PasskeyCredRecord {
	if p == nil {
		return nil
	}
	return &service.PasskeyCredRecord{
		NodeID:       id,
		CredentialID: p.GetCredentialId(),
		UserID:       p.GetUserId(),
		PublicKey:    p.GetPublicKey(),
		SignCount:    p.GetSignCount(),
		DeviceName:   p.GetDeviceName(),
		AAGUID:       p.GetAaguid(),
		Transports:   p.GetTransports(),
		CreatedAt:    p.GetCreatedAt(),
		LastUsedAt:   p.GetLastUsedAt(),
	}
}

func (r *entRepository) ListPasskeyCredentials(ctx context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.PasskeyCredential{}, map[string]any{"user_id": userID})
	if err != nil {
		return nil, fmt.Errorf("repo: ListPasskeyCredentials: %w", err)
	}
	out := make([]*service.PasskeyCredRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, passkeyCredFromProto(row.NodeID, row.Message.(*schemapb.PasskeyCredential)))
	}
	return out, nil
}

func (r *entRepository) GetPasskeyCredentialByCredID(ctx context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
	if credentialID == "" {
		return nil, nil
	}
	dst := &schemapb.PasskeyCredential{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.PasskeyCredentialCredentialID, credentialID, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: GetPasskeyCredentialByCredID: %w", err)
	}
	return passkeyCredFromProto(id, dst), nil
}

func (r *entRepository) CreatePasskeyCredential(ctx context.Context, c *service.PasskeyCredRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: CreatePasskeyCredential: nil record")
	}
	msg := &schemapb.PasskeyCredential{
		CredentialId: c.CredentialID,
		UserId:       c.UserID,
		PublicKey:    c.PublicKey,
		SignCount:    c.SignCount,
		DeviceName:   c.DeviceName,
		Aaguid:       c.AAGUID,
		Transports:   c.Transports,
		CreatedAt:    c.CreatedAt,
		LastUsedAt:   c.LastUsedAt,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreatePasskeyCredential: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) UpdatePasskeyCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("repo: UpdatePasskeyCredential: missing node id")
	}
	patch := &schemapb.PasskeyCredential{}
	applied := false
	for k, v := range fields {
		switch k {
		case "sign_count":
			patch.SignCount = asInt64(v)
			applied = true
		case "last_used_at":
			patch.LastUsedAt = asInt64(v)
			applied = true
		case "device_name":
			patch.DeviceName = asString(v)
			applied = true
		}
	}
	if !applied {
		return nil
	}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
		return fmt.Errorf("repo: UpdatePasskeyCredential: %w", err)
	}
	return nil
}

// ── Passkey challenges ────────────────────────────────────────────

func passkeyChallengeFromProto(id string, p *schemapb.PasskeyChallenge) *service.PasskeyChallengeRecord {
	if p == nil {
		return nil
	}
	return &service.PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     p.GetChallenge(),
		UserID:        p.GetUserId(),
		ChallengeType: p.GetChallengeType(),
		ExpiresAt:     p.GetExpiresAt(),
		CreatedAt:     p.GetCreatedAt(),
	}
}

func (r *entRepository) GetPasskeyChallenge(ctx context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	if nodeID == "" {
		return nil, nil
	}
	dst := &schemapb.PasskeyChallenge{}
	if err := r.client.get(ctx, systemActor, dst, nodeID); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("repo: GetPasskeyChallenge: %w", err)
	}
	return passkeyChallengeFromProto(nodeID, dst), nil
}

func (r *entRepository) CreatePasskeyChallenge(ctx context.Context, c *service.PasskeyChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: CreatePasskeyChallenge: nil record")
	}
	msg := &schemapb.PasskeyChallenge{
		Challenge:     c.Challenge,
		UserId:        c.UserID,
		ChallengeType: c.ChallengeType,
		ExpiresAt:     c.ExpiresAt,
		CreatedAt:     c.CreatedAt,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreatePasskeyChallenge: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) DeletePasskeyChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	if err := r.client.delete(ctx, systemActor, &schemapb.PasskeyChallenge{}, nodeID); err != nil {
		return fmt.Errorf("repo: DeletePasskeyChallenge: %w", err)
	}
	return nil
}

// ── QR login sessions ─────────────────────────────────────────────

func qrSessionFromProto(id string, p *schemapb.QrLoginSession) *service.QrLoginSessionRecord {
	if p == nil {
		return nil
	}
	return &service.QrLoginSessionRecord{
		NodeID:             id,
		SessionID:          p.GetSessionId(),
		Status:             p.GetStatus(),
		UserID:             p.GetUserId(),
		NewDeviceInfo:      p.GetNewDeviceInfo(),
		NewDeviceIP:        p.GetNewDeviceIp(),
		NewDeviceUserAgent: p.GetNewDeviceUserAgent(),
		ApprovedDeviceInfo: p.GetApprovedDeviceInfo(),
		PollSecretHash:     p.GetPollSecretHash(),
		ExpiresAt:          p.GetExpiresAt(),
		CreatedAt:          p.GetCreatedAt(),
		UpdatedAt:          p.GetUpdatedAt(),
	}
}

func (r *entRepository) FindQrLoginSession(ctx context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
	if sessionID == "" {
		return nil, nil
	}
	dst := &schemapb.QrLoginSession{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.QrLoginSessionSessionID, sessionID, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindQrLoginSession: %w", err)
	}
	return qrSessionFromProto(id, dst), nil
}

func (r *entRepository) CreateQrLoginSession(ctx context.Context, s *service.QrLoginSessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("repo: CreateQrLoginSession: nil record")
	}
	msg := &schemapb.QrLoginSession{
		SessionId:          s.SessionID,
		Status:             s.Status,
		UserId:             s.UserID,
		NewDeviceInfo:      s.NewDeviceInfo,
		NewDeviceIp:        s.NewDeviceIP,
		NewDeviceUserAgent: s.NewDeviceUserAgent,
		ApprovedDeviceInfo: s.ApprovedDeviceInfo,
		PollSecretHash:     s.PollSecretHash,
		ExpiresAt:          s.ExpiresAt,
		CreatedAt:          s.CreatedAt,
		UpdatedAt:          s.UpdatedAt,
	}
	id, err := r.client.create(ctx, systemActor, msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateQrLoginSession: %w", err)
	}
	s.NodeID = id
	return id, nil
}

func (r *entRepository) UpdateQrLoginSession(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("repo: UpdateQrLoginSession: missing node id")
	}
	patch := &schemapb.QrLoginSession{}
	applied := false
	for k, v := range fields {
		switch k {
		case "status":
			patch.Status = asString(v)
			applied = true
		case "user_id":
			patch.UserId = asString(v)
			applied = true
		case "approved_device_info":
			patch.ApprovedDeviceInfo = asString(v)
			applied = true
		case "updated_at":
			patch.UpdatedAt = asInt64(v)
			applied = true
		}
	}
	if !applied {
		return nil
	}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
		return fmt.Errorf("repo: UpdateQrLoginSession: %w", err)
	}
	return nil
}

// ConsumeQrLoginSession transitions status from "approved" to
// "consumed" atomically via the SDK's UpdateIf primitive. The server
// evaluates the precondition against the materialized node state, so
// two replicas racing on the same session row resolve to exactly one
// winner; the loser's plan aborts with ErrPreconditionFailed and this
// method returns service.ErrQrLoginNotPending.
func (r *entRepository) ConsumeQrLoginSession(ctx context.Context, nodeID string, atMs int64) error {
	if nodeID == "" {
		return service.ErrQrLoginNotPending
	}
	patch := &schemapb.QrLoginSession{
		Status:    "consumed",
		UpdatedAt: atMs,
	}
	err := r.client.updateIf(ctx, systemActor, nodeID, patch, "status", "approved")
	if errors.Is(err, errPreconditionFailed) {
		return service.ErrQrLoginNotPending
	}
	if err != nil {
		return fmt.Errorf("repo: ConsumeQrLoginSession: %w", err)
	}
	return nil
}

// ── OAuth one-time codes ──────────────────────────────────────────

func oauthOneTimeCodeFromProto(id string, p *schemapb.OAuthOneTimeCode) *service.OAuthOneTimeCodeRecord {
	if p == nil {
		return nil
	}
	return &service.OAuthOneTimeCodeRecord{
		NodeID:     id,
		CodeHash:   p.GetCodeHash(),
		UserID:     p.GetUserId(),
		ExpiresAt:  p.GetExpiresAt(),
		CreatedAt:  p.GetCreatedAt(),
		ConsumedAt: p.GetConsumedAt(),
	}
}

func (r *entRepository) CreateOAuthOneTimeCode(ctx context.Context, c *service.OAuthOneTimeCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: CreateOAuthOneTimeCode: nil record")
	}
	msg := &schemapb.OAuthOneTimeCode{
		CodeHash:   c.CodeHash,
		UserId:     c.UserID,
		ExpiresAt:  c.ExpiresAt,
		CreatedAt:  c.CreatedAt,
		ConsumedAt: c.ConsumedAt,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateOAuthOneTimeCode: %w", err)
	}
	c.NodeID = id
	return id, nil
}

// ConsumeOAuthOneTimeCode resolves the code by its unique code_hash,
// rejects an already-consumed or expired code, then flips consumed_at
// via the SDK's UpdateIf compare-and-set gated on consumed_at == 0.
// Two replicas racing the same code resolve to exactly one winner; the
// loser's plan aborts with ErrPreconditionFailed and this method
// returns service.ErrOAuthCodeInvalid — the same shape a replay sees.
func (r *entRepository) ConsumeOAuthOneTimeCode(ctx context.Context, codeHash string, atMs int64) (*service.OAuthOneTimeCodeRecord, error) {
	if codeHash == "" {
		return nil, service.ErrOAuthCodeInvalid
	}
	dst := &schemapb.OAuthOneTimeCode{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.OAuthOneTimeCodeCodeHash, codeHash, dst)
	if errors.Is(err, errNotFound) {
		return nil, service.ErrOAuthCodeInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumeOAuthOneTimeCode: %w", err)
	}
	if dst.GetConsumedAt() != 0 || dst.GetExpiresAt() <= atMs {
		return nil, service.ErrOAuthCodeInvalid
	}

	// The precondition value is nil (not int64(0)) because a proto3
	// int64 with the zero value is not serialized on the wire and so is
	// absent from the EntDB payload; the server applier matches an absent
	// field only against a nil expected value. This mirrors
	// ConsumeRefreshTokenByHash. After consumption the field carries the
	// timestamp, which is non-nil and so loses the nil precondition on a
	// replay.
	patch := &schemapb.OAuthOneTimeCode{ConsumedAt: atMs}
	err = r.client.updateIf(ctx, systemActor, id, patch, "consumed_at", nil)
	if errors.Is(err, errPreconditionFailed) {
		return nil, service.ErrOAuthCodeInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumeOAuthOneTimeCode: %w", err)
	}

	rec := oauthOneTimeCodeFromProto(id, dst)
	rec.ConsumedAt = atMs
	return rec, nil
}

// ── Email login codes (passwordless OTP) ──────────────────────────

func emailLoginCodeFromProto(id string, p *schemapb.EmailLoginCode) *service.EmailLoginCodeRecord {
	if p == nil {
		return nil
	}
	return &service.EmailLoginCodeRecord{
		NodeID:       id,
		Email:        p.GetEmail(),
		CodeHash:     p.GetCodeHash(),
		ExpiresAt:    p.GetExpiresAt(),
		CreatedAt:    p.GetCreatedAt(),
		ConsumedAt:   p.GetConsumedAt(),
		AttemptCount: p.GetAttemptCount(),
		MaxAttempts:  p.GetMaxAttempts(),
	}
}

// UpsertEmailLoginCode replaces any existing code for the email so at
// most one is live per address. The email field is unique, and the SDK
// has no upsert primitive, so this deletes the prior row (if any) then
// creates the fresh one. The brief gap between delete and create is
// acceptable: a concurrent request for the same email simply produces a
// second create that the unique constraint or the next read resolves to
// one live code; OTP requests for one address do not race meaningfully.
func (r *entRepository) UpsertEmailLoginCode(ctx context.Context, c *service.EmailLoginCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: UpsertEmailLoginCode: nil record")
	}
	prev := &schemapb.EmailLoginCode{}
	prevID, err := r.client.findByKey(ctx, systemActor, schemapb.EmailLoginCodeEmail, c.Email, prev)
	switch {
	case err == nil:
		if delErr := r.client.delete(ctx, systemActor, &schemapb.EmailLoginCode{}, prevID); delErr != nil &&
			!errors.Is(delErr, errNotFound) {
			return "", fmt.Errorf("repo: UpsertEmailLoginCode: replace: %w", delErr)
		}
	case errors.Is(err, errNotFound):
		// No prior code — fall through to create.
	default:
		return "", fmt.Errorf("repo: UpsertEmailLoginCode: %w", err)
	}

	msg := &schemapb.EmailLoginCode{
		Email:        c.Email,
		CodeHash:     c.CodeHash,
		ExpiresAt:    c.ExpiresAt,
		CreatedAt:    c.CreatedAt,
		ConsumedAt:   c.ConsumedAt,
		AttemptCount: c.AttemptCount,
		MaxAttempts:  c.MaxAttempts,
	}
	id, err := r.client.create(ctx, systemActor, msg)
	if err != nil {
		return "", fmt.Errorf("repo: UpsertEmailLoginCode: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) FindEmailLoginCodeByEmail(ctx context.Context, email string) (*service.EmailLoginCodeRecord, error) {
	dst := &schemapb.EmailLoginCode{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.EmailLoginCodeEmail, email, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailLoginCodeByEmail: %w", err)
	}
	return emailLoginCodeFromProto(id, dst), nil
}

func (r *entRepository) IncrementEmailLoginCodeAttempts(ctx context.Context, nodeID string) error {
	dst := &schemapb.EmailLoginCode{}
	if err := r.client.get(ctx, systemActor, dst, nodeID); err != nil {
		if errors.Is(err, errNotFound) {
			return fmt.Errorf("repo: IncrementEmailLoginCodeAttempts: %w", errNotFound)
		}
		return fmt.Errorf("repo: IncrementEmailLoginCodeAttempts: %w", err)
	}
	patch := &schemapb.EmailLoginCode{AttemptCount: dst.GetAttemptCount() + 1}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
		return fmt.Errorf("repo: IncrementEmailLoginCodeAttempts: %w", err)
	}
	return nil
}

// ConsumeEmailLoginCode resolves the email's code, rejects an
// already-consumed or expired code, then flips consumed_at via the SDK's
// UpdateIf compare-and-set gated on consumed_at == 0 (nil precondition,
// as for ConsumeOAuthOneTimeCode). Two replicas racing the same email
// resolve to exactly one winner; the loser sees ErrEmailLoginCodeInvalid.
func (r *entRepository) ConsumeEmailLoginCode(ctx context.Context, email string, atMs int64) (*service.EmailLoginCodeRecord, error) {
	if email == "" {
		return nil, service.ErrEmailLoginCodeInvalid
	}
	dst := &schemapb.EmailLoginCode{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.EmailLoginCodeEmail, email, dst)
	if errors.Is(err, errNotFound) {
		return nil, service.ErrEmailLoginCodeInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumeEmailLoginCode: %w", err)
	}
	if dst.GetConsumedAt() != 0 || dst.GetExpiresAt() <= atMs {
		return nil, service.ErrEmailLoginCodeInvalid
	}

	patch := &schemapb.EmailLoginCode{ConsumedAt: atMs}
	err = r.client.updateIf(ctx, systemActor, id, patch, "consumed_at", nil)
	if errors.Is(err, errPreconditionFailed) {
		return nil, service.ErrEmailLoginCodeInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumeEmailLoginCode: %w", err)
	}

	rec := emailLoginCodeFromProto(id, dst)
	rec.ConsumedAt = atMs
	return rec, nil
}

// ── Magic link tokens (passwordless) ──────────────────────────────

func magicLinkTokenFromProto(id string, p *schemapb.MagicLinkToken) *service.MagicLinkTokenRecord {
	if p == nil {
		return nil
	}
	return &service.MagicLinkTokenRecord{
		NodeID:     id,
		TokenHash:  p.GetTokenHash(),
		Email:      p.GetEmail(),
		ReturnTo:   p.GetReturnTo(),
		ExpiresAt:  p.GetExpiresAt(),
		CreatedAt:  p.GetCreatedAt(),
		ConsumedAt: p.GetConsumedAt(),
	}
}

func (r *entRepository) CreateMagicLinkToken(ctx context.Context, t *service.MagicLinkTokenRecord) (string, error) {
	if t == nil {
		return "", errors.New("repo: CreateMagicLinkToken: nil record")
	}
	msg := &schemapb.MagicLinkToken{
		TokenHash:  t.TokenHash,
		Email:      t.Email,
		ReturnTo:   t.ReturnTo,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
	id, err := r.client.create(ctx, systemActor, msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateMagicLinkToken: %w", err)
	}
	t.NodeID = id
	return id, nil
}

// ConsumeMagicLinkToken resolves the token by its unique token_hash,
// rejects an already-consumed or expired token, then flips consumed_at
// via UpdateIf gated on consumed_at == 0. Single-winner across replicas;
// the loser and any replay see ErrMagicLinkInvalid.
func (r *entRepository) ConsumeMagicLinkToken(ctx context.Context, tokenHash string, atMs int64) (*service.MagicLinkTokenRecord, error) {
	if tokenHash == "" {
		return nil, service.ErrMagicLinkInvalid
	}
	dst := &schemapb.MagicLinkToken{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.MagicLinkTokenTokenHash, tokenHash, dst)
	if errors.Is(err, errNotFound) {
		return nil, service.ErrMagicLinkInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumeMagicLinkToken: %w", err)
	}
	if dst.GetConsumedAt() != 0 || dst.GetExpiresAt() <= atMs {
		return nil, service.ErrMagicLinkInvalid
	}

	patch := &schemapb.MagicLinkToken{ConsumedAt: atMs}
	err = r.client.updateIf(ctx, systemActor, id, patch, "consumed_at", nil)
	if errors.Is(err, errPreconditionFailed) {
		return nil, service.ErrMagicLinkInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumeMagicLinkToken: %w", err)
	}

	rec := magicLinkTokenFromProto(id, dst)
	rec.ConsumedAt = atMs
	return rec, nil
}

// ── TOTP credentials ──────────────────────────────────────────────

func totpCredFromProto(id string, p *schemapb.TotpCredential) *service.TotpCredRecord {
	if p == nil {
		return nil
	}
	return &service.TotpCredRecord{
		NodeID:          id,
		UserID:          p.GetUserId(),
		SecretEncrypted: p.GetSecretEncrypted(),
		Verified:        p.GetVerified(),
		CreatedAt:       p.GetCreatedAt(),
		LastUsedAt:      p.GetLastUsedAt(),
	}
}

func (r *entRepository) GetTotpCredential(ctx context.Context, userID string) (*service.TotpCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.TotpCredential{}, map[string]any{"user_id": userID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetTotpCredential: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return totpCredFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.TotpCredential)), nil
}

func (r *entRepository) CreateTotpCredential(ctx context.Context, c *service.TotpCredRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: CreateTotpCredential: nil record")
	}
	msg := &schemapb.TotpCredential{
		UserId:          c.UserID,
		SecretEncrypted: c.SecretEncrypted,
		Verified:        c.Verified,
		CreatedAt:       c.CreatedAt,
		LastUsedAt:      c.LastUsedAt,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateTotpCredential: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) UpdateTotpCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("repo: UpdateTotpCredential: missing node id")
	}
	patch := &schemapb.TotpCredential{}
	var names []string
	for k, v := range fields {
		switch k {
		case "verified":
			patch.Verified = asBool(v)
			names = append(names, "verified")
		case "last_used_at":
			patch.LastUsedAt = asInt64(v)
			names = append(names, "last_used_at")
		case "secret_encrypted":
			patch.SecretEncrypted = asString(v)
			names = append(names, "secret_encrypted")
		}
	}
	if len(names) == 0 {
		return nil
	}
	// Explicit-fields update so "verified=false" (a proto3 zero) is sent
	// instead of being dropped as an unset field.
	if err := r.client.updateFields(ctx, systemActor, nodeID, patch, names...); err != nil {
		return fmt.Errorf("repo: UpdateTotpCredential: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteTotpCredential(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	if err := r.client.delete(ctx, systemActor, &schemapb.TotpCredential{}, nodeID); err != nil {
		return fmt.Errorf("repo: DeleteTotpCredential: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteTotpCredentialsForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	// SEC-4 drain loop — see DeleteRefreshTokensForUser. Identity
	// expects at most one TOTP credential per user (the create path
	// deletes the previous row), but the cleanup must converge even
	// if a buggy seed or replay leaves stragglers.
	for i := 0; i < bulkDrainMaxIterations; i++ {
		rows, err := r.client.query(ctx, actorStr(userID), &schemapb.TotpCredential{}, map[string]any{"user_id": userID})
		if err != nil {
			return fmt.Errorf("repo: DeleteTotpCredentialsForUser query: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := r.client.delete(ctx, actorStr(userID), &schemapb.TotpCredential{}, row.NodeID); err != nil {
				return fmt.Errorf("repo: DeleteTotpCredentialsForUser delete: %w", err)
			}
		}
	}
	return fmt.Errorf("repo: DeleteTotpCredentialsForUser: exceeded %d-iteration drain ceiling for user %q", bulkDrainMaxIterations, userID)
}

// ── Recovery codes ────────────────────────────────────────────────

func recoveryCodeFromProto(id string, p *schemapb.RecoveryCode) *service.RecoveryCodeRecord {
	if p == nil {
		return nil
	}
	return &service.RecoveryCodeRecord{
		NodeID:    id,
		UserID:    p.GetUserId(),
		CodeHash:  p.GetCodeHash(),
		Used:      p.GetUsed(),
		CreatedAt: p.GetCreatedAt(),
		UsedAt:    p.GetUsedAt(),
	}
}

func (r *entRepository) CreateRecoveryCode(ctx context.Context, c *service.RecoveryCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: CreateRecoveryCode: nil record")
	}
	msg := &schemapb.RecoveryCode{
		UserId:    c.UserID,
		CodeHash:  c.CodeHash,
		Used:      c.Used,
		CreatedAt: c.CreatedAt,
		UsedAt:    c.UsedAt,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateRecoveryCode: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) FindRecoveryCodeByHash(ctx context.Context, userID, hash string) (*service.RecoveryCodeRecord, error) {
	if userID == "" || hash == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.RecoveryCode{}, map[string]any{"user_id": userID, "code_hash": hash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindRecoveryCodeByHash: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return recoveryCodeFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.RecoveryCode)), nil
}

func (r *entRepository) UpdateRecoveryCode(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("repo: UpdateRecoveryCode: missing node id")
	}
	patch := &schemapb.RecoveryCode{}
	applied := false
	for k, v := range fields {
		switch k {
		case "used":
			patch.Used = asBool(v)
			applied = true
		case "used_at":
			patch.UsedAt = asInt64(v)
			applied = true
		}
	}
	if !applied {
		return nil
	}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
		return fmt.Errorf("repo: UpdateRecoveryCode: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteRecoveryCodesForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	// SEC-4 drain loop — see DeleteRefreshTokensForUser. Recovery
	// codes are typically a single batch (~10 codes) but the cleanup
	// path must converge for any plausible count.
	for i := 0; i < bulkDrainMaxIterations; i++ {
		rows, err := r.client.query(ctx, actorStr(userID), &schemapb.RecoveryCode{}, map[string]any{"user_id": userID})
		if err != nil {
			return fmt.Errorf("repo: DeleteRecoveryCodesForUser query: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := r.client.delete(ctx, actorStr(userID), &schemapb.RecoveryCode{}, row.NodeID); err != nil {
				return fmt.Errorf("repo: DeleteRecoveryCodesForUser delete: %w", err)
			}
		}
	}
	return fmt.Errorf("repo: DeleteRecoveryCodesForUser: exceeded %d-iteration drain ceiling for user %q", bulkDrainMaxIterations, userID)
}

// ── Login challenges ──────────────────────────────────────────────

func loginChallengeFromProto(id string, p *schemapb.LoginChallenge) *service.LoginChallengeRecord {
	if p == nil {
		return nil
	}
	return &service.LoginChallengeRecord{
		NodeID:      id,
		ChallengeID: p.GetChallengeId(),
		UserID:      p.GetUserId(),
		ExpiresAt:   p.GetExpiresAt(),
		CreatedAt:   p.GetCreatedAt(),
	}
}

func (r *entRepository) CreateLoginChallenge(ctx context.Context, c *service.LoginChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: CreateLoginChallenge: nil record")
	}
	msg := &schemapb.LoginChallenge{
		ChallengeId: c.ChallengeID,
		UserId:      c.UserID,
		ExpiresAt:   c.ExpiresAt,
		CreatedAt:   c.CreatedAt,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateLoginChallenge: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) GetLoginChallengeByChallengeID(ctx context.Context, challengeID string) (*service.LoginChallengeRecord, error) {
	if challengeID == "" {
		return nil, nil
	}
	dst := &schemapb.LoginChallenge{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.LoginChallengeChallengeID, challengeID, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: GetLoginChallengeByChallengeID: %w", err)
	}
	return loginChallengeFromProto(id, dst), nil
}

func (r *entRepository) DeleteLoginChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	if err := r.client.delete(ctx, systemActor, &schemapb.LoginChallenge{}, nodeID); err != nil {
		return fmt.Errorf("repo: DeleteLoginChallenge: %w", err)
	}
	return nil
}

// ── User invitations ──────────────────────────────────────────────

func invitationFromProto(id string, p *schemapb.UserInvitation) *service.InvitationRecord {
	if p == nil {
		return nil
	}
	return &service.InvitationRecord{
		NodeID:     id,
		TokenHash:  p.GetTokenHash(),
		Email:      p.GetEmail(),
		UserID:     p.GetUserId(),
		InvitedBy:  p.GetInvitedBy(),
		Role:       p.GetRole(),
		ExpiresAt:  p.GetExpiresAt(),
		AcceptedAt: p.GetAcceptedAt(),
		CreatedAt:  p.GetCreatedAt(),
	}
}

func (r *entRepository) FindInvitationByHash(ctx context.Context, tokenHash string) (*service.InvitationRecord, error) {
	if tokenHash == "" {
		return nil, nil
	}
	dst := &schemapb.UserInvitation{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.UserInvitationTokenHash, tokenHash, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindInvitationByHash: %w", err)
	}
	return invitationFromProto(id, dst), nil
}

func (r *entRepository) UpdateInvitation(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return errors.New("repo: UpdateInvitation: missing node id")
	}
	patch := &schemapb.UserInvitation{}
	applied := false
	for k, v := range fields {
		switch k {
		case "accepted_at":
			patch.AcceptedAt = asInt64(v)
			applied = true
		case "user_id":
			patch.UserId = asString(v)
			applied = true
		}
	}
	if !applied {
		return nil
	}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
		return fmt.Errorf("repo: UpdateInvitation: %w", err)
	}
	return nil
}

// ── Password-reset tokens ─────────────────────────────────────────

func passwordResetFromProto(id string, p *schemapb.PasswordResetToken) *service.PasswordResetToken {
	if p == nil {
		return nil
	}
	return &service.PasswordResetToken{
		NodeID:     id,
		TokenHash:  p.GetTokenHash(),
		UserID:     p.GetUserId(),
		ExpiresAt:  p.GetExpiresAt(),
		CreatedAt:  p.GetCreatedAt(),
		ConsumedAt: p.GetConsumedAt(),
	}
}

func (r *entRepository) CreatePasswordResetToken(ctx context.Context, t *service.PasswordResetToken) error {
	if t == nil {
		return errors.New("repo: CreatePasswordResetToken: nil record")
	}
	msg := &schemapb.PasswordResetToken{
		TokenHash:  t.TokenHash,
		UserId:     t.UserID,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
	id, err := r.client.create(ctx, actorStr(t.UserID), msg)
	if err != nil {
		return fmt.Errorf("repo: CreatePasswordResetToken: %w", err)
	}
	t.NodeID = id
	return nil
}

func (r *entRepository) FindPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*service.PasswordResetToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	dst := &schemapb.PasswordResetToken{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.PasswordResetTokenTokenHash, tokenHash, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindPasswordResetTokenByHash: %w", err)
	}
	return passwordResetFromProto(id, dst), nil
}

func (r *entRepository) MarkPasswordResetTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return errors.New("repo: MarkPasswordResetTokenConsumed: missing token id")
	}
	patch := &schemapb.PasswordResetToken{ConsumedAt: atMs}
	if err := r.client.update(ctx, systemActor, tokenID, patch); err != nil {
		return fmt.Errorf("repo: MarkPasswordResetTokenConsumed: %w", err)
	}
	return nil
}

// ── Email-verification tokens ─────────────────────────────────────

func emailVerificationFromProto(id string, p *schemapb.EmailVerificationToken) *service.EmailVerificationToken {
	if p == nil {
		return nil
	}
	return &service.EmailVerificationToken{
		NodeID:     id,
		TokenHash:  p.GetTokenHash(),
		UserID:     p.GetUserId(),
		Email:      p.GetEmail(),
		ExpiresAt:  p.GetExpiresAt(),
		CreatedAt:  p.GetCreatedAt(),
		ConsumedAt: p.GetConsumedAt(),
	}
}

func (r *entRepository) CreateEmailVerificationToken(ctx context.Context, t *service.EmailVerificationToken) error {
	if t == nil {
		return errors.New("repo: CreateEmailVerificationToken: nil record")
	}
	msg := &schemapb.EmailVerificationToken{
		TokenHash:  t.TokenHash,
		UserId:     t.UserID,
		Email:      t.Email,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
	id, err := r.client.create(ctx, actorStr(t.UserID), msg)
	if err != nil {
		return fmt.Errorf("repo: CreateEmailVerificationToken: %w", err)
	}
	t.NodeID = id
	return nil
}

func (r *entRepository) FindEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*service.EmailVerificationToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	dst := &schemapb.EmailVerificationToken{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.EmailVerificationTokenTokenHash, tokenHash, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailVerificationTokenByHash: %w", err)
	}
	return emailVerificationFromProto(id, dst), nil
}

func (r *entRepository) MarkEmailVerificationTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return errors.New("repo: MarkEmailVerificationTokenConsumed: missing token id")
	}
	patch := &schemapb.EmailVerificationToken{ConsumedAt: atMs}
	if err := r.client.update(ctx, systemActor, tokenID, patch); err != nil {
		return fmt.Errorf("repo: MarkEmailVerificationTokenConsumed: %w", err)
	}
	return nil
}

// ── Email-change tokens ───────────────────────────────────────────

func emailChangeFromProto(id string, p *schemapb.EmailChangeToken) *service.EmailChangeToken {
	if p == nil {
		return nil
	}
	return &service.EmailChangeToken{
		NodeID:     id,
		TokenHash:  p.GetTokenHash(),
		UserID:     p.GetUserId(),
		OldEmail:   p.GetOldEmail(),
		NewEmail:   p.GetNewEmail(),
		ExpiresAt:  p.GetExpiresAt(),
		CreatedAt:  p.GetCreatedAt(),
		ConsumedAt: p.GetConsumedAt(),
	}
}

func (r *entRepository) CreateEmailChangeToken(ctx context.Context, t *service.EmailChangeToken) error {
	if t == nil {
		return errors.New("repo: CreateEmailChangeToken: nil record")
	}
	msg := &schemapb.EmailChangeToken{
		TokenHash:  t.TokenHash,
		UserId:     t.UserID,
		OldEmail:   t.OldEmail,
		NewEmail:   t.NewEmail,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
	id, err := r.client.create(ctx, actorStr(t.UserID), msg)
	if err != nil {
		return fmt.Errorf("repo: CreateEmailChangeToken: %w", err)
	}
	t.NodeID = id
	return nil
}

func (r *entRepository) FindEmailChangeTokenByHash(ctx context.Context, tokenHash string) (*service.EmailChangeToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	dst := &schemapb.EmailChangeToken{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.EmailChangeTokenTokenHash, tokenHash, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailChangeTokenByHash: %w", err)
	}
	return emailChangeFromProto(id, dst), nil
}

func (r *entRepository) MarkEmailChangeTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return errors.New("repo: MarkEmailChangeTokenConsumed: missing token id")
	}
	patch := &schemapb.EmailChangeToken{ConsumedAt: atMs}
	if err := r.client.update(ctx, systemActor, tokenID, patch); err != nil {
		return fmt.Errorf("repo: MarkEmailChangeTokenConsumed: %w", err)
	}
	return nil
}

func (r *entRepository) UpdateUserEmail(ctx context.Context, userID, newEmail string, atMs int64) error {
	if userID == "" {
		return errors.New("repo: UpdateUserEmail: missing user id")
	}
	patch := &schemapb.User{
		Email:           newEmail,
		EmailVerified:   true,
		EmailVerifiedAt: atMs,
		UpdatedAt:       atMs,
	}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return fmt.Errorf("repo: UpdateUserEmail: %w", err)
	}
	return nil
}

// ── OAuthIdentity ─────────────────────────────────────────────────

func oauthIdentityFromProto(id string, p *schemapb.OAuthIdentity) *service.OAuthIdentity {
	if p == nil {
		return nil
	}
	return &service.OAuthIdentity{
		NodeID:          id,
		UserID:          p.GetUserId(),
		Provider:        p.GetProvider(),
		ProviderUserID:  p.GetProviderUserId(),
		EmailAtLinkTime: p.GetEmailAtLinkTime(),
		CreatedAt:       p.GetCreatedAt(),
	}
}

func (r *entRepository) FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*service.User, error) {
	if provider == "" || providerUserID == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, systemActor, &schemapb.OAuthIdentity{}, map[string]any{"provider": provider, "provider_user_id": providerUserID})
	if err != nil {
		return nil, fmt.Errorf("repo: FindUserByProviderID: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	link := oauthIdentityFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.OAuthIdentity))
	return r.GetUser(ctx, link.UserID)
}

func (r *entRepository) CreateOAuthIdentity(ctx context.Context, oi *service.OAuthIdentity) error {
	if oi == nil {
		return errors.New("repo: CreateOAuthIdentity: nil record")
	}
	// Server-side composite uniqueness on (provider, provider_user_id)
	// is enforced atomically by the entdb server: OAuthIdentity declares
	// (entdb.node).composite_unique = {provider, provider_user_id} and
	// the SDK auto-attaches the schema to ExecuteAtomic (ADR-031), so
	// concurrent creates with the same tuple collide on a real unique
	// index. We still pre-query here so the *common* "already linked"
	// case returns the friendly composite-violation message instead of
	// the generic UniqueConstraintError surfaced by the SDK on the
	// create itself, and so the in-memory fake (which has no schema
	// path) keeps the same observable behavior.
	dups, err := r.client.query(ctx, systemActor, &schemapb.OAuthIdentity{}, map[string]any{"provider": oi.Provider, "provider_user_id": oi.ProviderUserID})
	if err != nil {
		return fmt.Errorf("repo: CreateOAuthIdentity dup-check: %w", err)
	}
	if len(dups) > 0 {
		return fmt.Errorf("repo: CreateOAuthIdentity: composite unique violated (%s, %s)", oi.Provider, oi.ProviderUserID)
	}
	msg := &schemapb.OAuthIdentity{
		UserId:          oi.UserID,
		Provider:        oi.Provider,
		ProviderUserId:  oi.ProviderUserID,
		EmailAtLinkTime: oi.EmailAtLinkTime,
		CreatedAt:       oi.CreatedAt,
	}
	id, err := r.client.create(ctx, actorStr(oi.UserID), msg)
	if err != nil {
		return fmt.Errorf("repo: CreateOAuthIdentity: %w", err)
	}
	oi.NodeID = id
	return nil
}

func (r *entRepository) ListOAuthIdentitiesForUser(ctx context.Context, userID string) ([]*service.OAuthIdentity, error) {
	if userID == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, systemActor, &schemapb.OAuthIdentity{}, map[string]any{"user_id": userID})
	if err != nil {
		return nil, fmt.Errorf("repo: ListOAuthIdentitiesForUser: %w", err)
	}
	out := make([]*service.OAuthIdentity, 0, len(rows))
	for _, row := range rows {
		out = append(out, oauthIdentityFromProto(row.NodeID, row.Message.(*schemapb.OAuthIdentity)))
	}
	return out, nil
}

// ── Identity-verification records ─────────────────────────────────

// identityVerificationFromProto rehydrates a *service.IdentityVerificationRecord
// from the wire payload. tenantID is the repository's tenant scope —
// the proto has no tenant_id field because identity-tenant ↔ entdb-tenant
// is 1:1 (per docs/IDENTITY.md): the storage scope IS the tenant. Reads
// always know which tenant they're reading from, so the field is
// synthesised here rather than persisted on every row.
func identityVerificationFromProto(id, tenantID string, p *schemapb.IdentityVerificationRecord) *service.IdentityVerificationRecord {
	if p == nil {
		return nil
	}
	return &service.IdentityVerificationRecord{
		NodeID:            id,
		VerificationID:    p.GetVerificationId(),
		UserID:            p.GetUserId(),
		TenantID:          tenantID,
		Provider:          p.GetProvider(),
		ProviderSessionID: p.GetProviderSessionId(),
		Status:            p.GetStatus(),
		CreatedAt:         p.GetCreatedAt(),
		UpdatedAt:         p.GetUpdatedAt(),
		CompletedAt:       p.GetCompletedAt(),
		RejectionReason:   p.GetRejectionReason(),
	}
}

func (r *entRepository) CreateIdentityVerification(ctx context.Context, rec *service.IdentityVerificationRecord) error {
	if rec == nil {
		return errors.New("repo: CreateIdentityVerification: nil record")
	}
	if rec.VerificationID == "" {
		return errors.New("repo: CreateIdentityVerification: missing verification id")
	}
	msg := &schemapb.IdentityVerificationRecord{
		VerificationId:    rec.VerificationID,
		UserId:            rec.UserID,
		Provider:          rec.Provider,
		ProviderSessionId: rec.ProviderSessionID,
		Status:            rec.Status,
		CreatedAt:         rec.CreatedAt,
		UpdatedAt:         rec.UpdatedAt,
		CompletedAt:       rec.CompletedAt,
		RejectionReason:   rec.RejectionReason,
	}
	id, err := r.client.create(ctx, actorStr(rec.UserID), msg)
	if err != nil {
		return fmt.Errorf("repo: CreateIdentityVerification: %w", err)
	}
	rec.NodeID = id
	if err := r.awaitIdentityVerificationVisible(ctx, rec); err != nil {
		return fmt.Errorf("repo: CreateIdentityVerification: %w", err)
	}
	return nil
}

// awaitIdentityVerificationVisible blocks until a freshly created IDV
// record is observable through both secondary read paths the service
// fetches it by: GetIdentityVerification's verification_id unique-key
// lookup and GetLatestIdentityVerificationForUser's user_id filter
// query.
//
// sdkScope.create already waits for the node to be visible by its node
// id, but on entdb the secondary unique-key and filter indexes are
// applied to the canonical store asynchronously, a beat behind the node
// itself. The IDV RPC pair issues a write immediately followed by a
// read through one of those indexes (Begin→GetStatus by id, or
// Begin→GetLatest by user), so without this wait the read can race the
// index apply and observe nothing — the entdb-only read-after-write
// flake the nightly suite kept tripping on. Waiting here upholds the
// repository's "a write is visible to the next read" contract for the
// access patterns IDV actually uses. On the in-memory test backend both
// reads are synchronous, so the first poll returns immediately.
func (r *entRepository) awaitIdentityVerificationVisible(ctx context.Context, rec *service.IdentityVerificationRecord) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		byKey, err := r.GetIdentityVerification(ctx, rec.VerificationID)
		if err != nil {
			return err
		}
		var latest *service.IdentityVerificationRecord
		if byKey != nil {
			latest, err = r.GetLatestIdentityVerificationForUser(ctx, rec.UserID)
			if err != nil {
				return err
			}
		}
		// Probe both reader paths through the exact methods the service
		// calls. The user_id filter index reflects the write once
		// GetLatest returns a row at least as new as this one (it may be
		// a newer concurrent record — that still means our own write is
		// no longer racing the index apply).
		if byKey != nil && latest != nil && latest.CreatedAt >= rec.CreatedAt {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("identity verification %s not visible after create", rec.VerificationID)
		}
		if err := sleepOrContextDone(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
}

func (r *entRepository) GetIdentityVerification(ctx context.Context, verificationID string) (*service.IdentityVerificationRecord, error) {
	if verificationID == "" {
		return nil, nil
	}
	dst := &schemapb.IdentityVerificationRecord{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.IdentityVerificationRecordVerificationID, verificationID, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: GetIdentityVerification: %w", err)
	}
	return identityVerificationFromProto(id, r.tenantID, dst), nil
}

func (r *entRepository) GetLatestIdentityVerificationForUser(ctx context.Context, userID string) (*service.IdentityVerificationRecord, error) {
	if userID == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.IdentityVerificationRecord{}, map[string]any{"user_id": userID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetLatestIdentityVerificationForUser: %w", err)
	}
	var latest *service.IdentityVerificationRecord
	for _, row := range rows {
		rec := identityVerificationFromProto(row.NodeID, r.tenantID, row.Message.(*schemapb.IdentityVerificationRecord))
		if latest == nil || rec.CreatedAt > latest.CreatedAt {
			latest = rec
		}
	}
	return latest, nil
}

func (r *entRepository) UpdateIdentityVerificationStatus(ctx context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error {
	if verificationID == "" {
		return errors.New("repo: UpdateIdentityVerificationStatus: missing verification id")
	}
	rec, err := r.GetIdentityVerification(ctx, verificationID)
	if err != nil {
		return fmt.Errorf("repo: UpdateIdentityVerificationStatus: lookup: %w", err)
	}
	if rec == nil {
		return errors.New("repo: UpdateIdentityVerificationStatus: not found")
	}
	patch := &schemapb.IdentityVerificationRecord{
		Status:          status,
		RejectionReason: rejectionReason,
		CompletedAt:     completedAtMs,
		UpdatedAt:       updatedAtMs,
	}
	if err := r.client.update(ctx, systemActor, rec.NodeID, patch); err != nil {
		return fmt.Errorf("repo: UpdateIdentityVerificationStatus: %w", err)
	}
	return nil
}

// ── Sessions ──────────────────────────────────────────────────────

func sessionFromProto(id string, p *schemapb.Session) *service.SessionRecord {
	if p == nil {
		return nil
	}
	return &service.SessionRecord{
		NodeID:      id,
		SID:         p.GetSid(),
		UserID:      p.GetUserId(),
		CreatedAtMs: p.GetCreatedAtMs(),
		RevokedAtMs: p.GetRevokedAtMs(),
	}
}

func (r *entRepository) CreateSession(ctx context.Context, s *service.SessionRecord) (string, error) {
	if s == nil {
		return "", errors.New("repo: CreateSession: nil session")
	}
	if s.SID == "" {
		return "", fmt.Errorf("%w: missing sid", service.ErrInvalidArgument)
	}
	if s.UserID == "" {
		return "", fmt.Errorf("%w: missing user_id", service.ErrInvalidArgument)
	}
	if s.CreatedAtMs == 0 {
		s.CreatedAtMs = time.Now().UnixMilli()
	}
	// EntDB enforces sid uniqueness on the wire, but the underlying SDK
	// error type is opaque from the repo layer. The pre-check translates
	// the collision into the canonical service.ErrAlreadyExists for the
	// service layer + conformance suite.
	if existing, err := r.GetSessionBySid(ctx, s.SID); err != nil {
		return "", err
	} else if existing != nil {
		return "", fmt.Errorf("%w: sid %q", service.ErrAlreadyExists, s.SID)
	}
	msg := &schemapb.Session{
		Sid:         s.SID,
		UserId:      s.UserID,
		CreatedAtMs: s.CreatedAtMs,
		RevokedAtMs: s.RevokedAtMs,
	}
	id, err := r.client.create(ctx, actorStr(s.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateSession: %w", err)
	}
	s.NodeID = id
	return id, nil
}

func (r *entRepository) GetSessionBySid(ctx context.Context, sid string) (*service.SessionRecord, error) {
	if sid == "" {
		return nil, nil
	}
	dst := &schemapb.Session{}
	id, err := r.client.findByKey(ctx, systemActor, schemapb.SessionSid, sid, dst)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("repo: GetSessionBySid: %w", err)
	}
	return sessionFromProto(id, dst), nil
}

// RevokeSession is idempotent. The internal lookup discovers the node
// id by sid; an unknown sid is a successful no-op so concurrent
// revoke calls converge rather than racing each other into failure.
// The updateIf precondition is `revoked_at_ms == 0`, so a session
// that has already been revoked also resolves to no-op.
func (r *entRepository) RevokeSession(ctx context.Context, sid string, atMs int64) error {
	if sid == "" {
		return nil
	}
	rec, err := r.GetSessionBySid(ctx, sid)
	if err != nil {
		return fmt.Errorf("repo: RevokeSession: %w", err)
	}
	if rec == nil {
		return nil
	}
	if rec.RevokedAtMs != 0 {
		return nil
	}
	patch := &schemapb.Session{RevokedAtMs: atMs}
	if err := r.client.updateIf(ctx, actorStr(rec.UserID), rec.NodeID, patch, "revoked_at_ms", nil); err != nil {
		if errors.Is(err, errPreconditionFailed) {
			// Another caller revoked the same session first; that's
			// the contract — no-op rather than error.
			return nil
		}
		return fmt.Errorf("repo: RevokeSession: %w", err)
	}
	return nil
}

func (r *entRepository) RevokeSessionsForUser(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return nil
	}
	// SEC-4 caveat: tenant-shard-db v1.14.0 (#530) caps QueryNodes at
	// 1000 rows server-side. RevokeSessionsForUser mutates rows in
	// place rather than deleting them, so the usual drain-until-empty
	// pattern does not apply: already-revoked rows still match
	// `user_id = X` and would occupy the cap window forever. A
	// `revoked_at_ms = 0` filter would skip the cap window, but
	// proto3 zero scalars are not serialised on disk, so json_extract
	// against the absent field is NULL and the predicate matches
	// nothing. The pre-v1.14.0 behaviour (query all rows in one
	// shot, iterate and skip already-revoked) is the only correct
	// pattern given those two constraints; for the rare deployment
	// where a single user has > 1000 active sessions, the tail
	// beyond the cap is left for the next per-user revocation call
	// (typically a deliberate "revoke all my sessions" UI action
	// repeated by the user). Tracked in docs/IDENTITY.md §9.
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.Session{}, map[string]any{"user_id": userID})
	if err != nil {
		return fmt.Errorf("repo: RevokeSessionsForUser query: %w", err)
	}
	for _, row := range rows {
		rec := sessionFromProto(row.NodeID, row.Message.(*schemapb.Session))
		if rec == nil || rec.RevokedAtMs != 0 {
			continue
		}
		patch := &schemapb.Session{RevokedAtMs: atMs}
		if err := r.client.updateIf(ctx, actorStr(userID), rec.NodeID, patch, "revoked_at_ms", nil); err != nil {
			if errors.Is(err, errPreconditionFailed) {
				continue
			}
			return fmt.Errorf("repo: RevokeSessionsForUser update: %w", err)
		}
	}
	return nil
}

// Compile-time check that entRepository satisfies the interface.
var _ service.Repository = (*entRepository)(nil)
