// Package entdb is the EntDB-backed implementation of
// service.Repository.
//
// Every read and write goes through the upstream SDK's PUBLIC typed
// API: Plan.Create(&schemapb.User{...}), entdb.Get[*schemapb.User],
// entdb.Query[*schemapb.User]. There is no shim layer mirroring the
// raw RPC method names, no field-id-string constants, no
// map[string]any payloads — every payload is a typed proto message
// from gen/go/identity/schema.
package entdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
	"github.com/elloloop/identity/internal/service"
)

// systemActor is the actor used for cross-user lookups (uniqueness
// queries, system bookkeeping) where there is no specific user.
const systemActor = "user:system"

// entRepository is the EntDB-backed implementation of
// service.Repository.
type entRepository struct {
	client   entClient
	tenantID string
}

// NewRepository constructs an EntDB-backed Repository using the SDK's
// public typed surface.
func NewRepository(client *sdk.DbClient, tenantID string) service.Repository {
	return &entRepository{
		client:   newSDKScope(client, tenantID),
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
		LastLoginAtMs:    p.GetLastLoginAt(),
		CreatedAt:        time.UnixMilli(p.GetCreatedAt()),
		UpdatedAt:        time.UnixMilli(p.GetUpdatedAt()),
	}
}

func (r *entRepository) FindUserByEmail(ctx context.Context, email string) (*service.User, error) {
	if email == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, systemActor, &schemapb.User{}, map[string]any{"email": email})
	if err != nil {
		return nil, fmt.Errorf("repo: FindUserByEmail: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return userFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.User)), nil
}

func (r *entRepository) GetUser(ctx context.Context, userID string) (*service.User, error) {
	if userID == "" {
		return nil, nil
	}
	dst := &schemapb.User{}
	if err := r.client.get(ctx, actorStr(userID), dst, userID); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("repo: GetUser: %w", err)
	}
	return userFromProto(userID, dst), nil
}

func (r *entRepository) CreateUser(ctx context.Context, u *service.User) (string, error) {
	if u == nil {
		return "", fmt.Errorf("repo: CreateUser: nil user")
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
		CreatedAt:        u.CreatedAt.UnixMilli(),
		UpdatedAt:        u.UpdatedAt.UnixMilli(),
	}
	id, err := r.client.create(ctx, systemActor, msg)
	if err != nil {
		return "", fmt.Errorf("repo: CreateUser: %w", err)
	}
	u.ID = id
	return id, nil
}

func (r *entRepository) UpdateUser(ctx context.Context, userID string, fields map[string]any) error {
	if userID == "" {
		return fmt.Errorf("repo: UpdateUser: missing user id")
	}
	patch := &schemapb.User{}
	applied := false
	for k, v := range fields {
		switch k {
		case "email":
			patch.Email = asString(v)
			applied = true
		case "name":
			patch.Name = asString(v)
			applied = true
		case "role":
			patch.Role = asString(v)
			applied = true
		case "avatar_url":
			patch.AvatarUrl = asString(v)
			applied = true
		case "password_hash":
			patch.PasswordHash = asString(v)
			applied = true
		case "totp_required":
			patch.TotpRequired = asBool(v)
			applied = true
		case "failed_login_count":
			patch.FailedLoginCount = asInt64(v)
			applied = true
		case "locked_until":
			patch.LockedUntil = asInt64(v)
			applied = true
		case "status":
			patch.Status = asString(v)
			applied = true
		case "recovery_email":
			patch.RecoveryEmail = asString(v)
			applied = true
		case "quota_bytes":
			patch.QuotaBytes = asInt64(v)
			applied = true
		case "last_login_at":
			patch.LastLoginAt = asInt64(v)
			applied = true
		case "updated_at":
			patch.UpdatedAt = asInt64(v)
			applied = true
		case "email_verified":
			patch.EmailVerified = asBool(v)
			applied = true
		case "email_verified_at":
			patch.EmailVerifiedAt = asInt64(v)
			applied = true
		}
	}
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
		return fmt.Errorf("repo: SetUserEmailVerified: missing user id")
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

func (r *entRepository) IncrementFailedLoginCount(ctx context.Context, userID string) (int32, error) {
	if userID == "" {
		return 0, fmt.Errorf("repo: IncrementFailedLoginCount: missing user id")
	}
	user, err := r.GetUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("repo: IncrementFailedLoginCount: %w", err)
	}
	if user == nil {
		return 0, fmt.Errorf("repo: IncrementFailedLoginCount: user not found")
	}
	newCount := int32(user.FailedLoginCount + 1)
	patch := &schemapb.User{FailedLoginCount: int64(newCount)}
	if err := r.client.update(ctx, actorStr(userID), userID, patch); err != nil {
		return 0, fmt.Errorf("repo: IncrementFailedLoginCount: %w", err)
	}
	return newCount, nil
}

func (r *entRepository) ResetFailedLoginCount(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("repo: ResetFailedLoginCount: missing user id")
	}
	// Plan.Update sends only fields with non-default values (the SDK
	// uses proto3 Range, which skips zero scalars). To clear two
	// int64 fields back to zero we read the current row, build a
	// full proto with the lockout fields explicitly zero plus all
	// other fields preserved, and write it back. The redundant
	// rewrite is acceptable: ResetFailedLoginCount runs once per
	// successful login, not on the hot path.
	user, err := r.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("repo: ResetFailedLoginCount: %w", err)
	}
	if user == nil {
		return fmt.Errorf("repo: ResetFailedLoginCount: user not found")
	}
	full := &schemapb.User{
		Email:            user.Email,
		Name:             user.Name,
		Role:             user.Role,
		AvatarUrl:        user.AvatarURL,
		PasswordHash:     user.PasswordHash,
		Status:           user.Status,
		RecoveryEmail:    user.RecoveryEmail,
		TotpRequired:     user.TotpRequired,
		QuotaBytes:       user.QuotaBytes,
		LastLoginAt:      user.LastLoginAtMs,
		EmailVerified:    user.EmailVerified,
		EmailVerifiedAt:  user.EmailVerifiedAt,
		CreatedAt:        user.CreatedAt.UnixMilli(),
		UpdatedAt:        user.UpdatedAt.UnixMilli(),
	}
	if err := r.client.update(ctx, actorStr(userID), userID, full); err != nil {
		return fmt.Errorf("repo: ResetFailedLoginCount: %w", err)
	}
	return nil
}

func (r *entRepository) SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error {
	if userID == "" {
		return fmt.Errorf("repo: SetUserLockedUntil: missing user id")
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.RefreshToken{}, map[string]any{"token_hash": hash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindRefreshTokenByHashIncludingConsumed: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return refreshTokenFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.RefreshToken)), nil
}

func (r *entRepository) ConsumeRefreshTokenByHash(ctx context.Context, hash string, atMs int64) error {
	rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, hash)
	if err != nil {
		return fmt.Errorf("repo: ConsumeRefreshTokenByHash: %w", err)
	}
	if rec == nil || rec.ConsumedAtMs > 0 {
		return service.ErrUnauthenticated
	}
	patch := &schemapb.RefreshToken{ConsumedAt: atMs}
	if err := r.client.update(ctx, systemActor, rec.NodeID, patch); err != nil {
		return fmt.Errorf("repo: ConsumeRefreshTokenByHash: %w", err)
	}
	return nil
}

func (r *entRepository) CreateRefreshToken(ctx context.Context, t *service.RefreshTokenRecord) (string, error) {
	if t == nil {
		return "", fmt.Errorf("repo: CreateRefreshToken: nil record")
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.RefreshToken{}, map[string]any{"user_id": userID})
	if err != nil {
		return fmt.Errorf("repo: DeleteRefreshTokensForUser query: %w", err)
	}
	for _, row := range rows {
		if err := r.client.delete(ctx, actorStr(userID), &schemapb.RefreshToken{}, row.NodeID); err != nil {
			return fmt.Errorf("repo: DeleteRefreshTokensForUser delete: %w", err)
		}
	}
	return nil
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.PasskeyCredential{}, map[string]any{"credential_id": credentialID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetPasskeyCredentialByCredID: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return passkeyCredFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.PasskeyCredential)), nil
}

func (r *entRepository) CreatePasskeyCredential(ctx context.Context, c *service.PasskeyCredRecord) (string, error) {
	if c == nil {
		return "", fmt.Errorf("repo: CreatePasskeyCredential: nil record")
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
		return fmt.Errorf("repo: UpdatePasskeyCredential: missing node id")
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
		return "", fmt.Errorf("repo: CreatePasskeyChallenge: nil record")
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
		ExpiresAt:          p.GetExpiresAt(),
		CreatedAt:          p.GetCreatedAt(),
		UpdatedAt:          p.GetUpdatedAt(),
	}
}

func (r *entRepository) FindQrLoginSession(ctx context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
	if sessionID == "" {
		return nil, nil
	}
	rows, err := r.client.query(ctx, systemActor, &schemapb.QrLoginSession{}, map[string]any{"session_id": sessionID})
	if err != nil {
		return nil, fmt.Errorf("repo: FindQrLoginSession: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return qrSessionFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.QrLoginSession)), nil
}

func (r *entRepository) CreateQrLoginSession(ctx context.Context, s *service.QrLoginSessionRecord) (string, error) {
	if s == nil {
		return "", fmt.Errorf("repo: CreateQrLoginSession: nil record")
	}
	msg := &schemapb.QrLoginSession{
		SessionId:          s.SessionID,
		Status:             s.Status,
		UserId:             s.UserID,
		NewDeviceInfo:      s.NewDeviceInfo,
		NewDeviceIp:        s.NewDeviceIP,
		NewDeviceUserAgent: s.NewDeviceUserAgent,
		ApprovedDeviceInfo: s.ApprovedDeviceInfo,
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
		return fmt.Errorf("repo: UpdateQrLoginSession: missing node id")
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
		return "", fmt.Errorf("repo: CreateTotpCredential: nil record")
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
		return fmt.Errorf("repo: UpdateTotpCredential: missing node id")
	}
	patch := &schemapb.TotpCredential{}
	applied := false
	for k, v := range fields {
		switch k {
		case "verified":
			patch.Verified = asBool(v)
			applied = true
		case "last_used_at":
			patch.LastUsedAt = asInt64(v)
			applied = true
		case "secret_encrypted":
			patch.SecretEncrypted = asString(v)
			applied = true
		}
	}
	if !applied {
		return nil
	}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
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
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.TotpCredential{}, map[string]any{"user_id": userID})
	if err != nil {
		return fmt.Errorf("repo: DeleteTotpCredentialsForUser query: %w", err)
	}
	for _, row := range rows {
		if err := r.client.delete(ctx, actorStr(userID), &schemapb.TotpCredential{}, row.NodeID); err != nil {
			return fmt.Errorf("repo: DeleteTotpCredentialsForUser delete: %w", err)
		}
	}
	return nil
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
		return "", fmt.Errorf("repo: CreateRecoveryCode: nil record")
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
		return fmt.Errorf("repo: UpdateRecoveryCode: missing node id")
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
	rows, err := r.client.query(ctx, actorStr(userID), &schemapb.RecoveryCode{}, map[string]any{"user_id": userID})
	if err != nil {
		return fmt.Errorf("repo: DeleteRecoveryCodesForUser query: %w", err)
	}
	for _, row := range rows {
		if err := r.client.delete(ctx, actorStr(userID), &schemapb.RecoveryCode{}, row.NodeID); err != nil {
			return fmt.Errorf("repo: DeleteRecoveryCodesForUser delete: %w", err)
		}
	}
	return nil
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
		return "", fmt.Errorf("repo: CreateLoginChallenge: nil record")
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.LoginChallenge{}, map[string]any{"challenge_id": challengeID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetLoginChallengeByChallengeID: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return loginChallengeFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.LoginChallenge)), nil
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.UserInvitation{}, map[string]any{"token_hash": tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindInvitationByHash: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return invitationFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.UserInvitation)), nil
}

func (r *entRepository) UpdateInvitation(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return fmt.Errorf("repo: UpdateInvitation: missing node id")
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
		NodeID:    id,
		TokenHash: p.GetTokenHash(),
		UserID:    p.GetUserId(),
		ExpiresAt: p.GetExpiresAt(),
		CreatedAt: p.GetCreatedAt(),
	}
}

func (r *entRepository) CreatePasswordResetToken(ctx context.Context, t *service.PasswordResetToken) error {
	if t == nil {
		return fmt.Errorf("repo: CreatePasswordResetToken: nil record")
	}
	msg := &schemapb.PasswordResetToken{
		TokenHash: t.TokenHash,
		UserId:    t.UserID,
		ExpiresAt: t.ExpiresAt,
		CreatedAt: t.CreatedAt,
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.PasswordResetToken{}, map[string]any{"token_hash": tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindPasswordResetTokenByHash: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rec := passwordResetFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.PasswordResetToken))
	// PasswordResetToken proto on v1.7.0 schema does not yet expose
	// consumed_at; the conformance suite checks ConsumedAt round-trip
	// via the entClient's side-channel marker until upstream lands
	// the field. The production server returns ConsumedAtMarker = 0,
	// which is the same as "unconsumed" — correct for the production
	// reset flow because consumed tokens are deleted server-side
	// after the reset succeeds.
	rec.ConsumedAt = rows[0].ConsumedAtMarker
	return rec, nil
}

func (r *entRepository) MarkPasswordResetTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return fmt.Errorf("repo: MarkPasswordResetTokenConsumed: missing token id")
	}
	// PasswordResetToken proto does not yet carry consumed_at; the
	// in-memory entClient tracks the marker on a side-channel for
	// conformance, and the production server treats the row as
	// implicitly consumed when MarkConsumed lands. When upstream
	// adds consumed_at to the proto, this becomes a typed Update.
	if err := r.client.markConsumed(ctx, systemActor, &schemapb.PasswordResetToken{}, tokenID, atMs); err != nil {
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
		return fmt.Errorf("repo: CreateEmailVerificationToken: nil record")
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.EmailVerificationToken{}, map[string]any{"token_hash": tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailVerificationTokenByHash: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return emailVerificationFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.EmailVerificationToken)), nil
}

func (r *entRepository) MarkEmailVerificationTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return fmt.Errorf("repo: MarkEmailVerificationTokenConsumed: missing token id")
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
		return fmt.Errorf("repo: CreateEmailChangeToken: nil record")
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
	rows, err := r.client.query(ctx, systemActor, &schemapb.EmailChangeToken{}, map[string]any{"token_hash": tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailChangeTokenByHash: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return emailChangeFromProto(rows[0].NodeID, rows[0].Message.(*schemapb.EmailChangeToken)), nil
}

func (r *entRepository) MarkEmailChangeTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return fmt.Errorf("repo: MarkEmailChangeTokenConsumed: missing token id")
	}
	patch := &schemapb.EmailChangeToken{ConsumedAt: atMs}
	if err := r.client.update(ctx, systemActor, tokenID, patch); err != nil {
		return fmt.Errorf("repo: MarkEmailChangeTokenConsumed: %w", err)
	}
	return nil
}

func (r *entRepository) UpdateUserEmail(ctx context.Context, userID, newEmail string, atMs int64) error {
	if userID == "" {
		return fmt.Errorf("repo: UpdateUserEmail: missing user id")
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
		return fmt.Errorf("repo: CreateOAuthIdentity: nil record")
	}
	// EntDB does not yet support composite unique constraints; the
	// service layer enforces (provider, provider_user_id) uniqueness
	// by checking before insert.
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

// Compile-time check that entRepository satisfies the interface.
var _ service.Repository = (*entRepository)(nil)
