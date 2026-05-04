package entdb

import (
	"context"
	"fmt"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

// systemActor is the actor used for queries / writes that are not
// performed on behalf of a specific user (e.g. cross-user uniqueness
// look-ups, system bookkeeping).
const systemActor = "user:system"

// entRepository is the EntDB-backed implementation of
// service.Repository.
type entRepository struct {
	client   Client
	tenantID string
}

// NewRepository constructs an EntDB-backed Repository using the SDK's
// public typed surface. Both the auth and admin code paths share the
// same client so writes and reads are visible to each other within
// the same gRPC connection.
//
// Internally every read/write goes through a Client adapter built on
// top of the SDK's `Plan.Create(&schemapb.X{...})` /
// `sdk.Get[*schemapb.X]` / `sdk.Query[*schemapb.X]` /
// `sdk.GetByKey[T]` / `Scope.EdgesFrom` API — there is no `unsafe`,
// no reflection of the SDK's private `transport` field. See
// `transport.go` for the witness-table that maps the legacy numeric
// type_id used by service.DB to a typed proto witness.
func NewRepository(client *sdk.DbClient, tenantID string) service.Repository {
	return &entRepository{
		client:   NewSDKClient(client),
		tenantID: tenantID,
	}
}

// NewRepositoryWithClient is the test seam: it accepts a Client
// interface so unit tests can drop in a fake.
func NewRepositoryWithClient(c Client, tenantID string) service.Repository {
	return &entRepository{client: c, tenantID: tenantID}
}

// ── Helpers ───────────────────────────────────────────────────────

func nowMs() int64 { return time.Now().UnixMilli() }

func actorStr(userID string) string {
	if userID == "" {
		return systemActor
	}
	return "user:" + userID
}

func ps(p map[string]any, k string) string {
	if v, ok := p[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func pi(p map[string]any, k string) int64 {
	v, ok := p[k]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	case int32:
		return int64(n)
	}
	return 0
}

func pb(p map[string]any, k string) bool {
	if v, ok := p[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// nodeFromQuery returns the first node (or nil if none) from a
// QueryNodes result. Callers that look up by a unique field rely on
// at-most-one semantics.
func firstNode(nodes []*sdk.Node) *sdk.Node {
	if len(nodes) == 0 {
		return nil
	}
	return nodes[0]
}

// ── Users ─────────────────────────────────────────────────────────

func userFromNode(n *sdk.Node) *service.User {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.User{
		ID:               n.NodeID,
		Email:            ps(p, ufEmail),
		Name:             ps(p, ufName),
		Role:             ps(p, ufRole),
		AvatarURL:        ps(p, ufAvatarURL),
		Status:           ps(p, ufStatus),
		RecoveryEmail:    ps(p, ufRecoveryEmail),
		QuotaBytes:       pi(p, ufQuotaBytes),
		TotpRequired:     pb(p, ufTotpRequired),
		PasswordHash:     ps(p, ufPasswordHash),
		FailedLoginCount: int(pi(p, ufFailedLoginCount)),
		LockedUntil:      pi(p, ufLockedUntil),
		EmailVerified:    pb(p, ufEmailVerified),
		EmailVerifiedAt:  pi(p, ufEmailVerifiedAt),
		LastLoginAtMs:    pi(p, ufLastLoginAt),
		CreatedAt:        time.UnixMilli(pi(p, ufCreatedAt)),
		UpdatedAt:        time.UnixMilli(pi(p, ufUpdatedAt)),
	}
}

func (r *entRepository) FindUserByEmail(ctx context.Context, email string) (*service.User, error) {
	if email == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeUser,
		map[string]any{ufEmail: email})
	if err != nil {
		return nil, fmt.Errorf("repo: FindUserByEmail: %w", err)
	}
	return userFromNode(firstNode(nodes)), nil
}

func (r *entRepository) GetUser(ctx context.Context, userID string) (*service.User, error) {
	if userID == "" {
		return nil, nil
	}
	node, err := r.client.GetNode(ctx, r.tenantID, actorStr(userID), typeUser, userID)
	if err != nil {
		return nil, fmt.Errorf("repo: GetUser: %w", err)
	}
	return userFromNode(node), nil
}

func (r *entRepository) CreateUser(ctx context.Context, u *service.User) (string, error) {
	if u == nil {
		return "", fmt.Errorf("repo: CreateUser: nil user")
	}
	now := nowMs()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.UnixMilli(now)
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	data := map[string]any{
		ufEmail:     u.Email,
		ufName:      u.Name,
		ufCreatedAt: u.CreatedAt.UnixMilli(),
		ufUpdatedAt: u.UpdatedAt.UnixMilli(),
	}
	if u.Role != "" {
		data[ufRole] = u.Role
	}
	if u.AvatarURL != "" {
		data[ufAvatarURL] = u.AvatarURL
	}
	if u.PasswordHash != "" {
		data[ufPasswordHash] = u.PasswordHash
	}
	if u.Status != "" {
		data[ufStatus] = u.Status
	}
	if u.RecoveryEmail != "" {
		data[ufRecoveryEmail] = u.RecoveryEmail
	}
	if u.TotpRequired {
		data[ufTotpRequired] = true
	}
	if u.QuotaBytes != 0 {
		data[ufQuotaBytes] = u.QuotaBytes
	}
	if u.LastLoginAtMs != 0 {
		data[ufLastLoginAt] = u.LastLoginAtMs
	}
	if u.EmailVerified {
		data[ufEmailVerified] = true
	}
	if u.EmailVerifiedAt != 0 {
		data[ufEmailVerifiedAt] = u.EmailVerifiedAt
	}

	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeUser, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreateUser: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateUser")
	if err != nil {
		return "", err
	}
	u.ID = id
	return id, nil
}

func (r *entRepository) UpdateUser(ctx context.Context, userID string, fields map[string]any) error {
	if userID == "" {
		return fmt.Errorf("repo: UpdateUser: missing user id")
	}
	patch := translateUserFields(fields)
	if len(patch) == 0 {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typeUser, NodeID: userID, Patch: patch}})
	if err != nil {
		return fmt.Errorf("repo: UpdateUser: %w", err)
	}
	return nil
}

// translateUserFields converts the service-layer field-name patch
// into an entdb field-id patch. Unknown field names are dropped (they
// are typically non-persisted view fields). Numeric fields accept
// int / int64 / float64 to match map[string]any decoding.
func translateUserFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		switch k {
		case "email":
			out[ufEmail] = v
		case "name":
			out[ufName] = v
		case "role":
			out[ufRole] = v
		case "avatar_url":
			out[ufAvatarURL] = v
		case "password_hash":
			out[ufPasswordHash] = v
		case "totp_required":
			out[ufTotpRequired] = v
		case "failed_login_count":
			out[ufFailedLoginCount] = toInt64(v)
		case "locked_until":
			out[ufLockedUntil] = toInt64(v)
		case "status":
			out[ufStatus] = v
		case "recovery_email":
			out[ufRecoveryEmail] = v
		case "quota_bytes":
			out[ufQuotaBytes] = toInt64(v)
		case "last_login_at":
			out[ufLastLoginAt] = toInt64(v)
		case "updated_at":
			out[ufUpdatedAt] = toInt64(v)
		case "email_verified":
			out[ufEmailVerified] = v
		case "email_verified_at":
			out[ufEmailVerifiedAt] = toInt64(v)
		}
	}
	return out
}

// toInt64 normalises numeric values to int64 so EntDB sees a
// consistent type regardless of the caller's Go type.
func toInt64(v any) any {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case float64:
		return int64(n)
	}
	return v
}

func (r *entRepository) SetUserEmailVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return fmt.Errorf("repo: SetUserEmailVerified: missing user id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeUser,
			NodeID: userID,
			Patch: map[string]any{
				ufEmailVerified:   true,
				ufEmailVerifiedAt: atMs,
				ufUpdatedAt:       atMs,
			},
		}})
	if err != nil {
		return fmt.Errorf("repo: SetUserEmailVerified: %w", err)
	}
	return nil
}

// ── Refresh tokens ────────────────────────────────────────────────

func refreshTokenFromNode(n *sdk.Node) *service.RefreshTokenRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.RefreshTokenRecord{
		NodeID:       n.NodeID,
		TokenHash:    ps(p, rfTokenHash),
		UserID:       ps(p, rfUserID),
		DeviceInfo:   ps(p, rfDeviceInfo),
		DeviceName:   ps(p, rfDeviceName),
		IPAddress:    ps(p, rfIPAddress),
		UserAgent:    ps(p, rfUserAgent),
		ExpiresAt:    pi(p, rfExpiresAt),
		CreatedAt:    pi(p, rfCreatedAt),
		LastUsedAt:   pi(p, rfLastUsedAt),
		ConsumedAtMs: pi(p, rfConsumedAt),
	}
}

func (r *entRepository) FindRefreshTokenByHash(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, hash)
	if err != nil || rec == nil {
		return rec, err
	}
	if rec.ConsumedAtMs > 0 {
		// Caller wants only live tokens; consumed rows are surfaced via the
		// "IncludingConsumed" variant for replay detection.
		return nil, nil
	}
	return rec, nil
}

func (r *entRepository) FindRefreshTokenByHashIncludingConsumed(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	if hash == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeRefreshToken,
		map[string]any{rfTokenHash: hash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindRefreshTokenByHashIncludingConsumed: %w", err)
	}
	return refreshTokenFromNode(firstNode(nodes)), nil
}

func (r *entRepository) ConsumeRefreshTokenByHash(ctx context.Context, hash string, atMs int64) error {
	rec, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, hash)
	if err != nil {
		return fmt.Errorf("repo: ConsumeRefreshTokenByHash: %w", err)
	}
	if rec == nil || rec.ConsumedAtMs > 0 {
		// Missing or already consumed — service layer treats either as
		// the rotation losing the race; return ErrUnauthenticated so the
		// caller can detect replay.
		return service.ErrUnauthenticated
	}
	_, err = r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typeRefreshToken, NodeID: rec.NodeID,
			Data: map[string]any{rfConsumedAt: atMs}}})
	if err != nil {
		return fmt.Errorf("repo: ConsumeRefreshTokenByHash: %w", err)
	}
	return nil
}

func (r *entRepository) CreateRefreshToken(ctx context.Context, t *service.RefreshTokenRecord) (string, error) {
	if t == nil {
		return "", fmt.Errorf("repo: CreateRefreshToken: nil record")
	}
	data := map[string]any{
		rfTokenHash:  t.TokenHash,
		rfUserID:     t.UserID,
		rfExpiresAt:  t.ExpiresAt,
		rfCreatedAt:  t.CreatedAt,
		rfLastUsedAt: t.LastUsedAt,
	}
	if t.DeviceInfo != "" {
		data[rfDeviceInfo] = t.DeviceInfo
	}
	if t.DeviceName != "" {
		data[rfDeviceName] = t.DeviceName
	}
	if t.IPAddress != "" {
		data[rfIPAddress] = t.IPAddress
	}
	if t.UserAgent != "" {
		data[rfUserAgent] = t.UserAgent
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(t.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeRefreshToken, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreateRefreshToken: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateRefreshToken")
	if err != nil {
		return "", err
	}
	t.NodeID = id
	return id, nil
}

func (r *entRepository) DeleteRefreshToken(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpDeleteNode, TypeID: typeRefreshToken, NodeID: nodeID}})
	if err != nil {
		return fmt.Errorf("repo: DeleteRefreshToken: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteRefreshTokensForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeRefreshToken,
		map[string]any{rfUserID: userID})
	if err != nil {
		return fmt.Errorf("repo: DeleteRefreshTokensForUser query: %w", err)
	}
	if len(nodes) == 0 {
		return nil
	}
	ops := make([]sdk.Operation, 0, len(nodes))
	for _, n := range nodes {
		ops = append(ops, sdk.Operation{Type: sdk.OpDeleteNode, TypeID: typeRefreshToken, NodeID: n.NodeID})
	}
	if _, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "", ops); err != nil {
		return fmt.Errorf("repo: DeleteRefreshTokensForUser commit: %w", err)
	}
	return nil
}

// ── Passkey credentials ───────────────────────────────────────────

func passkeyCredFromNode(n *sdk.Node) *service.PasskeyCredRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.PasskeyCredRecord{
		NodeID:       n.NodeID,
		CredentialID: ps(p, pkCredentialID),
		UserID:       ps(p, pkUserID),
		PublicKey:    ps(p, pkPublicKey),
		SignCount:    pi(p, pkSignCount),
		DeviceName:   ps(p, pkDeviceName),
		AAGUID:       ps(p, pkAAGUID),
		Transports:   ps(p, pkTransports),
		CreatedAt:    pi(p, pkCreatedAt),
		LastUsedAt:   pi(p, pkLastUsedAt),
	}
}

func (r *entRepository) ListPasskeyCredentials(ctx context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, actorStr(userID), typePasskeyCredential,
		map[string]any{pkUserID: userID})
	if err != nil {
		return nil, fmt.Errorf("repo: ListPasskeyCredentials: %w", err)
	}
	out := make([]*service.PasskeyCredRecord, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, passkeyCredFromNode(n))
	}
	return out, nil
}

func (r *entRepository) GetPasskeyCredentialByCredID(ctx context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
	if credentialID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typePasskeyCredential,
		map[string]any{pkCredentialID: credentialID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetPasskeyCredentialByCredID: %w", err)
	}
	return passkeyCredFromNode(firstNode(nodes)), nil
}

func (r *entRepository) CreatePasskeyCredential(ctx context.Context, c *service.PasskeyCredRecord) (string, error) {
	if c == nil {
		return "", fmt.Errorf("repo: CreatePasskeyCredential: nil record")
	}
	data := map[string]any{
		pkCredentialID: c.CredentialID,
		pkUserID:       c.UserID,
		pkPublicKey:    c.PublicKey,
		pkSignCount:    c.SignCount,
		pkCreatedAt:    c.CreatedAt,
		pkLastUsedAt:   c.LastUsedAt,
	}
	if c.DeviceName != "" {
		data[pkDeviceName] = c.DeviceName
	}
	if c.AAGUID != "" {
		data[pkAAGUID] = c.AAGUID
	}
	if c.Transports != "" {
		data[pkTransports] = c.Transports
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(c.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typePasskeyCredential, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreatePasskeyCredential: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreatePasskeyCredential")
	if err != nil {
		return "", err
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) UpdatePasskeyCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return fmt.Errorf("repo: UpdatePasskeyCredential: missing node id")
	}
	patch := map[string]any{}
	for k, v := range fields {
		switch k {
		case "sign_count":
			patch[pkSignCount] = toInt64(v)
		case "last_used_at":
			patch[pkLastUsedAt] = toInt64(v)
		case "device_name":
			patch[pkDeviceName] = v
		}
	}
	if len(patch) == 0 {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typePasskeyCredential, NodeID: nodeID, Patch: patch}})
	if err != nil {
		return fmt.Errorf("repo: UpdatePasskeyCredential: %w", err)
	}
	return nil
}

// ── Passkey challenges ────────────────────────────────────────────

func passkeyChallengeFromNode(n *sdk.Node) *service.PasskeyChallengeRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.PasskeyChallengeRecord{
		NodeID:        n.NodeID,
		Challenge:     ps(p, pcChallenge),
		UserID:        ps(p, pcUserID),
		ChallengeType: ps(p, pcChallengeType),
		ExpiresAt:     pi(p, pcExpiresAt),
		CreatedAt:     pi(p, pcCreatedAt),
	}
}

func (r *entRepository) GetPasskeyChallenge(ctx context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	if nodeID == "" {
		return nil, nil
	}
	node, err := r.client.GetNode(ctx, r.tenantID, systemActor, typePasskeyChallenge, nodeID)
	if err != nil {
		return nil, fmt.Errorf("repo: GetPasskeyChallenge: %w", err)
	}
	return passkeyChallengeFromNode(node), nil
}

func (r *entRepository) CreatePasskeyChallenge(ctx context.Context, c *service.PasskeyChallengeRecord) (string, error) {
	if c == nil {
		return "", fmt.Errorf("repo: CreatePasskeyChallenge: nil record")
	}
	data := map[string]any{
		pcChallenge:     c.Challenge,
		pcChallengeType: c.ChallengeType,
		pcExpiresAt:     c.ExpiresAt,
		pcCreatedAt:     c.CreatedAt,
	}
	if c.UserID != "" {
		data[pcUserID] = c.UserID
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(c.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typePasskeyChallenge, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreatePasskeyChallenge: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreatePasskeyChallenge")
	if err != nil {
		return "", err
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) DeletePasskeyChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpDeleteNode, TypeID: typePasskeyChallenge, NodeID: nodeID}})
	if err != nil {
		return fmt.Errorf("repo: DeletePasskeyChallenge: %w", err)
	}
	return nil
}

// ── QR login sessions ─────────────────────────────────────────────

func qrSessionFromNode(n *sdk.Node) *service.QrLoginSessionRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.QrLoginSessionRecord{
		NodeID:             n.NodeID,
		SessionID:          ps(p, qrSessionID),
		Status:             ps(p, qrStatus),
		UserID:             ps(p, qrUserID),
		NewDeviceInfo:      ps(p, qrNewDeviceInfo),
		NewDeviceIP:        ps(p, qrNewDeviceIP),
		NewDeviceUserAgent: ps(p, qrNewDeviceUserAgent),
		ApprovedDeviceInfo: ps(p, qrApprovedDeviceInfo),
		ExpiresAt:          pi(p, qrExpiresAt),
		CreatedAt:          pi(p, qrCreatedAt),
		UpdatedAt:          pi(p, qrUpdatedAt),
	}
}

func (r *entRepository) FindQrLoginSession(ctx context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
	if sessionID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeQrLoginSession,
		map[string]any{qrSessionID: sessionID})
	if err != nil {
		return nil, fmt.Errorf("repo: FindQrLoginSession: %w", err)
	}
	return qrSessionFromNode(firstNode(nodes)), nil
}

func (r *entRepository) CreateQrLoginSession(ctx context.Context, s *service.QrLoginSessionRecord) (string, error) {
	if s == nil {
		return "", fmt.Errorf("repo: CreateQrLoginSession: nil record")
	}
	data := map[string]any{
		qrSessionID: s.SessionID,
		qrStatus:    s.Status,
		qrExpiresAt: s.ExpiresAt,
		qrCreatedAt: s.CreatedAt,
		qrUpdatedAt: s.UpdatedAt,
	}
	if s.UserID != "" {
		data[qrUserID] = s.UserID
	}
	if s.NewDeviceInfo != "" {
		data[qrNewDeviceInfo] = s.NewDeviceInfo
	}
	if s.NewDeviceIP != "" {
		data[qrNewDeviceIP] = s.NewDeviceIP
	}
	if s.NewDeviceUserAgent != "" {
		data[qrNewDeviceUserAgent] = s.NewDeviceUserAgent
	}
	if s.ApprovedDeviceInfo != "" {
		data[qrApprovedDeviceInfo] = s.ApprovedDeviceInfo
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeQrLoginSession, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreateQrLoginSession: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateQrLoginSession")
	if err != nil {
		return "", err
	}
	s.NodeID = id
	return id, nil
}

func (r *entRepository) UpdateQrLoginSession(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return fmt.Errorf("repo: UpdateQrLoginSession: missing node id")
	}
	patch := map[string]any{}
	for k, v := range fields {
		switch k {
		case "status":
			patch[qrStatus] = v
		case "user_id":
			patch[qrUserID] = v
		case "approved_device_info":
			patch[qrApprovedDeviceInfo] = v
		case "updated_at":
			patch[qrUpdatedAt] = toInt64(v)
		}
	}
	if len(patch) == 0 {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typeQrLoginSession, NodeID: nodeID, Patch: patch}})
	if err != nil {
		return fmt.Errorf("repo: UpdateQrLoginSession: %w", err)
	}
	return nil
}

// ── TOTP credentials ──────────────────────────────────────────────

func totpCredFromNode(n *sdk.Node) *service.TotpCredRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.TotpCredRecord{
		NodeID:          n.NodeID,
		UserID:          ps(p, tcUserID),
		SecretEncrypted: ps(p, tcSecretEncrypted),
		Verified:        pb(p, tcVerified),
		CreatedAt:       pi(p, tcCreatedAt),
		LastUsedAt:      pi(p, tcLastUsedAt),
	}
}

func (r *entRepository) GetTotpCredential(ctx context.Context, userID string) (*service.TotpCredRecord, error) {
	if userID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, actorStr(userID), typeTotpCredential,
		map[string]any{tcUserID: userID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetTotpCredential: %w", err)
	}
	return totpCredFromNode(firstNode(nodes)), nil
}

func (r *entRepository) CreateTotpCredential(ctx context.Context, c *service.TotpCredRecord) (string, error) {
	if c == nil {
		return "", fmt.Errorf("repo: CreateTotpCredential: nil record")
	}
	data := map[string]any{
		tcUserID:          c.UserID,
		tcSecretEncrypted: c.SecretEncrypted,
		tcVerified:        c.Verified,
		tcCreatedAt:       c.CreatedAt,
		tcLastUsedAt:      c.LastUsedAt,
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(c.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeTotpCredential, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreateTotpCredential: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateTotpCredential")
	if err != nil {
		return "", err
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) UpdateTotpCredential(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return fmt.Errorf("repo: UpdateTotpCredential: missing node id")
	}
	patch := map[string]any{}
	for k, v := range fields {
		switch k {
		case "verified":
			patch[tcVerified] = v
		case "last_used_at":
			patch[tcLastUsedAt] = toInt64(v)
		case "secret_encrypted":
			patch[tcSecretEncrypted] = v
		}
	}
	if len(patch) == 0 {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typeTotpCredential, NodeID: nodeID, Patch: patch}})
	if err != nil {
		return fmt.Errorf("repo: UpdateTotpCredential: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteTotpCredential(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpDeleteNode, TypeID: typeTotpCredential, NodeID: nodeID}})
	if err != nil {
		return fmt.Errorf("repo: DeleteTotpCredential: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteTotpCredentialsForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, actorStr(userID), typeTotpCredential,
		map[string]any{tcUserID: userID})
	if err != nil {
		return fmt.Errorf("repo: DeleteTotpCredentialsForUser query: %w", err)
	}
	if len(nodes) == 0 {
		return nil
	}
	ops := make([]sdk.Operation, 0, len(nodes))
	for _, n := range nodes {
		ops = append(ops, sdk.Operation{Type: sdk.OpDeleteNode, TypeID: typeTotpCredential, NodeID: n.NodeID})
	}
	if _, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "", ops); err != nil {
		return fmt.Errorf("repo: DeleteTotpCredentialsForUser commit: %w", err)
	}
	return nil
}

// ── Recovery codes ────────────────────────────────────────────────

func recoveryCodeFromNode(n *sdk.Node) *service.RecoveryCodeRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.RecoveryCodeRecord{
		NodeID:    n.NodeID,
		UserID:    ps(p, rcUserID),
		CodeHash:  ps(p, rcCodeHash),
		Used:      pb(p, rcUsed),
		CreatedAt: pi(p, rcCreatedAt),
		UsedAt:    pi(p, rcUsedAt),
	}
}

func (r *entRepository) CreateRecoveryCode(ctx context.Context, c *service.RecoveryCodeRecord) (string, error) {
	if c == nil {
		return "", fmt.Errorf("repo: CreateRecoveryCode: nil record")
	}
	data := map[string]any{
		rcUserID:    c.UserID,
		rcCodeHash:  c.CodeHash,
		rcUsed:      c.Used,
		rcCreatedAt: c.CreatedAt,
	}
	if c.UsedAt != 0 {
		data[rcUsedAt] = c.UsedAt
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(c.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeRecoveryCode, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreateRecoveryCode: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateRecoveryCode")
	if err != nil {
		return "", err
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) FindRecoveryCodeByHash(ctx context.Context, userID, hash string) (*service.RecoveryCodeRecord, error) {
	if userID == "" || hash == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, actorStr(userID), typeRecoveryCode,
		map[string]any{rcUserID: userID, rcCodeHash: hash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindRecoveryCodeByHash: %w", err)
	}
	return recoveryCodeFromNode(firstNode(nodes)), nil
}

func (r *entRepository) UpdateRecoveryCode(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return fmt.Errorf("repo: UpdateRecoveryCode: missing node id")
	}
	patch := map[string]any{}
	for k, v := range fields {
		switch k {
		case "used":
			patch[rcUsed] = v
		case "used_at":
			patch[rcUsedAt] = toInt64(v)
		}
	}
	if len(patch) == 0 {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typeRecoveryCode, NodeID: nodeID, Patch: patch}})
	if err != nil {
		return fmt.Errorf("repo: UpdateRecoveryCode: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteRecoveryCodesForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, actorStr(userID), typeRecoveryCode,
		map[string]any{rcUserID: userID})
	if err != nil {
		return fmt.Errorf("repo: DeleteRecoveryCodesForUser query: %w", err)
	}
	if len(nodes) == 0 {
		return nil
	}
	ops := make([]sdk.Operation, 0, len(nodes))
	for _, n := range nodes {
		ops = append(ops, sdk.Operation{Type: sdk.OpDeleteNode, TypeID: typeRecoveryCode, NodeID: n.NodeID})
	}
	if _, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "", ops); err != nil {
		return fmt.Errorf("repo: DeleteRecoveryCodesForUser commit: %w", err)
	}
	return nil
}

// ── Login challenges ──────────────────────────────────────────────

func loginChallengeFromNode(n *sdk.Node) *service.LoginChallengeRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.LoginChallengeRecord{
		NodeID:      n.NodeID,
		ChallengeID: ps(p, lcChallengeID),
		UserID:      ps(p, lcUserID),
		ExpiresAt:   pi(p, lcExpiresAt),
		CreatedAt:   pi(p, lcCreatedAt),
	}
}

func (r *entRepository) CreateLoginChallenge(ctx context.Context, c *service.LoginChallengeRecord) (string, error) {
	if c == nil {
		return "", fmt.Errorf("repo: CreateLoginChallenge: nil record")
	}
	data := map[string]any{
		lcChallengeID: c.ChallengeID,
		lcUserID:      c.UserID,
		lcExpiresAt:   c.ExpiresAt,
		lcCreatedAt:   c.CreatedAt,
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(c.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeLoginChallenge, Data: data}})
	if err != nil {
		return "", fmt.Errorf("repo: CreateLoginChallenge: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateLoginChallenge")
	if err != nil {
		return "", err
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) GetLoginChallengeByChallengeID(ctx context.Context, challengeID string) (*service.LoginChallengeRecord, error) {
	if challengeID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeLoginChallenge,
		map[string]any{lcChallengeID: challengeID})
	if err != nil {
		return nil, fmt.Errorf("repo: GetLoginChallengeByChallengeID: %w", err)
	}
	return loginChallengeFromNode(firstNode(nodes)), nil
}

func (r *entRepository) DeleteLoginChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpDeleteNode, TypeID: typeLoginChallenge, NodeID: nodeID}})
	if err != nil {
		return fmt.Errorf("repo: DeleteLoginChallenge: %w", err)
	}
	return nil
}

// ── User invitations ──────────────────────────────────────────────

func invitationFromNode(n *sdk.Node) *service.InvitationRecord {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.InvitationRecord{
		NodeID:     n.NodeID,
		TokenHash:  ps(p, invTokenHash),
		Email:      ps(p, invEmail),
		UserID:     ps(p, invUserID),
		InvitedBy:  ps(p, invInvitedBy),
		Role:       ps(p, invRole),
		ExpiresAt:  pi(p, invExpiresAt),
		AcceptedAt: pi(p, invAcceptedAt),
		CreatedAt:  pi(p, invCreatedAt),
	}
}

func (r *entRepository) FindInvitationByHash(ctx context.Context, tokenHash string) (*service.InvitationRecord, error) {
	if tokenHash == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeUserInvitation,
		map[string]any{invTokenHash: tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindInvitationByHash: %w", err)
	}
	return invitationFromNode(firstNode(nodes)), nil
}

func (r *entRepository) UpdateInvitation(ctx context.Context, nodeID string, fields map[string]any) error {
	if nodeID == "" {
		return fmt.Errorf("repo: UpdateInvitation: missing node id")
	}
	patch := map[string]any{}
	for k, v := range fields {
		switch k {
		case "accepted_at":
			patch[invAcceptedAt] = toInt64(v)
		case "user_id":
			patch[invUserID] = v
		}
	}
	if len(patch) == 0 {
		return nil
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{Type: sdk.OpUpdateNode, TypeID: typeUserInvitation, NodeID: nodeID, Patch: patch}})
	if err != nil {
		return fmt.Errorf("repo: UpdateInvitation: %w", err)
	}
	return nil
}

// ── Password-reset tokens ─────────────────────────────────────────

func passwordResetFromNode(n *sdk.Node) *service.PasswordResetToken {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.PasswordResetToken{
		NodeID:     n.NodeID,
		TokenHash:  ps(p, prTokenHash),
		UserID:     ps(p, prUserID),
		ExpiresAt:  pi(p, prExpiresAt),
		CreatedAt:  pi(p, prCreatedAt),
		ConsumedAt: pi(p, prConsumedAt),
	}
}

func (r *entRepository) CreatePasswordResetToken(ctx context.Context, t *service.PasswordResetToken) error {
	if t == nil {
		return fmt.Errorf("repo: CreatePasswordResetToken: nil record")
	}
	data := map[string]any{
		prTokenHash: t.TokenHash,
		prUserID:    t.UserID,
		prExpiresAt: t.ExpiresAt,
		prCreatedAt: t.CreatedAt,
	}
	if t.ConsumedAt != 0 {
		data[prConsumedAt] = t.ConsumedAt
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(t.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typePasswordResetToken, Data: data}})
	if err != nil {
		return fmt.Errorf("repo: CreatePasswordResetToken: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreatePasswordResetToken")
	if err != nil {
		return err
	}
	t.NodeID = id
	return nil
}

func (r *entRepository) FindPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*service.PasswordResetToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typePasswordResetToken,
		map[string]any{prTokenHash: tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindPasswordResetTokenByHash: %w", err)
	}
	return passwordResetFromNode(firstNode(nodes)), nil
}

func (r *entRepository) MarkPasswordResetTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return fmt.Errorf("repo: MarkPasswordResetTokenConsumed: missing token id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typePasswordResetToken,
			NodeID: tokenID,
			Patch:  map[string]any{prConsumedAt: atMs},
		}})
	if err != nil {
		return fmt.Errorf("repo: MarkPasswordResetTokenConsumed: %w", err)
	}
	return nil
}

// ── Email-verification tokens ─────────────────────────────────────

func emailVerificationFromNode(n *sdk.Node) *service.EmailVerificationToken {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.EmailVerificationToken{
		NodeID:     n.NodeID,
		TokenHash:  ps(p, evTokenHash),
		UserID:     ps(p, evUserID),
		Email:      ps(p, evEmail),
		ExpiresAt:  pi(p, evExpiresAt),
		CreatedAt:  pi(p, evCreatedAt),
		ConsumedAt: pi(p, evConsumedAt),
	}
}

func (r *entRepository) CreateEmailVerificationToken(ctx context.Context, t *service.EmailVerificationToken) error {
	if t == nil {
		return fmt.Errorf("repo: CreateEmailVerificationToken: nil record")
	}
	data := map[string]any{
		evTokenHash: t.TokenHash,
		evEmail:     t.Email,
		evExpiresAt: t.ExpiresAt,
		evCreatedAt: t.CreatedAt,
	}
	if t.UserID != "" {
		data[evUserID] = t.UserID
	}
	if t.ConsumedAt != 0 {
		data[evConsumedAt] = t.ConsumedAt
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(t.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeEmailVerificationToken, Data: data}})
	if err != nil {
		return fmt.Errorf("repo: CreateEmailVerificationToken: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateEmailVerificationToken")
	if err != nil {
		return err
	}
	t.NodeID = id
	return nil
}

func (r *entRepository) FindEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*service.EmailVerificationToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeEmailVerificationToken,
		map[string]any{evTokenHash: tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailVerificationTokenByHash: %w", err)
	}
	return emailVerificationFromNode(firstNode(nodes)), nil
}

func (r *entRepository) MarkEmailVerificationTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return fmt.Errorf("repo: MarkEmailVerificationTokenConsumed: missing token id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeEmailVerificationToken,
			NodeID: tokenID,
			Patch:  map[string]any{evConsumedAt: atMs},
		}})
	if err != nil {
		return fmt.Errorf("repo: MarkEmailVerificationTokenConsumed: %w", err)
	}
	return nil
}

// ── Lockout ───────────────────────────────────────────────────────

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
	_, err = r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeUser,
			NodeID: userID,
			Patch:  map[string]any{ufFailedLoginCount: int64(newCount)},
		}})
	if err != nil {
		return 0, fmt.Errorf("repo: IncrementFailedLoginCount: %w", err)
	}
	return newCount, nil
}

func (r *entRepository) ResetFailedLoginCount(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("repo: ResetFailedLoginCount: missing user id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeUser,
			NodeID: userID,
			Patch: map[string]any{
				ufFailedLoginCount: int64(0),
				ufLockedUntil:      int64(0),
			},
		}})
	if err != nil {
		return fmt.Errorf("repo: ResetFailedLoginCount: %w", err)
	}
	return nil
}

func (r *entRepository) SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error {
	if userID == "" {
		return fmt.Errorf("repo: SetUserLockedUntil: missing user id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeUser,
			NodeID: userID,
			Patch:  map[string]any{ufLockedUntil: lockedUntilMs},
		}})
	if err != nil {
		return fmt.Errorf("repo: SetUserLockedUntil: %w", err)
	}
	return nil
}

// ── EmailChangeToken ──────────────────────────────────────────────

func emailChangeFromNode(n *sdk.Node) *service.EmailChangeToken {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.EmailChangeToken{
		NodeID:     n.NodeID,
		TokenHash:  ps(p, ecTokenHash),
		UserID:     ps(p, ecUserID),
		OldEmail:   ps(p, ecOldEmail),
		NewEmail:   ps(p, ecNewEmail),
		ExpiresAt:  pi(p, ecExpiresAt),
		CreatedAt:  pi(p, ecCreatedAt),
		ConsumedAt: pi(p, ecConsumedAt),
	}
}

func (r *entRepository) CreateEmailChangeToken(ctx context.Context, t *service.EmailChangeToken) error {
	if t == nil {
		return fmt.Errorf("repo: CreateEmailChangeToken: nil record")
	}
	data := map[string]any{
		ecTokenHash: t.TokenHash,
		ecUserID:    t.UserID,
		ecOldEmail:  t.OldEmail,
		ecNewEmail:  t.NewEmail,
		ecExpiresAt: t.ExpiresAt,
		ecCreatedAt: t.CreatedAt,
	}
	if t.ConsumedAt != 0 {
		data[ecConsumedAt] = t.ConsumedAt
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(t.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeEmailChangeToken, Data: data}})
	if err != nil {
		return fmt.Errorf("repo: CreateEmailChangeToken: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateEmailChangeToken")
	if err != nil {
		return err
	}
	t.NodeID = id
	return nil
}

func (r *entRepository) FindEmailChangeTokenByHash(ctx context.Context, tokenHash string) (*service.EmailChangeToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeEmailChangeToken,
		map[string]any{ecTokenHash: tokenHash})
	if err != nil {
		return nil, fmt.Errorf("repo: FindEmailChangeTokenByHash: %w", err)
	}
	return emailChangeFromNode(firstNode(nodes)), nil
}

func (r *entRepository) MarkEmailChangeTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return fmt.Errorf("repo: MarkEmailChangeTokenConsumed: missing token id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, systemActor, "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeEmailChangeToken,
			NodeID: tokenID,
			Patch:  map[string]any{ecConsumedAt: atMs},
		}})
	if err != nil {
		return fmt.Errorf("repo: MarkEmailChangeTokenConsumed: %w", err)
	}
	return nil
}

func (r *entRepository) UpdateUserEmail(ctx context.Context, userID, newEmail string, atMs int64) error {
	if userID == "" {
		return fmt.Errorf("repo: UpdateUserEmail: missing user id")
	}
	_, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(userID), "",
		[]sdk.Operation{{
			Type:   sdk.OpUpdateNode,
			TypeID: typeUser,
			NodeID: userID,
			Patch: map[string]any{
				ufEmail:           newEmail,
				ufEmailVerified:   true,
				ufEmailVerifiedAt: atMs,
				ufUpdatedAt:       atMs,
			},
		}})
	if err != nil {
		return fmt.Errorf("repo: UpdateUserEmail: %w", err)
	}
	return nil
}

// ── OAuthIdentity ─────────────────────────────────────────────────

func oauthIdentityFromNode(n *sdk.Node) *service.OAuthIdentity {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &service.OAuthIdentity{
		NodeID:          n.NodeID,
		UserID:          ps(p, oiUserID),
		Provider:        ps(p, oiProvider),
		ProviderUserID:  ps(p, oiProviderUserID),
		EmailAtLinkTime: ps(p, oiEmailAtLink),
		CreatedAt:       pi(p, oiCreatedAt),
	}
}

func (r *entRepository) FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*service.User, error) {
	if provider == "" || providerUserID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeOAuthIdentity,
		map[string]any{oiProvider: provider, oiProviderUserID: providerUserID})
	if err != nil {
		return nil, fmt.Errorf("repo: FindUserByProviderID: %w", err)
	}
	link := oauthIdentityFromNode(firstNode(nodes))
	if link == nil {
		return nil, nil
	}
	return r.GetUser(ctx, link.UserID)
}

func (r *entRepository) CreateOAuthIdentity(ctx context.Context, oi *service.OAuthIdentity) error {
	if oi == nil {
		return fmt.Errorf("repo: CreateOAuthIdentity: nil record")
	}
	data := map[string]any{
		oiUserID:         oi.UserID,
		oiProvider:       oi.Provider,
		oiProviderUserID: oi.ProviderUserID,
		oiEmailAtLink:    oi.EmailAtLinkTime,
		oiCreatedAt:      oi.CreatedAt,
	}
	res, err := r.client.ExecuteAtomic(ctx, r.tenantID, actorStr(oi.UserID), "",
		[]sdk.Operation{{Type: sdk.OpCreateNode, TypeID: typeOAuthIdentity, Data: data}})
	if err != nil {
		return fmt.Errorf("repo: CreateOAuthIdentity: %w", err)
	}
	id, err := firstCreatedNodeID(res, "CreateOAuthIdentity")
	if err != nil {
		return err
	}
	oi.NodeID = id
	return nil
}

func (r *entRepository) ListOAuthIdentitiesForUser(ctx context.Context, userID string) ([]*service.OAuthIdentity, error) {
	if userID == "" {
		return nil, nil
	}
	nodes, err := r.client.QueryNodes(ctx, r.tenantID, systemActor, typeOAuthIdentity,
		map[string]any{oiUserID: userID})
	if err != nil {
		return nil, fmt.Errorf("repo: ListOAuthIdentitiesForUser: %w", err)
	}
	out := make([]*service.OAuthIdentity, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, oauthIdentityFromNode(n))
	}
	return out, nil
}

// Compile-time check that entRepository satisfies the interface.
var _ service.Repository = (*entRepository)(nil)
