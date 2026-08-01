package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/graph"
	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

const (
	dbTypeUser             = 1
	dbTypeWorkingGroup     = 2
	dbTypeRefreshToken     = 5
	dbTypePasswordReset    = 19
	dbTypePasskey          = 20
	dbTypePasskeyChallenge = 21
	dbTypeQrLoginSession   = 22
	dbTypeAuditEvent       = 26
	dbTypeInvitation       = 27
	dbTypeAdminHelpReq     = 28

	dbEdgeMemberOf = 101
)

const (
	dbUfEmail            = "1"
	dbUfName             = "2"
	dbUfRole             = "3"
	dbUfAvatarURL        = "4"
	dbUfCreatedAt        = "5"
	dbUfUpdatedAt        = "6"
	dbUfPasswordHash     = "7"
	dbUfTOTPRequired     = "8"
	dbUfFailedLoginCount = "9"
	dbUfLockedUntil      = "10"
	dbUfStatus           = "11"
	dbUfRecoveryEmail    = "12"
	dbUfInvitedBy        = "13"
	dbUfInvitedAt        = "14"
	dbUfQuotaBytes       = "15"
	dbUfDeactivatedAt    = "16"
	dbUfLastLoginAt      = "17"
	dbUfEmailVerified    = "18"
	dbUfEmailVerifiedAt  = "19"
)

const (
	dbGfName        = "1"
	dbGfDescription = "2"
	dbGfCreatedBy   = "3"
	dbGfCreatedAt   = "4"
	dbGfUpdatedAt   = "5"
)

const (
	dbRfTokenHash  = "1"
	dbRfUserID     = "2"
	dbRfDeviceInfo = "3"
	dbRfExpiresAt  = "4"
	dbRfCreatedAt  = "5"
	dbRfDeviceName = "6"
	dbRfIPAddress  = "7"
	dbRfUserAgent  = "8"
	dbRfLastUsedAt = "9"
	dbRfConsumedAt = "10"
)

const (
	dbPrfTokenHash = "1"
	dbPrfUserID    = "2"
	dbPrfExpiresAt = "3"
	dbPrfCreatedAt = "4"
)

const (
	dbPkfCredentialID = "1"
	dbPkfUserID       = "2"
	dbPkfDeviceName   = "5"
	dbPkfCreatedAt    = "8"
	dbPkfLastUsedAt   = "9"
)

const (
	dbInvTokenHash  = "1"
	dbInvEmail      = "2"
	dbInvUserID     = "3"
	dbInvInvitedBy  = "4"
	dbInvRole       = "5"
	dbInvExpiresAt  = "6"
	dbInvAcceptedAt = "7"
	dbInvCreatedAt  = "8"
)

const (
	dbHfEmail           = "1"
	dbHfReason          = "2"
	dbHfSourceIP        = "3"
	dbHfUserAgent       = "4"
	dbHfStatus          = "5"
	dbHfResolvedBy      = "6"
	dbHfResolutionNotes = "7"
	dbHfResolvedAt      = "8"
	dbHfCreatedAt       = "9"
)

const (
	dbAfEventType    = "1"
	dbAfActorUserID  = "2"
	dbAfTargetUserID = "3"
	dbAfIPAddress    = "4"
	dbAfUserAgent    = "5"
	dbAfSuccess      = "6"
	dbAfDetails      = "7"
	dbAfCreatedAt    = "8"
)

type dbFieldSpec struct {
	col             string
	kind            string
	caseInsensitive bool
}

const (
	dbKindString = "string"
	dbKindBool   = "bool"
	dbKindInt64  = "int64"
)

var (
	userQueryFields = map[string]dbFieldSpec{
		dbUfEmail:            {col: "email", kind: dbKindString, caseInsensitive: true},
		dbUfName:             {col: "name", kind: dbKindString},
		dbUfRole:             {col: "role", kind: dbKindString},
		dbUfAvatarURL:        {col: "avatar_url", kind: dbKindString},
		dbUfPasswordHash:     {col: "password_hash", kind: dbKindString},
		dbUfTOTPRequired:     {col: "totp_required", kind: dbKindBool},
		dbUfFailedLoginCount: {col: "failed_login_count", kind: dbKindInt64},
		dbUfLockedUntil:      {col: "locked_until_ms", kind: dbKindInt64},
		dbUfStatus:           {col: "status", kind: dbKindString},
		dbUfRecoveryEmail:    {col: "recovery_email", kind: dbKindString, caseInsensitive: true},
		dbUfInvitedBy:        {col: "invited_by", kind: dbKindString},
		dbUfInvitedAt:        {col: "invited_at_ms", kind: dbKindInt64},
		dbUfQuotaBytes:       {col: "quota_bytes", kind: dbKindInt64},
		dbUfDeactivatedAt:    {col: "deactivated_at_ms", kind: dbKindInt64},
		dbUfLastLoginAt:      {col: "last_login_at_ms", kind: dbKindInt64},
		dbUfEmailVerified:    {col: "email_verified", kind: dbKindBool},
		dbUfEmailVerifiedAt:  {col: "email_verified_at_ms", kind: dbKindInt64},
	}
	groupQueryFields = map[string]dbFieldSpec{
		dbGfName:        {col: "name", kind: dbKindString},
		dbGfDescription: {col: "description", kind: dbKindString},
		dbGfCreatedBy:   {col: "created_by", kind: dbKindString},
		dbGfCreatedAt:   {col: "created_at_ms", kind: dbKindInt64},
		dbGfUpdatedAt:   {col: "updated_at_ms", kind: dbKindInt64},
	}
	refreshQueryFields = map[string]dbFieldSpec{
		dbRfTokenHash: {col: "token_hash", kind: dbKindString},
		dbRfUserID:    {col: "user_id", kind: dbKindString},
	}
	passkeyQueryFields = map[string]dbFieldSpec{
		dbPkfCredentialID: {col: "credential_id", kind: dbKindString},
		dbPkfUserID:       {col: "user_id", kind: dbKindString},
		dbPkfDeviceName:   {col: "device_name", kind: dbKindString},
	}
	auditQueryFields = map[string]dbFieldSpec{
		dbAfEventType:    {col: "event_type", kind: dbKindString},
		dbAfActorUserID:  {col: "actor", kind: dbKindString},
		dbAfTargetUserID: {col: "target", kind: dbKindString},
		dbAfSuccess:      {col: "success", kind: dbKindBool},
	}
	helpQueryFields = map[string]dbFieldSpec{
		dbHfEmail:      {col: "email", kind: dbKindString, caseInsensitive: true},
		dbHfStatus:     {col: "status", kind: dbKindString},
		dbHfResolvedBy: {col: "resolved_by", kind: dbKindString},
	}
)

func (r *pgRepository) GetNode(ctx context.Context, _, _ string, typeID int, nodeID string) (*graph.Node, error) {
	switch typeID {
	case dbTypeUser:
		return r.getUserNode(ctx, nodeID)
	case dbTypeWorkingGroup:
		return r.getGroupNode(ctx, nodeID)
	case dbTypeRefreshToken:
		return r.getRefreshTokenNode(ctx, nodeID)
	case dbTypePasskey:
		return r.getPasskeyNode(ctx, nodeID)
	case dbTypeAuditEvent:
		return r.getAuditEventNode(ctx, nodeID)
	case dbTypeAdminHelpReq:
		return r.getHelpRequestNode(ctx, nodeID)
	default:
		return nil, fmt.Errorf("postgres: GetNode: unsupported type_id %d", typeID)
	}
}

func (r *pgRepository) QueryNodes(ctx context.Context, _, _ string, typeID int, filter map[string]any) ([]*graph.Node, error) {
	switch typeID {
	case dbTypeUser:
		return r.queryUserNodes(ctx, filter)
	case dbTypeWorkingGroup:
		return r.queryGroupNodes(ctx, filter)
	case dbTypeRefreshToken:
		return r.queryRefreshTokenNodes(ctx, filter)
	case dbTypePasswordReset:
		return r.queryPasswordResetNodes(ctx, filter)
	case dbTypePasskey:
		return r.queryPasskeyNodes(ctx, filter)
	case dbTypeAuditEvent:
		return r.queryAuditEventNodes(ctx, filter)
	case dbTypeAdminHelpReq:
		return r.queryHelpRequestNodes(ctx, filter)
	default:
		return nil, fmt.Errorf("postgres: QueryNodes: unsupported type_id %d", typeID)
	}
}

func (r *pgRepository) ExecuteAtomic(ctx context.Context, _, _ string, ops []graph.Operation) (*graph.CommitResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr("ExecuteAtomic", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	createdIDs := make([]string, 0, len(ops))
	for _, op := range ops {
		createdID, err := r.applyAtomicOp(ctx, tx, op)
		if err != nil {
			return nil, err
		}
		if createdID != "" {
			createdIDs = append(createdIDs, createdID)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr("ExecuteAtomic", err)
	}
	return &graph.CommitResult{Success: true, Applied: true, CreatedNodeIDs: createdIDs}, nil
}

func (r *pgRepository) GetEdgesFrom(ctx context.Context, _, _ string, fromNodeID string, edgeTypeID int) ([]*graph.Edge, error) {
	if edgeTypeID != dbEdgeMemberOf {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT user_id, group_id
		  FROM group_memberships
		 WHERE project_id = $1 AND user_id = $2
		 ORDER BY group_id ASC
	`, r.projectID, fromNodeID)
	if err != nil {
		return nil, wrapPgErr("GetEdgesFrom", err)
	}
	defer rows.Close()

	var out []*graph.Edge
	for rows.Next() {
		var fromID, toID string
		if err := rows.Scan(&fromID, &toID); err != nil {
			return nil, wrapPgErr("GetEdgesFrom", err)
		}
		out = append(out, &graph.Edge{EdgeTypeID: dbEdgeMemberOf, FromNodeID: fromID, ToNodeID: toID})
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("GetEdgesFrom", err)
	}
	return out, nil
}

func (r *pgRepository) GetEdgesTo(ctx context.Context, _, _ string, toNodeID string, edgeTypeID int) ([]*graph.Edge, error) {
	if edgeTypeID != dbEdgeMemberOf {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT user_id, group_id
		  FROM group_memberships
		 WHERE project_id = $1 AND group_id = $2
		 ORDER BY user_id ASC
	`, r.projectID, toNodeID)
	if err != nil {
		return nil, wrapPgErr("GetEdgesTo", err)
	}
	defer rows.Close()

	var out []*graph.Edge
	for rows.Next() {
		var fromID, toID string
		if err := rows.Scan(&fromID, &toID); err != nil {
			return nil, wrapPgErr("GetEdgesTo", err)
		}
		out = append(out, &graph.Edge{EdgeTypeID: dbEdgeMemberOf, FromNodeID: fromID, ToNodeID: toID})
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("GetEdgesTo", err)
	}
	return out, nil
}

func (r *pgRepository) SearchNodes(ctx context.Context, _, _ string, typeID int, query string) ([]*graph.Node, error) {
	q := "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	if q == "%%" {
		return nil, nil
	}

	switch typeID {
	case dbTypeUser:
		rows, err := r.pool.Query(ctx, `
			SELECT `+userColumns+`
			  FROM users
			 WHERE project_id = $1
			   AND (lower(email) LIKE $2 OR lower(name) LIKE $2)
			 ORDER BY created_at_ms ASC, id ASC
		`, r.projectID, q)
		if err != nil {
			return nil, wrapPgErr("SearchNodes", err)
		}
		defer rows.Close()
		var out []*graph.Node
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return nil, wrapPgErr("SearchNodes", err)
			}
			out = append(out, userNodeFromRecord(u))
		}
		if err := rows.Err(); err != nil {
			return nil, wrapPgErr("SearchNodes", err)
		}
		return out, nil
	case dbTypeWorkingGroup:
		rows, err := r.pool.Query(ctx, `
			SELECT id, name, description, created_by, created_at_ms, updated_at_ms
			  FROM groups
			 WHERE project_id = $1
			   AND (lower(name) LIKE $2 OR lower(description) LIKE $2)
			 ORDER BY created_at_ms ASC, id ASC
		`, r.projectID, q)
		if err != nil {
			return nil, wrapPgErr("SearchNodes", err)
		}
		defer rows.Close()
		var out []*graph.Node
		for rows.Next() {
			node, err := scanGroupNode(rows)
			if err != nil {
				return nil, wrapPgErr("SearchNodes", err)
			}
			out = append(out, node)
		}
		if err := rows.Err(); err != nil {
			return nil, wrapPgErr("SearchNodes", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("postgres: SearchNodes: unsupported type_id %d", typeID)
	}
}

func (r *pgRepository) applyAtomicOp(ctx context.Context, tx pgx.Tx, op graph.Operation) (string, error) {
	switch op.Type {
	case graph.OpCreateNode:
		return r.createAtomicNode(ctx, tx, op)
	case graph.OpUpdateNode:
		return "", r.updateAtomicNode(ctx, tx, op)
	case graph.OpDeleteNode:
		return "", r.deleteAtomicNode(ctx, tx, op)
	case graph.OpCreateEdge:
		return "", r.createAtomicEdge(ctx, tx, op)
	case graph.OpDeleteEdge:
		return "", r.deleteAtomicEdge(ctx, tx, op)
	default:
		return "", fmt.Errorf("postgres: ExecuteAtomic: unsupported op type %v", op.Type)
	}
}

func (r *pgRepository) createAtomicNode(ctx context.Context, tx pgx.Tx, op graph.Operation) (string, error) {
	switch op.TypeID {
	case dbTypeUser:
		id := op.NodeID
		if id == "" {
			id = newID()
		}
		createdAt, _ := nullableInt64(op.Data[dbUfCreatedAt])
		if createdAt == 0 {
			createdAt = nowMs()
		}
		updatedAt, _ := nullableInt64(op.Data[dbUfUpdatedAt])
		if updatedAt == 0 {
			updatedAt = createdAt
		}
		email, _ := nullableString(op.Data[dbUfEmail])
		name, _ := nullableString(op.Data[dbUfName])
		role, _ := nullableString(op.Data[dbUfRole])
		if role == "" {
			role = "member"
		}
		avatarURL, _ := nullableString(op.Data[dbUfAvatarURL])
		passwordHash, _ := nullableString(op.Data[dbUfPasswordHash])
		status, _ := nullableString(op.Data[dbUfStatus])
		if status == "" {
			status = "active"
		}
		recoveryEmail, _ := nullableString(op.Data[dbUfRecoveryEmail])
		invitedBy, _ := nullableString(op.Data[dbUfInvitedBy])
		totpRequired, _ := nullableBool(op.Data[dbUfTOTPRequired])
		emailVerified, _ := nullableBool(op.Data[dbUfEmailVerified])
		failedLoginCount, _ := nullableInt64(op.Data[dbUfFailedLoginCount])
		lockedUntil, _ := nullableInt64(op.Data[dbUfLockedUntil])
		invitedAt, _ := nullableInt64(op.Data[dbUfInvitedAt])
		quotaBytes, _ := nullableInt64(op.Data[dbUfQuotaBytes])
		deactivatedAt, _ := nullableInt64(op.Data[dbUfDeactivatedAt])
		lastLoginAt, _ := nullableInt64(op.Data[dbUfLastLoginAt])
		emailVerifiedAt, _ := nullableInt64(op.Data[dbUfEmailVerifiedAt])

		_, err := tx.Exec(
			ctx, `
			INSERT INTO users (
				id, project_id, email, name, role, avatar_url, status,
				recovery_email, password_hash, quota_bytes, totp_required,
				failed_login_count, locked_until_ms,
				email_verified, email_verified_at_ms,
				invited_by, invited_at_ms, last_login_at_ms, deactivated_at_ms,
				created_at_ms, updated_at_ms
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7,
				$8, $9, $10, $11,
				$12, $13,
				$14, $15,
				$16, $17, $18, $19,
				$20, $21
			)
		`, id, r.projectID, email, name, role, avatarURL, status,
			recoveryEmail, passwordHash, quotaBytes, totpRequired,
			failedLoginCount, lockedUntil,
			emailVerified, emailVerifiedAt,
			invitedBy, invitedAt, lastLoginAt, deactivatedAt,
			createdAt, updatedAt,
		)
		if err != nil {
			return "", wrapPgErr("ExecuteAtomic(create user)", err)
		}
		return id, nil
	case dbTypeWorkingGroup:
		id := op.NodeID
		if id == "" {
			id = newID()
		}
		name, _ := nullableString(op.Data[dbGfName])
		description, _ := nullableString(op.Data[dbGfDescription])
		createdBy, _ := nullableString(op.Data[dbGfCreatedBy])
		createdAt, _ := nullableInt64(op.Data[dbGfCreatedAt])
		if createdAt == 0 {
			createdAt = nowMs()
		}
		updatedAt, _ := nullableInt64(op.Data[dbGfUpdatedAt])
		if updatedAt == 0 {
			updatedAt = createdAt
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO groups (id, project_id, name, description, created_by, created_at_ms, updated_at_ms)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, id, r.projectID, name, description, createdBy, createdAt, updatedAt)
		if err != nil {
			return "", wrapPgErr("ExecuteAtomic(create group)", err)
		}
		return id, nil
	case dbTypePasswordReset:
		id := op.NodeID
		if id == "" {
			id = newID()
		}
		tokenHash, _ := nullableString(op.Data[dbPrfTokenHash])
		userID, _ := nullableString(op.Data[dbPrfUserID])
		expiresAt, _ := nullableInt64(op.Data[dbPrfExpiresAt])
		createdAt, _ := nullableInt64(op.Data[dbPrfCreatedAt])
		if createdAt == 0 {
			createdAt = nowMs()
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO password_reset_tokens (
				id, project_id, token_hash, user_id, email,
				expires_at_ms, created_at_ms, consumed_at_ms
			) VALUES ($1, $2, $3, $4, '', $5, $6, 0)
		`, id, r.projectID, tokenHash, userID, expiresAt, createdAt)
		if err != nil {
			return "", wrapPgErr("ExecuteAtomic(create password reset)", err)
		}
		return id, nil
	case dbTypeInvitation:
		id := op.NodeID
		if id == "" {
			id = newID()
		}
		tokenHash, _ := nullableString(op.Data[dbInvTokenHash])
		email, _ := nullableString(op.Data[dbInvEmail])
		userID, _ := nullableString(op.Data[dbInvUserID])
		invitedBy, _ := nullableString(op.Data[dbInvInvitedBy])
		role, _ := nullableString(op.Data[dbInvRole])
		if role == "" {
			role = "member"
		}
		expiresAt, _ := nullableInt64(op.Data[dbInvExpiresAt])
		acceptedAt, _ := nullableInt64(op.Data[dbInvAcceptedAt])
		createdAt, _ := nullableInt64(op.Data[dbInvCreatedAt])
		if createdAt == 0 {
			createdAt = nowMs()
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO user_invitations (
				id, project_id, token_hash, email, user_id, invited_by, role,
				expires_at_ms, accepted_at_ms, created_at_ms
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, id, r.projectID, tokenHash, email, userID, invitedBy, role, expiresAt, acceptedAt, createdAt)
		if err != nil {
			return "", wrapPgErr("ExecuteAtomic(create invitation)", err)
		}
		return id, nil
	case dbTypeAuditEvent:
		id := op.NodeID
		if id == "" {
			id = newID()
		}
		eventType, _ := nullableString(op.Data[dbAfEventType])
		actorUserID, _ := nullableString(op.Data[dbAfActorUserID])
		targetUserID, _ := nullableString(op.Data[dbAfTargetUserID])
		ipAddress, _ := nullableString(op.Data[dbAfIPAddress])
		userAgent, _ := nullableString(op.Data[dbAfUserAgent])
		success, _ := nullableBool(op.Data[dbAfSuccess])
		details, _ := nullableString(op.Data[dbAfDetails])
		if strings.TrimSpace(details) == "" {
			details = "{}"
		}
		createdAt, _ := nullableInt64(op.Data[dbAfCreatedAt])
		if createdAt == 0 {
			createdAt = nowMs()
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO audit_events (
				id, project_id, event_type, actor, target, ip_address, user_agent,
				success, details, occurred_at_ms
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ($9)::jsonb, $10)
		`, id, r.projectID, eventType, actorUserID, targetUserID, ipAddress, userAgent, success, details, createdAt)
		if err != nil {
			return "", wrapPgErr("ExecuteAtomic(create audit event)", err)
		}
		return id, nil
	case dbTypeAdminHelpReq:
		id := op.NodeID
		if id == "" {
			id = newID()
		}
		email, _ := nullableString(op.Data[dbHfEmail])
		reason, _ := nullableString(op.Data[dbHfReason])
		sourceIP, _ := nullableString(op.Data[dbHfSourceIP])
		userAgent, _ := nullableString(op.Data[dbHfUserAgent])
		status, _ := nullableString(op.Data[dbHfStatus])
		if status == "" {
			status = "pending"
		}
		resolvedBy, _ := nullableString(op.Data[dbHfResolvedBy])
		resolutionNotes, _ := nullableString(op.Data[dbHfResolutionNotes])
		resolvedAt, _ := nullableInt64(op.Data[dbHfResolvedAt])
		createdAt, _ := nullableInt64(op.Data[dbHfCreatedAt])
		if createdAt == 0 {
			createdAt = nowMs()
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO admin_help_requests (
				id, project_id, email, reason, source_ip, user_agent, status,
				resolved_by, resolution_notes, resolved_at_ms, created_at_ms
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, id, r.projectID, email, reason, sourceIP, userAgent, status, resolvedBy, resolutionNotes, resolvedAt, createdAt)
		if err != nil {
			return "", wrapPgErr("ExecuteAtomic(create admin help request)", err)
		}
		return id, nil
	default:
		return "", fmt.Errorf("postgres: ExecuteAtomic(create): unsupported type_id %d", op.TypeID)
	}
}

func (r *pgRepository) updateAtomicNode(ctx context.Context, tx pgx.Tx, op graph.Operation) error {
	switch op.TypeID {
	case dbTypeUser:
		return updateBySpecs(ctx, tx, r.projectID, "users", op.NodeID, op.Patch, userQueryFields)
	case dbTypeWorkingGroup:
		return updateBySpecs(ctx, tx, r.projectID, "groups", op.NodeID, op.Patch, groupQueryFields)
	case dbTypeAdminHelpReq:
		return updateBySpecs(ctx, tx, r.projectID, "admin_help_requests", op.NodeID, op.Patch, map[string]dbFieldSpec{
			dbHfEmail:           {col: "email", kind: dbKindString},
			dbHfReason:          {col: "reason", kind: dbKindString},
			dbHfSourceIP:        {col: "source_ip", kind: dbKindString},
			dbHfUserAgent:       {col: "user_agent", kind: dbKindString},
			dbHfStatus:          {col: "status", kind: dbKindString},
			dbHfResolvedBy:      {col: "resolved_by", kind: dbKindString},
			dbHfResolutionNotes: {col: "resolution_notes", kind: dbKindString},
			dbHfResolvedAt:      {col: "resolved_at_ms", kind: dbKindInt64},
		})
	case dbTypePasskey:
		return updateBySpecs(ctx, tx, r.projectID, "passkeys", op.NodeID, op.Patch, map[string]dbFieldSpec{
			dbPkfDeviceName: {col: "device_name", kind: dbKindString},
			dbPkfLastUsedAt: {col: "last_used_at_ms", kind: dbKindInt64},
			"4":             {col: "sign_count", kind: dbKindInt64},
		})
	case dbTypePasskeyChallenge:
		return updateBySpecs(ctx, tx, r.projectID, "passkey_challenges", op.NodeID, op.Patch, map[string]dbFieldSpec{
			"1": {col: "challenge", kind: dbKindString},
		})
	case dbTypeQrLoginSession:
		return updateBySpecs(ctx, tx, r.projectID, "qr_login_sessions", op.NodeID, op.Patch, map[string]dbFieldSpec{
			"2":  {col: "status", kind: dbKindString},
			"3":  {col: "user_id", kind: dbKindString},
			"7":  {col: "approved_device_info", kind: dbKindString},
			"8":  {col: "expires_at_ms", kind: dbKindInt64},
			"10": {col: "updated_at_ms", kind: dbKindInt64},
		})
	default:
		return fmt.Errorf("postgres: ExecuteAtomic(update): unsupported type_id %d", op.TypeID)
	}
}

func (r *pgRepository) deleteAtomicNode(ctx context.Context, tx pgx.Tx, op graph.Operation) error {
	var table string
	switch op.TypeID {
	case dbTypeWorkingGroup:
		table = "groups"
	case dbTypeRefreshToken:
		table = "refresh_tokens"
	case dbTypePasskey:
		table = "passkeys"
	default:
		return fmt.Errorf("postgres: ExecuteAtomic(delete): unsupported type_id %d", op.TypeID)
	}
	_, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE project_id = $1 AND id = $2`, table), r.projectID, op.NodeID)
	if err != nil {
		return wrapPgErr("ExecuteAtomic(delete)", err)
	}
	return nil
}

func (r *pgRepository) createAtomicEdge(ctx context.Context, tx pgx.Tx, op graph.Operation) error {
	if op.EdgeTypeID != dbEdgeMemberOf {
		return fmt.Errorf("postgres: ExecuteAtomic(create edge): unsupported edge_type_id %d", op.EdgeTypeID)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO group_memberships (project_id, group_id, user_id, created_at_ms)
		VALUES ($1, $2, $3, $4)
	`, r.projectID, op.ToNodeID, op.FromNodeID, nowMs())
	if err != nil {
		return wrapPgErr("ExecuteAtomic(create edge)", err)
	}
	return nil
}

func (r *pgRepository) deleteAtomicEdge(ctx context.Context, tx pgx.Tx, op graph.Operation) error {
	if op.EdgeTypeID != dbEdgeMemberOf {
		return fmt.Errorf("postgres: ExecuteAtomic(delete edge): unsupported edge_type_id %d", op.EdgeTypeID)
	}
	_, err := tx.Exec(ctx, `
		DELETE FROM group_memberships
		 WHERE project_id = $1 AND group_id = $2 AND user_id = $3
	`, r.projectID, op.ToNodeID, op.FromNodeID)
	if err != nil {
		return wrapPgErr("ExecuteAtomic(delete edge)", err)
	}
	return nil
}

func (r *pgRepository) getUserNode(ctx context.Context, userID string) (*graph.Node, error) {
	u, err := r.GetUser(ctx, userID)
	if err != nil || u == nil {
		return nil, err
	}
	return userNodeFromRecord(u), nil
}

func (r *pgRepository) queryUserNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`SELECT `+userColumns+` FROM users WHERE project_id = $1`, r.projectID, filter, userQueryFields, ` ORDER BY created_at_ms ASC, id ASC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(users)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(users)", err)
		}
		out = append(out, userNodeFromRecord(u))
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(users)", err)
	}
	return out, nil
}

func (r *pgRepository) getGroupNode(ctx context.Context, groupID string) (*graph.Node, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, name, description, created_by, created_at_ms, updated_at_ms
		  FROM groups
		 WHERE project_id = $1 AND id = $2
	`, r.projectID, groupID)
	node, err := scanGroupNode(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetNode(group)", err)
	}
	return node, nil
}

func (r *pgRepository) queryGroupNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`
		SELECT id, name, description, created_by, created_at_ms, updated_at_ms
		  FROM groups
		 WHERE project_id = $1
	`, r.projectID, filter, groupQueryFields, ` ORDER BY created_at_ms ASC, id ASC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(groups)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		node, err := scanGroupNode(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(groups)", err)
		}
		out = append(out, node)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(groups)", err)
	}
	return out, nil
}

func (r *pgRepository) getRefreshTokenNode(ctx context.Context, nodeID string) (*graph.Node, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+refreshTokenColumns+`
		  FROM refresh_tokens
		 WHERE project_id = $1 AND id = $2
	`, r.projectID, nodeID)
	rec, err := scanRefreshToken(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetNode(refresh token)", err)
	}
	return refreshTokenNodeFromRecord(rec), nil
}

func (r *pgRepository) queryRefreshTokenNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`SELECT `+refreshTokenColumns+` FROM refresh_tokens WHERE project_id = $1`, r.projectID, filter, refreshQueryFields, ` ORDER BY created_at_ms ASC, id ASC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(refresh tokens)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		rec, err := scanRefreshToken(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(refresh tokens)", err)
		}
		out = append(out, refreshTokenNodeFromRecord(rec))
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(refresh tokens)", err)
	}
	return out, nil
}

func (r *pgRepository) queryPasswordResetNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`SELECT id, token_hash, user_id, expires_at_ms, created_at_ms, consumed_at_ms FROM password_reset_tokens WHERE project_id = $1`, r.projectID, filter, map[string]dbFieldSpec{
		dbPrfTokenHash: {col: "token_hash", kind: dbKindString},
		dbPrfUserID:    {col: "user_id", kind: dbKindString},
		dbPrfExpiresAt: {col: "expires_at_ms", kind: dbKindInt64},
		dbPrfCreatedAt: {col: "created_at_ms", kind: dbKindInt64},
	}, ` ORDER BY created_at_ms ASC, id ASC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(password reset tokens)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		rec, err := scanPasswordReset(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(password reset tokens)", err)
		}
		out = append(out, passwordResetNodeFromRecord(rec))
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(password reset tokens)", err)
	}
	return out, nil
}

func (r *pgRepository) getPasskeyNode(ctx context.Context, nodeID string) (*graph.Node, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+passkeyColumns+`
		  FROM passkeys
		 WHERE project_id = $1 AND id = $2
	`, r.projectID, nodeID)
	rec, err := scanPasskey(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetNode(passkey)", err)
	}
	return passkeyNodeFromRecord(rec), nil
}

func (r *pgRepository) queryPasskeyNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`SELECT `+passkeyColumns+` FROM passkeys WHERE project_id = $1`, r.projectID, filter, passkeyQueryFields, ` ORDER BY created_at_ms ASC, id ASC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(passkeys)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		rec, err := scanPasskey(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(passkeys)", err)
		}
		out = append(out, passkeyNodeFromRecord(rec))
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(passkeys)", err)
	}
	return out, nil
}

func (r *pgRepository) getAuditEventNode(ctx context.Context, nodeID string) (*graph.Node, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, event_type, actor, target, ip_address, user_agent, success, details::text, occurred_at_ms
		  FROM audit_events
		 WHERE project_id = $1 AND id = $2
	`, r.projectID, nodeID)
	node, err := scanAuditEventNode(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetNode(audit event)", err)
	}
	return node, nil
}

func (r *pgRepository) queryAuditEventNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`
		SELECT id, event_type, actor, target, ip_address, user_agent, success, details::text, occurred_at_ms
		  FROM audit_events
		 WHERE project_id = $1
	`, r.projectID, filter, auditQueryFields, ` ORDER BY occurred_at_ms DESC, id DESC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(audit events)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		node, err := scanAuditEventNode(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(audit events)", err)
		}
		out = append(out, node)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(audit events)", err)
	}
	return out, nil
}

func (r *pgRepository) getHelpRequestNode(ctx context.Context, nodeID string) (*graph.Node, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, email, reason, source_ip, user_agent, status, resolved_by, resolution_notes, resolved_at_ms, created_at_ms
		  FROM admin_help_requests
		 WHERE project_id = $1 AND id = $2
	`, r.projectID, nodeID)
	node, err := scanHelpRequestNode(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetNode(admin help request)", err)
	}
	return node, nil
}

func (r *pgRepository) queryHelpRequestNodes(ctx context.Context, filter map[string]any) ([]*graph.Node, error) {
	query, args := buildSelectQuery(`
		SELECT id, email, reason, source_ip, user_agent, status, resolved_by, resolution_notes, resolved_at_ms, created_at_ms
		  FROM admin_help_requests
		 WHERE project_id = $1
	`, r.projectID, filter, helpQueryFields, ` ORDER BY created_at_ms DESC, id DESC`)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapPgErr("QueryNodes(admin help requests)", err)
	}
	defer rows.Close()

	var out []*graph.Node
	for rows.Next() {
		node, err := scanHelpRequestNode(rows)
		if err != nil {
			return nil, wrapPgErr("QueryNodes(admin help requests)", err)
		}
		out = append(out, node)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("QueryNodes(admin help requests)", err)
	}
	return out, nil
}

func userNodeFromRecord(u *service.User) *graph.Node {
	if u == nil {
		return nil
	}
	return &graph.Node{
		NodeID: u.ID,
		TypeID: dbTypeUser,
		Payload: map[string]any{
			dbUfEmail:            u.Email,
			dbUfName:             u.Name,
			dbUfRole:             u.Role,
			dbUfAvatarURL:        u.AvatarURL,
			dbUfCreatedAt:        u.CreatedAt.UnixMilli(),
			dbUfUpdatedAt:        u.UpdatedAt.UnixMilli(),
			dbUfPasswordHash:     u.PasswordHash,
			dbUfTOTPRequired:     u.TotpRequired,
			dbUfFailedLoginCount: int64(u.FailedLoginCount),
			dbUfLockedUntil:      u.LockedUntil,
			dbUfStatus:           u.Status,
			dbUfRecoveryEmail:    u.RecoveryEmail,
			dbUfQuotaBytes:       u.QuotaBytes,
			dbUfLastLoginAt:      u.LastLoginAtMs,
			dbUfEmailVerified:    u.EmailVerified,
			dbUfEmailVerifiedAt:  u.EmailVerifiedAt,
		},
	}
}

func refreshTokenNodeFromRecord(rec *service.RefreshTokenRecord) *graph.Node {
	if rec == nil {
		return nil
	}
	return &graph.Node{
		NodeID: rec.NodeID,
		TypeID: dbTypeRefreshToken,
		Payload: map[string]any{
			dbRfTokenHash:  rec.TokenHash,
			dbRfUserID:     rec.UserID,
			dbRfDeviceInfo: rec.DeviceInfo,
			dbRfExpiresAt:  rec.ExpiresAt,
			dbRfCreatedAt:  rec.CreatedAt,
			dbRfDeviceName: rec.DeviceName,
			dbRfIPAddress:  rec.IPAddress,
			dbRfUserAgent:  rec.UserAgent,
			dbRfLastUsedAt: rec.LastUsedAt,
			dbRfConsumedAt: rec.ConsumedAtMs,
		},
	}
}

func passkeyNodeFromRecord(rec *service.PasskeyCredRecord) *graph.Node {
	if rec == nil {
		return nil
	}
	return &graph.Node{
		NodeID: rec.NodeID,
		TypeID: dbTypePasskey,
		Payload: map[string]any{
			dbPkfCredentialID: rec.CredentialID,
			dbPkfUserID:       rec.UserID,
			"4":               rec.SignCount,
			dbPkfDeviceName:   rec.DeviceName,
			dbPkfCreatedAt:    rec.CreatedAt,
			dbPkfLastUsedAt:   rec.LastUsedAt,
		},
	}
}

func passwordResetNodeFromRecord(rec *service.PasswordResetToken) *graph.Node {
	return &graph.Node{
		NodeID: rec.NodeID,
		TypeID: dbTypePasswordReset,
		Payload: map[string]any{
			dbPrfTokenHash: rec.TokenHash,
			dbPrfUserID:    rec.UserID,
			dbPrfExpiresAt: rec.ExpiresAt,
			dbPrfCreatedAt: rec.CreatedAt,
		},
	}
}

func scanGroupNode(row interface{ Scan(...any) error }) (*graph.Node, error) {
	var id, name, description, createdBy string
	var createdAt, updatedAt int64
	if err := row.Scan(&id, &name, &description, &createdBy, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	return &graph.Node{
		NodeID: id,
		TypeID: dbTypeWorkingGroup,
		Payload: map[string]any{
			dbGfName:        name,
			dbGfDescription: description,
			dbGfCreatedBy:   createdBy,
			dbGfCreatedAt:   createdAt,
			dbGfUpdatedAt:   updatedAt,
		},
	}, nil
}

func scanAuditEventNode(row interface{ Scan(...any) error }) (*graph.Node, error) {
	var id, eventType, actorUserID, targetUserID, ipAddress, userAgent, details string
	var success bool
	var createdAt int64
	if err := row.Scan(&id, &eventType, &actorUserID, &targetUserID, &ipAddress, &userAgent, &success, &details, &createdAt); err != nil {
		return nil, err
	}
	return &graph.Node{
		NodeID: id,
		TypeID: dbTypeAuditEvent,
		Payload: map[string]any{
			dbAfEventType:    eventType,
			dbAfActorUserID:  actorUserID,
			dbAfTargetUserID: targetUserID,
			dbAfIPAddress:    ipAddress,
			dbAfUserAgent:    userAgent,
			dbAfSuccess:      success,
			dbAfDetails:      details,
			dbAfCreatedAt:    createdAt,
		},
	}, nil
}

func scanHelpRequestNode(row interface{ Scan(...any) error }) (*graph.Node, error) {
	var id, email, reason, sourceIP, userAgent, status, resolvedBy, resolutionNotes string
	var resolvedAt, createdAt int64
	if err := row.Scan(&id, &email, &reason, &sourceIP, &userAgent, &status, &resolvedBy, &resolutionNotes, &resolvedAt, &createdAt); err != nil {
		return nil, err
	}
	return &graph.Node{
		NodeID: id,
		TypeID: dbTypeAdminHelpReq,
		Payload: map[string]any{
			dbHfEmail:           email,
			dbHfReason:          reason,
			dbHfSourceIP:        sourceIP,
			dbHfUserAgent:       userAgent,
			dbHfStatus:          status,
			dbHfResolvedBy:      resolvedBy,
			dbHfResolutionNotes: resolutionNotes,
			dbHfResolvedAt:      resolvedAt,
			dbHfCreatedAt:       createdAt,
		},
	}, nil
}

func buildSelectQuery(base string, projectID string, filter map[string]any, specs map[string]dbFieldSpec, suffix string) (string, []any) {
	var sb strings.Builder
	sb.WriteString(base)
	args := []any{projectID}
	idx := 2
	for fieldID, value := range filter {
		spec, ok := specs[fieldID]
		if !ok {
			continue
		}
		switch spec.kind {
		case dbKindString:
			s, ok := nullableString(value)
			if !ok {
				continue
			}
			if spec.caseInsensitive {
				// `col <> ''` keeps a PARTIAL index on that column usable.
				// users_project_email_partial_uidx (0028) is predicated on
				// `email <> ''`, and Postgres only uses a partial index when
				// the query provably implies its predicate — a
				// `lower(col) = lower($n)` clause against a parameter does
				// not. Without this the admin invite/create duplicate-address
				// check falls back to a full project scan. Semantically a
				// no-op: an empty needle never equals a non-empty value, and
				// callers filtering on "" want no rows either way.
				fmt.Fprintf(&sb, " AND %s <> '' AND lower(%s) = lower($%d)", spec.col, spec.col, idx)
			} else {
				fmt.Fprintf(&sb, " AND %s = $%d", spec.col, idx)
			}
			args = append(args, s)
			idx++
		case dbKindBool:
			b, ok := nullableBool(value)
			if !ok {
				continue
			}
			fmt.Fprintf(&sb, " AND %s = $%d", spec.col, idx)
			args = append(args, b)
			idx++
		case dbKindInt64:
			n, ok := nullableInt64(value)
			if !ok {
				continue
			}
			fmt.Fprintf(&sb, " AND %s = $%d", spec.col, idx)
			args = append(args, n)
			idx++
		}
	}
	sb.WriteString(suffix)
	return sb.String(), args
}

func updateBySpecs(ctx context.Context, tx pgx.Tx, projectID, table, nodeID string, fields map[string]any, specs map[string]dbFieldSpec) error {
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for fieldID, value := range fields {
		spec, ok := specs[fieldID]
		if !ok {
			continue
		}
		switch spec.kind {
		case dbKindString:
			s, ok := nullableString(value)
			if !ok {
				continue
			}
			sets = append(sets, fmt.Sprintf("%s = $%d", spec.col, idx))
			args = append(args, s)
		case dbKindBool:
			b, ok := nullableBool(value)
			if !ok {
				continue
			}
			sets = append(sets, fmt.Sprintf("%s = $%d", spec.col, idx))
			args = append(args, b)
		case dbKindInt64:
			n, ok := nullableInt64(value)
			if !ok {
				continue
			}
			sets = append(sets, fmt.Sprintf("%s = $%d", spec.col, idx))
			args = append(args, n)
		}
		idx++
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, projectID, nodeID)
	_, err := tx.Exec(
		ctx,
		fmt.Sprintf(`UPDATE %s SET %s WHERE project_id = $%d AND id = $%d`, table, strings.Join(sets, ", "), idx, idx+1),
		args...,
	)
	if err != nil {
		return wrapPgErr("ExecuteAtomic(update)", err)
	}
	return nil
}

// RegisterUserInTenant is a no-op on the postgres driver. Unlike
// tenant-shard-db's two-tier (global registry + per-tenant scope)
// model, the postgres driver runs a single SQL database; there is no
// separate registration step before tenant-scoped writes succeed.
func (r *pgRepository) RegisterUserInTenant(_ context.Context, _, _, _, _, _ string) error {
	return nil
}

var _ service.DB = (*pgRepository)(nil)
