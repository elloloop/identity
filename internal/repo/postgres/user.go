package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// userColumns is the canonical SELECT list for the users table. Listed
// once here so all readers (FindUserByEmail, GetUser) decode the same
// column ordering.
const userColumns = `
	id, email, name, role, avatar_url, status, recovery_email,
	password_hash, quota_bytes, totp_required,
	failed_login_count, locked_until_ms,
	email_verified, email_verified_at_ms,
	idv_verified, idv_verified_at_ms,
	phone_number, phone_verified, phone_verified_at_ms,
	date_of_birth_ms,
	last_login_at_ms,
	external_id,
	deletion_scheduled_at_ms,
	is_anonymous,
	created_at_ms, updated_at_ms`

// userColumnsPrefixed returns userColumns with every column qualified by
// the given table alias (e.g. "u"). Used by joins that select the user
// columns alongside another table so the shared column list — and its
// scanUser ordering — stays the single source of truth.
func userColumnsPrefixed(alias string) string {
	cols := strings.Split(userColumns, ",")
	for i, c := range cols {
		cols[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(cols, ", ")
}

// scanUser reads one row in userColumns order into a *service.User.
func scanUser(row pgx.Row) (*service.User, error) {
	var (
		u                                                      service.User
		createdAtMs, updatedAtMs                               int64
		quotaBytes, lockedUntilMs                              int64
		failedLoginCount                                       int64
		emailVerifiedAtMs, idvVerifiedAtMs, lastLoginAtMs      int64
		phoneVerifiedAtMs, dateOfBirthMs                       int64
		deletionScheduledAtMs                                  int64
		emailVerified, idvVerified, totpRequired               bool
		phoneVerified, isAnonymous                             bool
		id, email, name, role, avatar, status, recovery, phash string
		phoneNumber                                            string
		externalID                                             string
	)
	if err := row.Scan(
		&id, &email, &name, &role, &avatar, &status, &recovery,
		&phash, &quotaBytes, &totpRequired,
		&failedLoginCount, &lockedUntilMs,
		&emailVerified, &emailVerifiedAtMs,
		&idvVerified, &idvVerifiedAtMs,
		&phoneNumber, &phoneVerified, &phoneVerifiedAtMs,
		&dateOfBirthMs,
		&lastLoginAtMs,
		&externalID,
		&deletionScheduledAtMs,
		&isAnonymous,
		&createdAtMs, &updatedAtMs,
	); err != nil {
		return nil, err
	}
	u.ID = id
	u.Email = email
	u.Name = name
	u.Role = role
	u.AvatarURL = avatar
	u.Status = status
	u.RecoveryEmail = recovery
	u.PasswordHash = phash
	u.QuotaBytes = quotaBytes
	u.TotpRequired = totpRequired
	u.FailedLoginCount = int(failedLoginCount)
	u.LockedUntil = lockedUntilMs
	u.EmailVerified = emailVerified
	u.EmailVerifiedAt = emailVerifiedAtMs
	u.IDVVerified = idvVerified
	u.IDVVerifiedAt = idvVerifiedAtMs
	u.PhoneNumber = phoneNumber
	u.PhoneVerified = phoneVerified
	u.PhoneVerifiedAt = phoneVerifiedAtMs
	u.DateOfBirthMs = dateOfBirthMs
	u.LastLoginAtMs = lastLoginAtMs
	u.ExternalID = externalID
	u.DeletionScheduledAtMs = deletionScheduledAtMs
	u.IsAnonymous = isAnonymous
	u.CreatedAt = time.UnixMilli(createdAtMs)
	u.UpdatedAt = time.UnixMilli(updatedAtMs)
	return &u, nil
}

func (r *pgRepository) FindUserByEmail(ctx context.Context, email string) (*service.User, error) {
	if email == "" {
		return nil, nil
	}
	const q = `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1 AND lower(email) = lower($2)
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, email)
	u, err := scanUser(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindUserByEmail", err)
	}
	return u, nil
}

func (r *pgRepository) GetUser(ctx context.Context, userID string) (*service.User, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1 AND id = $2`
	row := r.pool.QueryRow(ctx, q, r.projectID, userID)
	u, err := scanUser(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetUser", err)
	}
	return u, nil
}

func (r *pgRepository) ListUsers(ctx context.Context, filter service.UserListFilter) ([]*service.User, error) {
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

	where, args := r.userFilterWhere(filter)
	args = append(args, limit, offset)
	q := fmt.Sprintf(`SELECT %s
		FROM users
		WHERE %s
		ORDER BY created_at_ms ASC, id ASC
		LIMIT $%d OFFSET $%d`,
		userColumns, strings.Join(where, " AND "), len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, wrapPgErr("ListUsers", err)
	}
	defer rows.Close()

	var out []*service.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, wrapPgErr("ListUsers", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListUsers", err)
	}
	return out, nil
}

// CountUsers returns the total number of users matching filter's equality
// predicates (Email/ExternalID), ignoring Offset/Limit. It backs the SCIM
// /Users totalResults so a page can report the true match count rather than
// the page size — and never silently truncates large projects at the page cap.
func (r *pgRepository) CountUsers(ctx context.Context, filter service.UserListFilter) (int, error) {
	where, args := r.userFilterWhere(filter)
	q := `SELECT count(*) FROM users WHERE ` + strings.Join(where, " AND ")
	var n int
	if err := r.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, wrapPgErr("CountUsers", err)
	}
	return n, nil
}

// userFilterWhere builds the project-scoped WHERE predicates and positional
// args shared by ListUsers and CountUsers, so the two never drift on which
// rows match. The mandatory project_id = $1 boundary is always first.
func (r *pgRepository) userFilterWhere(filter service.UserListFilter) (where []string, args []any) {
	where = []string{"project_id = $1"}
	args = []any{r.projectID}
	if filter.Email != "" {
		args = append(args, filter.Email)
		where = append(where, fmt.Sprintf("lower(email) = lower($%d)", len(args)))
	}
	if filter.ExternalID != "" {
		args = append(args, filter.ExternalID)
		where = append(where, fmt.Sprintf("external_id = $%d", len(args)))
	}
	return where, args
}

func (r *pgRepository) CreateUser(ctx context.Context, u *service.User) (string, error) {
	if u == nil {
		return "", errors.New("postgres: CreateUser: nil user")
	}
	now := nowMs()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.UnixMilli(now)
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	id := u.ID
	if id == "" {
		id = newID()
	}

	role := u.Role
	if role == "" {
		role = "member"
	}
	status := u.Status
	if status == "" {
		status = "active"
	}

	const q = `
		INSERT INTO users (
			id, project_id, email, name, role, avatar_url, status,
			recovery_email, password_hash, quota_bytes, totp_required,
			failed_login_count, locked_until_ms,
			email_verified, email_verified_at_ms,
			idv_verified, idv_verified_at_ms,
			phone_number, phone_verified, phone_verified_at_ms,
			date_of_birth_ms,
			last_login_at_ms,
			external_id,
			deletion_scheduled_at_ms,
			is_anonymous,
			created_at_ms, updated_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			$12, $13,
			$14, $15,
			$16, $17,
			$18, $19, $20,
			$21,
			$22,
			$23,
			$24,
			$25,
			$26, $27
		)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, u.Email, u.Name, role, u.AvatarURL, status,
		u.RecoveryEmail, u.PasswordHash, u.QuotaBytes, u.TotpRequired,
		int64(u.FailedLoginCount), u.LockedUntil,
		u.EmailVerified, u.EmailVerifiedAt,
		u.IDVVerified, u.IDVVerifiedAt,
		u.PhoneNumber, u.PhoneVerified, u.PhoneVerifiedAt,
		u.DateOfBirthMs,
		u.LastLoginAtMs,
		u.ExternalID,
		u.DeletionScheduledAtMs,
		u.IsAnonymous,
		u.CreatedAt.UnixMilli(), u.UpdatedAt.UnixMilli(),
	)
	if err != nil {
		return "", wrapPgErr("CreateUser", err)
	}
	u.ID = id
	return id, nil
}

// userFieldColumns maps service-layer field names to (column, value-coercer).
// Unknown keys are dropped to match the graph driver's behaviour.
var userFieldColumns = map[string]struct {
	col  string
	kind string // "string" | "bool" | "int64"
}{
	"email":                    {"email", "string"},
	"name":                     {"name", "string"},
	"role":                     {"role", "string"},
	"avatar_url":               {"avatar_url", "string"},
	"password_hash":            {"password_hash", "string"},
	"totp_required":            {"totp_required", "bool"},
	"failed_login_count":       {"failed_login_count", "int64"},
	"locked_until":             {"locked_until_ms", "int64"},
	"status":                   {"status", "string"},
	"recovery_email":           {"recovery_email", "string"},
	"quota_bytes":              {"quota_bytes", "int64"},
	"last_login_at":            {"last_login_at_ms", "int64"},
	"updated_at":               {"updated_at_ms", "int64"},
	"email_verified":           {"email_verified", "bool"},
	"email_verified_at":        {"email_verified_at_ms", "int64"},
	"idv_verified":             {"idv_verified", "bool"},
	"idv_verified_at":          {"idv_verified_at_ms", "int64"},
	"phone_number":             {"phone_number", "string"},
	"phone_verified":           {"phone_verified", "bool"},
	"phone_verified_at":        {"phone_verified_at_ms", "int64"},
	"date_of_birth_ms":         {"date_of_birth_ms", "int64"},
	"external_id":              {"external_id", "string"},
	"deletion_scheduled_at_ms": {"deletion_scheduled_at_ms", "int64"},
	"is_anonymous":             {"is_anonymous", "bool"},
}

func (r *pgRepository) UpdateUser(ctx context.Context, userID string, fields map[string]any) error {
	if userID == "" {
		return errors.New("postgres: UpdateUser: missing user id")
	}
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+2)
	idx := 1
	for k, v := range fields {
		spec, ok := userFieldColumns[k]
		if !ok {
			continue
		}
		var arg any
		switch spec.kind {
		case "string":
			s, ok := nullableString(v)
			if !ok {
				continue
			}
			arg = s
		case "bool":
			b, ok := nullableBool(v)
			if !ok {
				continue
			}
			arg = b
		case "int64":
			n, ok := nullableInt64(v)
			if !ok {
				continue
			}
			arg = n
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", spec.col, idx))
		args = append(args, arg)
		idx++
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, r.projectID, userID)
	q := fmt.Sprintf(
		`UPDATE users SET %s WHERE project_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1,
	)
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return wrapPgErr("UpdateUser", err)
	}
	return nil
}

// userDeleteNonFKTables lists the user-keyed tables whose user_id column
// has no FK to users(id) — they default to ” so they can legitimately
// hold rows with no owning user (pre-account email verification,
// anonymous QR sessions, pending invitations). DeleteUser removes their
// rows explicitly; the FK ON DELETE CASCADE on every other user-keyed
// table fires automatically when the users row is deleted.
var userDeleteNonFKTables = []string{
	"email_verification_tokens",
	"passkey_challenges",
	"qr_login_sessions",
	"user_invitations",
}

// DeleteUser physically removes the user and cascades all user-owned
// rows inside one transaction. The four non-FK tables are deleted
// explicitly; the DELETE FROM users then triggers ON DELETE CASCADE for
// refresh_tokens, sessions, password_reset_tokens, email_change_tokens,
// oauth_identities, passkeys, totp_secrets, recovery_codes,
// login_challenges, oauth_one_time_codes, identity_verifications,
// phone_verification_codes, and group_memberships.
// audit_events has no FK to users and is retained for accountability.
// The email-keyed email_login_codes / magic_link_tokens are out of scope
// (no user_id).
//
// It is idempotent: deleting a non-existent user touches zero rows and
// returns nil.
func (r *pgRepository) DeleteUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("DeleteUser", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, tbl := range userDeleteNonFKTables {
		if _, err := tx.Exec(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE project_id = $1 AND user_id = $2`, tbl),
			r.projectID, userID); err != nil {
			return wrapPgErr("DeleteUser("+tbl+")", err)
		}
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM users WHERE project_id = $1 AND id = $2`,
		r.projectID, userID); err != nil {
		return wrapPgErr("DeleteUser(users)", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("DeleteUser", err)
	}
	return nil
}

// ListUsersPendingDeletionBefore returns users whose self-service deletion
// grace window has elapsed (status = pending_deletion, deletion_scheduled_at_ms
// in (0, cutoffMs]), ordered by deletion_scheduled_at_ms then id, capped at
// limit. It backs the account-deletion sweeper. limit <= 0 is rejected so an
// uncapped scan can never lock the users table.
func (r *pgRepository) ListUsersPendingDeletionBefore(ctx context.Context, cutoffMs int64, limit int) ([]*service.User, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("postgres: ListUsersPendingDeletionBefore: limit must be > 0, got %d", limit)
	}
	q := `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1
		  AND status = $2
		  AND deletion_scheduled_at_ms > 0
		  AND deletion_scheduled_at_ms <= $3
		ORDER BY deletion_scheduled_at_ms ASC, id ASC
		LIMIT $4`
	rows, err := r.pool.Query(ctx, q, r.projectID, service.StatusPendingDeletion, cutoffMs, limit)
	if err != nil {
		return nil, wrapPgErr("ListUsersPendingDeletionBefore", err)
	}
	defer rows.Close()

	var out []*service.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, wrapPgErr("ListUsersPendingDeletionBefore", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListUsersPendingDeletionBefore", err)
	}
	return out, nil
}

// ── Lockout state ─────────────────────────────────────────────────

func (r *pgRepository) IncrementFailedLoginCount(ctx context.Context, userID string) (int32, error) {
	if userID == "" {
		return 0, errors.New("postgres: IncrementFailedLoginCount: missing user id")
	}
	const q = `
		UPDATE users
		   SET failed_login_count = failed_login_count + 1
		 WHERE project_id = $1 AND id = $2
		RETURNING failed_login_count`
	var newCount int64
	err := r.pool.QueryRow(ctx, q, r.projectID, userID).Scan(&newCount)
	if noRows(err) {
		return 0, errors.New("postgres: IncrementFailedLoginCount: user not found")
	}
	if err != nil {
		return 0, wrapPgErr("IncrementFailedLoginCount", err)
	}
	if newCount > int64(math.MaxInt32) {
		return 0, errors.New("postgres: IncrementFailedLoginCount: count overflow")
	}
	return int32(newCount), nil // #nosec G115 -- bounds checked above.
}

func (r *pgRepository) ResetFailedLoginCount(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("postgres: ResetFailedLoginCount: missing user id")
	}
	const q = `
		UPDATE users
		   SET failed_login_count = 0, locked_until_ms = 0
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapPgErr("ResetFailedLoginCount", err)
	}
	return nil
}

func (r *pgRepository) SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error {
	if userID == "" {
		return errors.New("postgres: SetUserLockedUntil: missing user id")
	}
	const q = `UPDATE users SET locked_until_ms = $3 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, lockedUntilMs); err != nil {
		return wrapPgErr("SetUserLockedUntil", err)
	}
	return nil
}

func (r *pgRepository) SetUserEmailVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("postgres: SetUserEmailVerified: missing user id")
	}
	const q = `
		UPDATE users
		   SET email_verified = TRUE,
		       email_verified_at_ms = $3,
		       updated_at_ms = $3
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapPgErr("SetUserEmailVerified", err)
	}
	return nil
}

func (r *pgRepository) SetUserIDVVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("postgres: SetUserIDVVerified: missing user id")
	}
	const q = `
		UPDATE users
		   SET idv_verified = TRUE,
		       idv_verified_at_ms = $3,
		       updated_at_ms = $3
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapPgErr("SetUserIDVVerified", err)
	}
	return nil
}

func (r *pgRepository) SetUserPhoneVerified(ctx context.Context, userID, phoneNumber string, atMs int64) error {
	if userID == "" {
		return errors.New("postgres: SetUserPhoneVerified: missing user id")
	}
	const q = `
		UPDATE users
		   SET phone_number = $3,
		       phone_verified = TRUE,
		       phone_verified_at_ms = $4,
		       updated_at_ms = $4
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, phoneNumber, atMs); err != nil {
		return wrapPgErr("SetUserPhoneVerified", err)
	}
	return nil
}

func (r *pgRepository) UpdateUserEmail(ctx context.Context, userID, newEmail string, atMs int64) error {
	if userID == "" {
		return errors.New("postgres: UpdateUserEmail: missing user id")
	}
	const q = `
		UPDATE users
		   SET email = $3,
		       email_verified = TRUE,
		       email_verified_at_ms = $4,
		       updated_at_ms = $4
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID, newEmail, atMs); err != nil {
		return wrapPgErr("UpdateUserEmail", err)
	}
	return nil
}
