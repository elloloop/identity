package sqlite

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// userColumns is the canonical SELECT list for the users table, listed once
// so every reader decodes the same column ordering (mirrors the postgres
// driver). SQLite stores booleans as INTEGER 0/1, so scanUser reads the bool
// columns into int64 and converts — database/sql does not coerce int->bool.
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
	is_anonymous, anonymous_last_seen_ms,
	market, username,
	created_at_ms, updated_at_ms`

// userColumnsPrefixed qualifies every column with the given table alias so
// joins keep the shared column list — and scanUser ordering — authoritative.
func userColumnsPrefixed(alias string) string {
	cols := strings.Split(userColumns, ",")
	for i, c := range cols {
		cols[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(cols, ", ")
}

func scanUser(s scanner) (*service.User, error) {
	var (
		u                                                      service.User
		createdAtMs, updatedAtMs                               int64
		quotaBytes, lockedUntilMs                              int64
		failedLoginCount                                       int64
		emailVerifiedAtMs, idvVerifiedAtMs, lastLoginAtMs      int64
		phoneVerifiedAtMs, dateOfBirthMs                       int64
		deletionScheduledAtMs, anonymousLastSeenMs             int64
		emailVerified, idvVerified, totpRequired               int64
		phoneVerified, isAnonymous                             int64
		id, email, name, role, avatar, status, recovery, phash string
		phoneNumber                                            string
		externalID                                             string
		market, username                                       string
	)
	if err := s.Scan(
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
		&isAnonymous, &anonymousLastSeenMs,
		&market, &username,
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
	u.TotpRequired = totpRequired != 0
	u.FailedLoginCount = int(failedLoginCount)
	u.LockedUntil = lockedUntilMs
	u.EmailVerified = emailVerified != 0
	u.EmailVerifiedAt = emailVerifiedAtMs
	u.IDVVerified = idvVerified != 0
	u.IDVVerifiedAt = idvVerifiedAtMs
	u.PhoneNumber = phoneNumber
	u.PhoneVerified = phoneVerified != 0
	u.PhoneVerifiedAt = phoneVerifiedAtMs
	u.DateOfBirthMs = dateOfBirthMs
	u.LastLoginAtMs = lastLoginAtMs
	u.ExternalID = externalID
	u.DeletionScheduledAtMs = deletionScheduledAtMs
	u.IsAnonymous = isAnonymous != 0
	u.AnonymousLastSeenMs = anonymousLastSeenMs
	u.Market = market
	u.Username = username
	u.CreatedAt = time.UnixMilli(createdAtMs)
	u.UpdatedAt = time.UnixMilli(updatedAtMs)
	return &u, nil
}

func (r *sqliteRepository) FindUserByEmail(ctx context.Context, email string) (*service.User, error) {
	if email == "" {
		return nil, nil
	}
	const q = `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1 AND email <> '' AND lower(email) = lower($2)
		LIMIT 1`
	u, err := scanUser(r.db.QueryRow(ctx, q, r.projectID, email))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindUserByEmail", err)
	}
	return u, nil
}

func (r *sqliteRepository) GetUser(ctx context.Context, userID string) (*service.User, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1 AND id = $2`
	u, err := scanUser(r.db.QueryRow(ctx, q, r.projectID, userID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetUser", err)
	}
	return u, nil
}

// FindUserByUsername resolves a managed child account by its project-unique
// username. The username <> ” predicate keeps the partial unique index
// (0017) usable, mirroring the email lookup. Mirrors the postgres driver.
func (r *sqliteRepository) FindUserByUsername(ctx context.Context, username string) (*service.User, error) {
	if username == "" {
		return nil, nil
	}
	const q = `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1 AND username <> '' AND username = $2
		LIMIT 1`
	u, err := scanUser(r.db.QueryRow(ctx, q, r.projectID, username))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindUserByUsername", err)
	}
	return u, nil
}

func (r *sqliteRepository) ListUsers(ctx context.Context, filter service.UserListFilter) ([]*service.User, error) {
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

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, wrapErr("ListUsers", err)
	}
	defer rows.Close()

	var out []*service.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, wrapErr("ListUsers", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ListUsers", err)
	}
	return out, nil
}

// CountUsers returns the total number of users matching filter's equality
// predicates (Email/ExternalID), ignoring Offset/Limit. It backs the SCIM
// /Users totalResults so a page reports the true match count rather than the
// page size — and never silently truncates large projects at the page cap.
// Mirrors the postgres driver.
func (r *sqliteRepository) CountUsers(ctx context.Context, filter service.UserListFilter) (int, error) {
	where, args := r.userFilterWhere(filter)
	q := `SELECT count(*) FROM users WHERE ` + strings.Join(where, " AND ")
	var n int
	if err := r.db.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, wrapErr("CountUsers", err)
	}
	return n, nil
}

// userFilterWhere builds the project-scoped WHERE predicates and positional
// args shared by ListUsers and CountUsers, so the two never drift on which
// rows match. The mandatory project_id = $1 boundary is always first.
func (r *sqliteRepository) userFilterWhere(filter service.UserListFilter) (where []string, args []any) {
	where = []string{"project_id = $1"}
	args = []any{r.projectID}
	if filter.Email != "" {
		args = append(args, filter.Email)
		// email <> '' keeps the partial unique index (0028/0013) usable;
		// without it the planner cannot prove the index covers this filter.
		where = append(where, fmt.Sprintf("email <> '' AND lower(email) = lower($%d)", len(args)))
	}
	if filter.ExternalID != "" {
		args = append(args, filter.ExternalID)
		where = append(where, fmt.Sprintf("external_id = $%d", len(args)))
	}
	if !filter.IncludeAnonymous {
		// Anonymous accounts have no email, so every consumer that presents
		// users by address would render them blank. Excluded here rather
		// than by the caller so ListUsers and CountUsers agree.
		where = append(where, "NOT is_anonymous")
	}
	return where, args
}

// insertUserQuery is the canonical users INSERT, shared by CreateUser and the
// transactional CreateManagedChildAccount so the two never drift on column
// order. Mirrors the postgres driver.
const insertUserQuery = `
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
		is_anonymous, anonymous_last_seen_ms,
		market, username,
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
		$25, $26,
		$27, $28,
		$29, $30
	)`

// insertUserArgs renders the bind args for insertUserQuery in column order.
// projectID is the shard; id/role/status carry the caller-defaulted values.
func insertUserArgs(projectID, id, role, status string, u *service.User) []any {
	return []any{
		id, projectID, u.Email, u.Name, role, u.AvatarURL, status,
		u.RecoveryEmail, u.PasswordHash, u.QuotaBytes, u.TotpRequired,
		int64(u.FailedLoginCount), u.LockedUntil,
		u.EmailVerified, u.EmailVerifiedAt,
		u.IDVVerified, u.IDVVerifiedAt,
		u.PhoneNumber, u.PhoneVerified, u.PhoneVerifiedAt,
		u.DateOfBirthMs,
		u.LastLoginAtMs,
		u.ExternalID,
		u.DeletionScheduledAtMs,
		u.IsAnonymous, u.AnonymousLastSeenMs,
		u.Market, u.Username,
		u.CreatedAt.UnixMilli(), u.UpdatedAt.UnixMilli(),
	}
}

// defaultNewUserFields fills the zero-value fields of a user about to be
// inserted (timestamps, id, role, status), shared by CreateUser and
// CreateManagedChildAccount.
func defaultNewUserFields(u *service.User) (id, role, status string) {
	now := nowMs()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.UnixMilli(now)
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	id = u.ID
	if id == "" {
		id = newID()
	}
	role = u.Role
	if role == "" {
		role = "member"
	}
	status = u.Status
	if status == "" {
		status = "active"
	}
	return id, role, status
}

func (r *sqliteRepository) CreateUser(ctx context.Context, u *service.User) (string, error) {
	if u == nil {
		return "", errors.New("sqlite: CreateUser: nil user")
	}
	id, role, status := defaultNewUserFields(u)
	_, err := r.db.Exec(ctx, insertUserQuery, insertUserArgs(r.projectID, id, role, status, u)...)
	if err != nil {
		return "", wrapErr("CreateUser", err)
	}
	u.ID = id
	return id, nil
}

// userFieldColumns maps service-layer field names to (column, value-coercer).
// Unknown keys are dropped to match the other drivers' behaviour.
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
	"anonymous_last_seen_ms":   {"anonymous_last_seen_ms", "int64"},
	"market":                   {"market", "string"},
	"username":                 {"username", "string"},
}

func (r *sqliteRepository) UpdateUser(ctx context.Context, userID string, fields map[string]any) error {
	if userID == "" {
		return errors.New("sqlite: UpdateUser: missing user id")
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
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return wrapErr("UpdateUser", err)
	}
	return nil
}

// userDeleteNonFKTables lists the user-keyed tables whose user_id column has
// no FK to users(id) — they default to ” so they can legitimately hold rows
// with no owning user. DeleteUser removes their rows explicitly; the FK ON
// DELETE CASCADE on every other user-keyed table fires automatically when the
// users row is deleted (foreign_keys is enabled per-connection).
var userDeleteNonFKTables = []string{
	"email_verification_tokens",
	"passkey_challenges",
	"qr_login_sessions",
	"user_invitations",
}

// SetDateOfBirthOnce sets the date of birth only while the row still has none,
// applying the optional status in the same statement. Reports whether this
// call was the one that set it.
// GetUsersByIDs fetches many users in one query, ordered by id. Unknown ids
// are absent from the result rather than an error. SQLite has no array
// parameter, so the id list becomes placeholders.
func (r *sqliteRepository) GetUsersByIDs(ctx context.Context, ids []string) ([]*service.User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, r.projectID)
	placeholders := make([]string, 0, len(ids))
	for i, id := range ids {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+2))
		args = append(args, id)
	}
	q := `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1 AND id IN (` + strings.Join(placeholders, ", ") + `)
		ORDER BY id ASC`
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, wrapErr("GetUsersByIDs", err)
	}
	defer rows.Close()

	out := make([]*service.User, 0, len(ids))
	for rows.Next() {
		u, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, wrapErr("GetUsersByIDs", scanErr)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("GetUsersByIDs", err)
	}
	return out, nil
}

func (r *sqliteRepository) SetDateOfBirthOnce(
	ctx context.Context, userID string, dobMs int64, status string, nowMs int64,
) (bool, error) {
	if userID == "" {
		return false, errors.New("sqlite: SetDateOfBirthOnce: missing user id")
	}
	const q = `
		UPDATE users
		   SET date_of_birth_ms = $3,
		       status          = CASE WHEN $4 = '' THEN status ELSE $4 END,
		       updated_at_ms   = $5
		 WHERE project_id = $1 AND id = $2 AND date_of_birth_ms = 0`
	res, err := r.db.Exec(ctx, q, r.projectID, userID, dobMs, status, nowMs)
	if err != nil {
		return false, wrapErr("SetDateOfBirthOnce", err)
	}
	return res.RowsAffected() > 0, nil
}

func (r *sqliteRepository) DeleteUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	t, err := r.db.Begin(ctx)
	if err != nil {
		return wrapErr("DeleteUser", err)
	}
	defer func() { _ = t.Rollback(ctx) }()

	for _, tbl := range userDeleteNonFKTables {
		if _, err := t.Exec(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE project_id = $1 AND user_id = $2`, tbl),
			r.projectID, userID); err != nil {
			return wrapErr("DeleteUser("+tbl+")", err)
		}
	}
	if _, err := t.Exec(ctx,
		`DELETE FROM users WHERE project_id = $1 AND id = $2`,
		r.projectID, userID); err != nil {
		return wrapErr("DeleteUser(users)", err)
	}
	if err := t.Commit(ctx); err != nil {
		return wrapErr("DeleteUser", err)
	}
	return nil
}

// ListUsersPendingDeletionBefore returns users whose self-service deletion
// grace window has elapsed (status = pending_deletion, deletion_scheduled_at_ms
// in (0, cutoffMs]), ordered by deletion_scheduled_at_ms then id, capped at
// limit. It backs the account-deletion sweeper. limit <= 0 is rejected so an
// uncapped scan can never lock the users table. Mirrors the postgres driver.
func (r *sqliteRepository) ListUsersPendingDeletionBefore(ctx context.Context, cutoffMs int64, limit int) ([]*service.User, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("sqlite: ListUsersPendingDeletionBefore: limit must be > 0, got %d", limit)
	}
	q := `SELECT ` + userColumns + `
		FROM users
		WHERE project_id = $1
		  AND status = $2
		  AND deletion_scheduled_at_ms > 0
		  AND deletion_scheduled_at_ms <= $3
		ORDER BY deletion_scheduled_at_ms ASC, id ASC
		LIMIT $4`
	rows, err := r.db.Query(ctx, q, r.projectID, service.StatusPendingDeletion, cutoffMs, limit)
	if err != nil {
		return nil, wrapErr("ListUsersPendingDeletionBefore", err)
	}
	defer rows.Close()

	var out []*service.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, wrapErr("ListUsersPendingDeletionBefore", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ListUsersPendingDeletionBefore", err)
	}
	return out, nil
}

// ── Lockout state ─────────────────────────────────────────────────

func (r *sqliteRepository) IncrementFailedLoginCount(ctx context.Context, userID string) (int32, error) {
	if userID == "" {
		return 0, errors.New("sqlite: IncrementFailedLoginCount: missing user id")
	}
	const q = `
		UPDATE users
		   SET failed_login_count = failed_login_count + 1
		 WHERE project_id = $1 AND id = $2
		RETURNING failed_login_count`
	var newCount int64
	err := r.db.QueryRow(ctx, q, r.projectID, userID).Scan(&newCount)
	if noRows(err) {
		return 0, errors.New("sqlite: IncrementFailedLoginCount: user not found")
	}
	if err != nil {
		return 0, wrapErr("IncrementFailedLoginCount", err)
	}
	if newCount > int64(math.MaxInt32) {
		return 0, errors.New("sqlite: IncrementFailedLoginCount: count overflow")
	}
	return int32(newCount), nil // #nosec G115 -- bounds checked above.
}

func (r *sqliteRepository) ResetFailedLoginCount(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("sqlite: ResetFailedLoginCount: missing user id")
	}
	const q = `
		UPDATE users
		   SET failed_login_count = 0, locked_until_ms = 0
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapErr("ResetFailedLoginCount", err)
	}
	return nil
}

func (r *sqliteRepository) SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error {
	if userID == "" {
		return errors.New("sqlite: SetUserLockedUntil: missing user id")
	}
	const q = `UPDATE users SET locked_until_ms = $3 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID, lockedUntilMs); err != nil {
		return wrapErr("SetUserLockedUntil", err)
	}
	return nil
}

func (r *sqliteRepository) SetUserEmailVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("sqlite: SetUserEmailVerified: missing user id")
	}
	const q = `
		UPDATE users
		   SET email_verified = 1, email_verified_at_ms = $3, updated_at_ms = $3
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapErr("SetUserEmailVerified", err)
	}
	return nil
}

func (r *sqliteRepository) SetUserIDVVerified(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("sqlite: SetUserIDVVerified: missing user id")
	}
	const q = `
		UPDATE users
		   SET idv_verified = 1, idv_verified_at_ms = $3, updated_at_ms = $3
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID, atMs); err != nil {
		return wrapErr("SetUserIDVVerified", err)
	}
	return nil
}

func (r *sqliteRepository) SetUserPhoneVerified(ctx context.Context, userID, phoneNumber string, atMs int64) error {
	if userID == "" {
		return errors.New("sqlite: SetUserPhoneVerified: missing user id")
	}
	const q = `
		UPDATE users
		   SET phone_number = $3, phone_verified = 1, phone_verified_at_ms = $4, updated_at_ms = $4
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID, phoneNumber, atMs); err != nil {
		return wrapErr("SetUserPhoneVerified", err)
	}
	return nil
}

func (r *sqliteRepository) UpdateUserEmail(ctx context.Context, userID, newEmail string, atMs int64) error {
	if userID == "" {
		return errors.New("sqlite: UpdateUserEmail: missing user id")
	}
	const q = `
		UPDATE users
		   SET email = $3, email_verified = 1, email_verified_at_ms = $4, updated_at_ms = $4
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID, newEmail, atMs); err != nil {
		return wrapErr("UpdateUserEmail", err)
	}
	return nil
}
