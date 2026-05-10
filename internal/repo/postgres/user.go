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
	last_login_at_ms,
	created_at_ms, updated_at_ms`

// scanUser reads one row in userColumns order into a *service.User.
func scanUser(row pgx.Row) (*service.User, error) {
	var (
		u                                                      service.User
		createdAtMs, updatedAtMs                               int64
		quotaBytes, lockedUntilMs                              int64
		failedLoginCount                                       int64
		emailVerifiedAtMs, idvVerifiedAtMs, lastLoginAtMs      int64
		emailVerified, idvVerified, totpRequired               bool
		id, email, name, role, avatar, status, recovery, phash string
	)
	if err := row.Scan(
		&id, &email, &name, &role, &avatar, &status, &recovery,
		&phash, &quotaBytes, &totpRequired,
		&failedLoginCount, &lockedUntilMs,
		&emailVerified, &emailVerifiedAtMs,
		&idvVerified, &idvVerifiedAtMs,
		&lastLoginAtMs,
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
	u.LastLoginAtMs = lastLoginAtMs
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
		WHERE tenant_id = $1 AND lower(email) = lower($2)
		LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.tenantID, email)
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
		WHERE tenant_id = $1 AND id = $2`
	row := r.pool.QueryRow(ctx, q, r.tenantID, userID)
	u, err := scanUser(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetUser", err)
	}
	return u, nil
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
			id, tenant_id, email, name, role, avatar_url, status,
			recovery_email, password_hash, quota_bytes, totp_required,
			failed_login_count, locked_until_ms,
			email_verified, email_verified_at_ms,
			idv_verified, idv_verified_at_ms,
			last_login_at_ms,
			created_at_ms, updated_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			$12, $13,
			$14, $15,
			$16, $17,
			$18,
			$19, $20
		)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.tenantID, u.Email, u.Name, role, u.AvatarURL, status,
		u.RecoveryEmail, u.PasswordHash, u.QuotaBytes, u.TotpRequired,
		int64(u.FailedLoginCount), u.LockedUntil,
		u.EmailVerified, u.EmailVerifiedAt,
		u.IDVVerified, u.IDVVerifiedAt,
		u.LastLoginAtMs,
		u.CreatedAt.UnixMilli(), u.UpdatedAt.UnixMilli(),
	)
	if err != nil {
		return "", wrapPgErr("CreateUser", err)
	}
	u.ID = id
	return id, nil
}

// userFieldColumns maps service-layer field names to (column, value-coercer).
// Unknown keys are dropped to match the EntDB driver's behaviour.
var userFieldColumns = map[string]struct {
	col  string
	kind string // "string" | "bool" | "int64"
}{
	"email":              {"email", "string"},
	"name":               {"name", "string"},
	"role":               {"role", "string"},
	"avatar_url":         {"avatar_url", "string"},
	"password_hash":      {"password_hash", "string"},
	"totp_required":      {"totp_required", "bool"},
	"failed_login_count": {"failed_login_count", "int64"},
	"locked_until":       {"locked_until_ms", "int64"},
	"status":             {"status", "string"},
	"recovery_email":     {"recovery_email", "string"},
	"quota_bytes":        {"quota_bytes", "int64"},
	"last_login_at":      {"last_login_at_ms", "int64"},
	"updated_at":         {"updated_at_ms", "int64"},
	"email_verified":     {"email_verified", "bool"},
	"email_verified_at":  {"email_verified_at_ms", "int64"},
	"idv_verified":       {"idv_verified", "bool"},
	"idv_verified_at":    {"idv_verified_at_ms", "int64"},
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
	args = append(args, r.tenantID, userID)
	q := fmt.Sprintf(
		`UPDATE users SET %s WHERE tenant_id = $%d AND id = $%d`,
		strings.Join(sets, ", "), idx, idx+1,
	)
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return wrapPgErr("UpdateUser", err)
	}
	return nil
}

// ── Lockout state ─────────────────────────────────────────────────

func (r *pgRepository) IncrementFailedLoginCount(ctx context.Context, userID string) (int32, error) {
	if userID == "" {
		return 0, errors.New("postgres: IncrementFailedLoginCount: missing user id")
	}
	const q = `
		UPDATE users
		   SET failed_login_count = failed_login_count + 1
		 WHERE tenant_id = $1 AND id = $2
		RETURNING failed_login_count`
	var newCount int64
	err := r.pool.QueryRow(ctx, q, r.tenantID, userID).Scan(&newCount)
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
		 WHERE tenant_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.tenantID, userID); err != nil {
		return wrapPgErr("ResetFailedLoginCount", err)
	}
	return nil
}

func (r *pgRepository) SetUserLockedUntil(ctx context.Context, userID string, lockedUntilMs int64) error {
	if userID == "" {
		return errors.New("postgres: SetUserLockedUntil: missing user id")
	}
	const q = `UPDATE users SET locked_until_ms = $3 WHERE tenant_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.tenantID, userID, lockedUntilMs); err != nil {
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
		 WHERE tenant_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.tenantID, userID, atMs); err != nil {
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
		 WHERE tenant_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.tenantID, userID, atMs); err != nil {
		return wrapPgErr("SetUserIDVVerified", err)
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
		 WHERE tenant_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.tenantID, userID, newEmail, atMs); err != nil {
		return wrapPgErr("UpdateUserEmail", err)
	}
	return nil
}
