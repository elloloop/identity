package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/elloloop/identity/internal/service"
)

// ── Recovery emails ───────────────────────────────────────────────────

// addressLockKey serialises every write that decides which account holds an
// address within a project: a user row taking it as its primary email, and
// an account taking it as a recovery email. The two live in different
// tables, so no unique index can hold "one account per address" across
// them; the lock does.
func addressLockKey(projectID, email string) string {
	return advisoryKey("account_address_holder", projectID, service.FoldEmail(email))
}

// holdAddress is what every write of a non-empty users.email does first,
// inside the write's transaction: it takes the address's lock and refuses
// with ErrAlreadyExists when the address is an account's recovery email.
func (r *pgRepository) holdAddress(ctx context.Context, tx pgx.Tx, op, email string) error {
	if err := lockXact(ctx, tx, op, addressLockKey(r.projectID, email)); err != nil {
		return err
	}
	var held bool
	const q = `SELECT EXISTS (SELECT 1 FROM user_recovery_emails WHERE project_id = $1 AND email_fold = $2)`
	if err := tx.QueryRow(ctx, q, r.projectID, service.FoldEmail(email)).Scan(&held); err != nil {
		return wrapPgErr(op, err)
	}
	if held {
		return fmt.Errorf("postgres: %s: address is a recovery email: %w", op, service.ErrAlreadyExists)
	}
	return nil
}

// execHoldingAddress runs one write of users.email. For an empty address it
// is a plain Exec. Otherwise it runs the write in a transaction that holds
// the address first (holdAddress).
func (r *pgRepository) execHoldingAddress(ctx context.Context, op, email, sql string, args ...any) (pgconn.CommandTag, error) {
	if email == "" {
		tag, err := r.pool.Exec(ctx, sql, args...)
		return tag, wrapPgErr(op, err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return pgconn.CommandTag{}, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := r.holdAddress(ctx, tx, op, email); err != nil {
		return pgconn.CommandTag{}, err
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return pgconn.CommandTag{}, wrapPgErr(op, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return pgconn.CommandTag{}, wrapPgErr(op, err)
	}
	return tag, nil
}

// UpsertRecoveryEmailCode replaces any existing code for the user so at most
// one is live per user, as UpsertPhoneVerificationCode does.
func (r *pgRepository) UpsertRecoveryEmailCode(ctx context.Context, c *service.RecoveryEmailCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: UpsertRecoveryEmailCode: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO recovery_email_codes (
			id, project_id, user_id, email, code_hash,
			expires_at_ms, created_at_ms, consumed_at_ms,
			attempt_count, max_attempts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (project_id, user_id) DO UPDATE SET
			email          = EXCLUDED.email,
			code_hash      = EXCLUDED.code_hash,
			expires_at_ms  = EXCLUDED.expires_at_ms,
			created_at_ms  = EXCLUDED.created_at_ms,
			consumed_at_ms = EXCLUDED.consumed_at_ms,
			attempt_count  = EXCLUDED.attempt_count,
			max_attempts   = EXCLUDED.max_attempts
		RETURNING id`
	var outID string
	err := r.pool.QueryRow(
		ctx, q,
		id, r.projectID, c.UserID, c.Email, c.CodeHash,
		c.ExpiresAt, c.CreatedAt, c.ConsumedAt,
		c.AttemptCount, c.MaxAttempts,
	).Scan(&outID)
	if err != nil {
		return "", wrapPgErr("UpsertRecoveryEmailCode", err)
	}
	c.NodeID = outID
	return outID, nil
}

const recoveryEmailCodeColumns = `id, user_id, email, code_hash, expires_at_ms,
	created_at_ms, consumed_at_ms, attempt_count, max_attempts`

func scanRecoveryEmailCode(row pgx.Row) (*service.RecoveryEmailCodeRecord, error) {
	var c service.RecoveryEmailCodeRecord
	if err := row.Scan(
		&c.NodeID, &c.UserID, &c.Email, &c.CodeHash, &c.ExpiresAt,
		&c.CreatedAt, &c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *pgRepository) FindRecoveryEmailCodeByUser(ctx context.Context, userID string) (*service.RecoveryEmailCodeRecord, error) {
	const q = `SELECT ` + recoveryEmailCodeColumns + `
		  FROM recovery_email_codes
		 WHERE project_id = $1 AND user_id = $2`
	c, err := scanRecoveryEmailCode(r.pool.QueryRow(ctx, q, r.projectID, userID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindRecoveryEmailCodeByUser", err)
	}
	return c, nil
}

func (r *pgRepository) IncrementRecoveryEmailCodeAttempts(ctx context.Context, nodeID string) error {
	const q = `
		UPDATE recovery_email_codes
		   SET attempt_count = attempt_count + 1
		 WHERE project_id = $1 AND id = $2`
	tag, err := r.pool.Exec(ctx, q, r.projectID, nodeID)
	if err != nil {
		return wrapPgErr("IncrementRecoveryEmailCodeAttempts", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("postgres: IncrementRecoveryEmailCodeAttempts: no such row")
	}
	return nil
}

// ConsumeRecoveryEmailCode atomically marks an unconsumed, unexpired code
// consumed via a single CAS UPDATE keyed by user_id. A replay, an expired
// code, or a missing code all hit zero rows and return
// ErrRecoveryEmailCodeInvalid.
func (r *pgRepository) ConsumeRecoveryEmailCode(ctx context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
	if userID == "" {
		return nil, service.ErrRecoveryEmailCodeInvalid
	}
	const q = `
		UPDATE recovery_email_codes
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND user_id = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		RETURNING ` + recoveryEmailCodeColumns
	c, err := scanRecoveryEmailCode(r.pool.QueryRow(ctx, q, r.projectID, userID, atMs))
	if noRows(err) {
		return nil, service.ErrRecoveryEmailCodeInvalid
	}
	if err != nil {
		return nil, wrapPgErr("ConsumeRecoveryEmailCode", err)
	}
	return c, nil
}

// AddRecoveryEmail takes the address's lock, then the account's row lock so
// two adds to one account count each other, and inserts only when the
// address is free in both tables and the account is under max.
func (r *pgRepository) AddRecoveryEmail(ctx context.Context, e *service.RecoveryEmail, max int) error {
	if e == nil || e.UserID == "" || e.Email == "" {
		return errors.New("postgres: AddRecoveryEmail: missing user id or email")
	}
	fold := service.FoldEmail(e.Email)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("AddRecoveryEmail", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockXact(ctx, tx, "AddRecoveryEmail", addressLockKey(r.projectID, e.Email)); err != nil {
		return err
	}
	var userExists bool
	if err := tx.QueryRow(ctx,
		`SELECT TRUE FROM users WHERE project_id = $1 AND id = $2 FOR UPDATE`,
		r.projectID, e.UserID).Scan(&userExists); err != nil {
		if noRows(err) {
			return fmt.Errorf("postgres: AddRecoveryEmail: %w", service.ErrNotFound)
		}
		return wrapPgErr("AddRecoveryEmail(user)", err)
	}
	var primary bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE project_id = $1 AND email <> '' AND email_fold = $2)`,
		r.projectID, fold).Scan(&primary); err != nil {
		return wrapPgErr("AddRecoveryEmail(primary)", err)
	}
	if primary {
		return service.ErrRecoveryEmailTaken
	}
	var holder string
	err = tx.QueryRow(ctx,
		`SELECT user_id FROM user_recovery_emails WHERE project_id = $1 AND email_fold = $2`,
		r.projectID, fold).Scan(&holder)
	switch {
	case err == nil && holder == e.UserID:
		return nil
	case err == nil:
		return service.ErrRecoveryEmailTaken
	case !noRows(err):
		return wrapPgErr("AddRecoveryEmail(holder)", err)
	}
	var held int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM user_recovery_emails WHERE project_id = $1 AND user_id = $2`,
		r.projectID, e.UserID).Scan(&held); err != nil {
		return wrapPgErr("AddRecoveryEmail(count)", err)
	}
	if held >= max {
		return service.ErrRecoveryEmailLimit
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO user_recovery_emails (id, project_id, user_id, email, verified_at_ms)
		 VALUES ($1, $2, $3, $4, $5)`,
		newID(), r.projectID, e.UserID, e.Email, e.VerifiedAt); err != nil {
		return wrapPgErr("AddRecoveryEmail", err)
	}
	return wrapPgErr("AddRecoveryEmail", tx.Commit(ctx))
}

func (r *pgRepository) ListRecoveryEmails(ctx context.Context, userID string) ([]*service.RecoveryEmail, error) {
	const q = `
		SELECT user_id, email, verified_at_ms, last_sign_in_at_ms
		  FROM user_recovery_emails
		 WHERE project_id = $1 AND user_id = $2
		 ORDER BY verified_at_ms ASC, id ASC`
	rows, err := r.pool.Query(ctx, q, r.projectID, userID)
	if err != nil {
		return nil, wrapPgErr("ListRecoveryEmails", err)
	}
	defer rows.Close()
	var out []*service.RecoveryEmail
	for rows.Next() {
		var e service.RecoveryEmail
		if err := rows.Scan(&e.UserID, &e.Email, &e.VerifiedAt, &e.LastSignInAt); err != nil {
			return nil, wrapPgErr("ListRecoveryEmails", err)
		}
		out = append(out, &e)
	}
	return out, wrapPgErr("ListRecoveryEmails", rows.Err())
}

func (r *pgRepository) RemoveRecoveryEmail(ctx context.Context, userID, email string) (bool, error) {
	const q = `
		DELETE FROM user_recovery_emails
		 WHERE project_id = $1 AND user_id = $2 AND email_fold = $3`
	tag, err := r.pool.Exec(ctx, q, r.projectID, userID, service.FoldEmail(email))
	if err != nil {
		return false, wrapPgErr("RemoveRecoveryEmail", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *pgRepository) FindRecoveryEmailHolder(ctx context.Context, email string) (*service.RecoveryEmail, error) {
	if email == "" {
		return nil, nil
	}
	const q = `
		SELECT user_id, email, verified_at_ms, last_sign_in_at_ms
		  FROM user_recovery_emails
		 WHERE project_id = $1 AND email_fold = $2`
	var e service.RecoveryEmail
	err := r.pool.QueryRow(ctx, q, r.projectID, service.FoldEmail(email)).Scan(&e.UserID, &e.Email, &e.VerifiedAt, &e.LastSignInAt)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindRecoveryEmailHolder", err)
	}
	return &e, nil
}

func (r *pgRepository) MarkRecoveryEmailSignIn(ctx context.Context, userID, email string, atMs, holdMs int64) error {
	const q = `
		UPDATE user_recovery_emails
		   SET last_sign_in_at_ms = CASE WHEN last_sign_in_at_ms <= $4::bigint - $5::bigint THEN $4::bigint ELSE last_sign_in_at_ms END
		 WHERE project_id = $1 AND user_id = $2 AND email_fold = $3`
	tag, err := r.pool.Exec(ctx, q, r.projectID, userID, service.FoldEmail(email), atMs, holdMs)
	if err != nil {
		return wrapPgErr("MarkRecoveryEmailSignIn", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: MarkRecoveryEmailSignIn: %w", service.ErrNotFound)
	}
	return nil
}

func (r *pgRepository) DeleteExpiredRecoveryEmailCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredRecoveryEmailCodes", "recovery_email_codes", beforeMs, limit)
}
