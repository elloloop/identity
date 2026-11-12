package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// ── Recovery emails ───────────────────────────────────────────────────

// execHoldingAddress runs one write of users.email. For an empty address it
// is a plain Exec. Otherwise the write and the check that the address is no
// account's recovery email share a transaction, write first: the write takes
// SQLite's single writer lock, so no recovery email can be added between the
// check and the commit, and a transaction that starts by writing never has
// to upgrade a read snapshot another writer has made stale.
func (r *sqliteRepository) execHoldingAddress(ctx context.Context, op, email, sql string, args ...any) (commandTag, error) {
	if email == "" {
		tag, err := r.db.Exec(ctx, sql, args...)
		return tag, wrapErr(op, err)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return commandTag{}, wrapErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return commandTag{}, wrapErr(op, err)
	}
	var held bool
	const q = `SELECT EXISTS (SELECT 1 FROM user_recovery_emails WHERE project_id = $1 AND lower(email) = $2)`
	if err := tx.QueryRow(ctx, q, r.projectID, service.FoldEmail(email)).Scan(&held); err != nil {
		return commandTag{}, wrapErr(op, err)
	}
	if held {
		return commandTag{}, fmt.Errorf("sqlite: %s: address is a recovery email: %w", op, service.ErrAlreadyExists)
	}
	if err := tx.Commit(ctx); err != nil {
		return commandTag{}, wrapErr(op, err)
	}
	return tag, nil
}

// UpsertRecoveryEmailCode replaces any existing code for the user so at most
// one is live per user, as UpsertPhoneVerificationCode does.
func (r *sqliteRepository) UpsertRecoveryEmailCode(ctx context.Context, c *service.RecoveryEmailCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: UpsertRecoveryEmailCode: nil record")
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
			email          = excluded.email,
			code_hash      = excluded.code_hash,
			expires_at_ms  = excluded.expires_at_ms,
			created_at_ms  = excluded.created_at_ms,
			consumed_at_ms = excluded.consumed_at_ms,
			attempt_count  = excluded.attempt_count,
			max_attempts   = excluded.max_attempts
		RETURNING id`
	var outID string
	err := r.db.QueryRow(
		ctx, q,
		id, r.projectID, c.UserID, c.Email, c.CodeHash,
		c.ExpiresAt, c.CreatedAt, c.ConsumedAt,
		c.AttemptCount, c.MaxAttempts,
	).Scan(&outID)
	if err != nil {
		return "", wrapErr("UpsertRecoveryEmailCode", err)
	}
	c.NodeID = outID
	return outID, nil
}

const recoveryEmailCodeColumns = `id, user_id, email, code_hash, expires_at_ms,
	created_at_ms, consumed_at_ms, attempt_count, max_attempts`

func scanRecoveryEmailCode(row scanner) (*service.RecoveryEmailCodeRecord, error) {
	var c service.RecoveryEmailCodeRecord
	if err := row.Scan(
		&c.NodeID, &c.UserID, &c.Email, &c.CodeHash, &c.ExpiresAt,
		&c.CreatedAt, &c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *sqliteRepository) FindRecoveryEmailCodeByUser(ctx context.Context, userID string) (*service.RecoveryEmailCodeRecord, error) {
	const q = `SELECT ` + recoveryEmailCodeColumns + `
		  FROM recovery_email_codes
		 WHERE project_id = $1 AND user_id = $2`
	c, err := scanRecoveryEmailCode(r.db.QueryRow(ctx, q, r.projectID, userID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindRecoveryEmailCodeByUser", err)
	}
	return c, nil
}

func (r *sqliteRepository) IncrementRecoveryEmailCodeAttempts(ctx context.Context, nodeID string) error {
	const q = `
		UPDATE recovery_email_codes
		   SET attempt_count = attempt_count + 1
		 WHERE project_id = $1 AND id = $2`
	tag, err := r.db.Exec(ctx, q, r.projectID, nodeID)
	if err != nil {
		return wrapErr("IncrementRecoveryEmailCodeAttempts", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("sqlite: IncrementRecoveryEmailCodeAttempts: no such row")
	}
	return nil
}

// ConsumeRecoveryEmailCode atomically marks an unconsumed, unexpired code
// consumed via a single CAS UPDATE keyed by user_id. A replay, an expired
// code, or a missing code all hit zero rows and return
// ErrRecoveryEmailCodeInvalid.
func (r *sqliteRepository) ConsumeRecoveryEmailCode(ctx context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
	if userID == "" {
		return nil, service.ErrRecoveryEmailCodeInvalid
	}
	const q = `
		UPDATE recovery_email_codes
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND user_id = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		RETURNING ` + recoveryEmailCodeColumns
	c, err := scanRecoveryEmailCode(r.db.QueryRow(ctx, q, r.projectID, userID, atMs))
	if noRows(err) {
		return nil, service.ErrRecoveryEmailCodeInvalid
	}
	if err != nil {
		return nil, wrapErr("ConsumeRecoveryEmailCode", err)
	}
	return c, nil
}

// AddRecoveryEmail inserts first, which takes SQLite's single writer lock
// and lets the unique index answer for another account's recovery email,
// then checks the primary emails and the account's count inside the same
// transaction and rolls back on a refusal.
func (r *sqliteRepository) AddRecoveryEmail(ctx context.Context, e *service.RecoveryEmail, max int) error {
	if e == nil || e.UserID == "" || e.Email == "" {
		return errors.New("sqlite: AddRecoveryEmail: missing user id or email")
	}
	fold := service.FoldEmail(e.Email)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return wrapErr("AddRecoveryEmail", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`INSERT INTO user_recovery_emails (id, project_id, user_id, email, verified_at_ms)
		 SELECT $1, $2, $3, $4, $5
		  WHERE EXISTS (SELECT 1 FROM users WHERE project_id = $2 AND id = $3)
		 ON CONFLICT (project_id, lower(email)) DO NOTHING`,
		newID(), r.projectID, e.UserID, e.Email, e.VerifiedAt)
	if err != nil {
		return wrapErr("AddRecoveryEmail", err)
	}
	if tag.RowsAffected() == 0 {
		var holder string
		err := tx.QueryRow(ctx,
			`SELECT user_id FROM user_recovery_emails WHERE project_id = $1 AND lower(email) = $2`,
			r.projectID, fold).Scan(&holder)
		switch {
		case noRows(err):
			return fmt.Errorf("sqlite: AddRecoveryEmail: %w", service.ErrNotFound)
		case err != nil:
			return wrapErr("AddRecoveryEmail(holder)", err)
		case holder == e.UserID:
			return nil
		default:
			return service.ErrRecoveryEmailTaken
		}
	}
	var primary bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE project_id = $1 AND email <> '' AND lower(email) = $2)`,
		r.projectID, fold).Scan(&primary); err != nil {
		return wrapErr("AddRecoveryEmail(primary)", err)
	}
	if primary {
		return service.ErrRecoveryEmailTaken
	}
	var held int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM user_recovery_emails WHERE project_id = $1 AND user_id = $2`,
		r.projectID, e.UserID).Scan(&held); err != nil {
		return wrapErr("AddRecoveryEmail(count)", err)
	}
	if held > max {
		return service.ErrRecoveryEmailLimit
	}
	return wrapErr("AddRecoveryEmail", tx.Commit(ctx))
}

func (r *sqliteRepository) ListRecoveryEmails(ctx context.Context, userID string) ([]*service.RecoveryEmail, error) {
	const q = `
		SELECT user_id, email, verified_at_ms, last_sign_in_at_ms
		  FROM user_recovery_emails
		 WHERE project_id = $1 AND user_id = $2
		 ORDER BY verified_at_ms ASC, id ASC`
	rows, err := r.db.Query(ctx, q, r.projectID, userID)
	if err != nil {
		return nil, wrapErr("ListRecoveryEmails", err)
	}
	defer rows.Close()
	var out []*service.RecoveryEmail
	for rows.Next() {
		var e service.RecoveryEmail
		if err := rows.Scan(&e.UserID, &e.Email, &e.VerifiedAt, &e.LastSignInAt); err != nil {
			return nil, wrapErr("ListRecoveryEmails", err)
		}
		out = append(out, &e)
	}
	return out, wrapErr("ListRecoveryEmails", rows.Err())
}

func (r *sqliteRepository) RemoveRecoveryEmail(ctx context.Context, userID, email string) (bool, error) {
	const q = `
		DELETE FROM user_recovery_emails
		 WHERE project_id = $1 AND user_id = $2 AND lower(email) = $3`
	tag, err := r.db.Exec(ctx, q, r.projectID, userID, service.FoldEmail(email))
	if err != nil {
		return false, wrapErr("RemoveRecoveryEmail", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *sqliteRepository) FindRecoveryEmailHolder(ctx context.Context, email string) (*service.RecoveryEmail, error) {
	if email == "" {
		return nil, nil
	}
	const q = `
		SELECT user_id, email, verified_at_ms, last_sign_in_at_ms
		  FROM user_recovery_emails
		 WHERE project_id = $1 AND lower(email) = $2`
	var e service.RecoveryEmail
	err := r.db.QueryRow(ctx, q, r.projectID, service.FoldEmail(email)).Scan(&e.UserID, &e.Email, &e.VerifiedAt, &e.LastSignInAt)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindRecoveryEmailHolder", err)
	}
	return &e, nil
}

func (r *sqliteRepository) MarkRecoveryEmailSignIn(ctx context.Context, userID, email string, atMs int64) error {
	const q = `
		UPDATE user_recovery_emails
		   SET last_sign_in_at_ms = $4
		 WHERE project_id = $1 AND user_id = $2 AND lower(email) = $3`
	tag, err := r.db.Exec(ctx, q, r.projectID, userID, service.FoldEmail(email), atMs)
	if err != nil {
		return wrapErr("MarkRecoveryEmailSignIn", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("sqlite: MarkRecoveryEmailSignIn: %w", service.ErrNotFound)
	}
	return nil
}

func (r *sqliteRepository) DeleteExpiredRecoveryEmailCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredRecoveryEmailCodes", "recovery_email_codes", beforeMs, limit)
}
