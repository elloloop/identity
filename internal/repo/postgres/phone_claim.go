package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// ── Phone number claims ───────────────────────────────────────────────

// ClaimPhoneNumber writes the user first, which finds an unknown user
// before anything else and holds the user's row for the transaction, then
// lets the claims table's primary key decide who holds the number.
func (r *pgRepository) ClaimPhoneNumber(ctx context.Context, userID, phoneNumber string, atMs, takeOverBeforeMs int64) (string, error) {
	if userID == "" || phoneNumber == "" {
		return "", errors.New("postgres: ClaimPhoneNumber: missing user id or phone number")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("ClaimPhoneNumber", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE users
		   SET phone_number = $3, phone_verified = TRUE, phone_verified_at_ms = $4, updated_at_ms = $4
		 WHERE project_id = $1 AND id = $2`,
		r.projectID, userID, phoneNumber, atMs)
	if err != nil {
		return "", wrapPgErr("ClaimPhoneNumber(user)", err)
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("postgres: ClaimPhoneNumber: %w", service.ErrNotFound)
	}

	// A claim that a concurrent release deletes between the insert's
	// conflict and the locking read leaves the number free: insert again.
	previous := ""
	for claimed := false; !claimed; {
		tag, err := tx.Exec(ctx, `
			INSERT INTO phone_number_claims (project_id, phone_number, user_id, claimed_at_ms)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (project_id, phone_number) DO NOTHING`,
			r.projectID, phoneNumber, userID, atMs)
		if err != nil {
			return "", wrapPgErr("ClaimPhoneNumber(claim)", err)
		}
		if tag.RowsAffected() == 1 {
			break
		}
		var holder string
		var claimedAt int64
		err = tx.QueryRow(ctx, `
			SELECT user_id, claimed_at_ms FROM phone_number_claims
			 WHERE project_id = $1 AND phone_number = $2 FOR UPDATE`,
			r.projectID, phoneNumber).Scan(&holder, &claimedAt)
		switch {
		case noRows(err):
			continue
		case err != nil:
			return "", wrapPgErr("ClaimPhoneNumber(holder)", err)
		case holder == userID:
			claimed = true
		case claimedAt >= takeOverBeforeMs:
			return "", service.ErrPhoneNumberTaken
		default:
			if _, err := tx.Exec(ctx, `
				UPDATE phone_number_claims SET user_id = $3, claimed_at_ms = $4
				 WHERE project_id = $1 AND phone_number = $2`,
				r.projectID, phoneNumber, userID, atMs); err != nil {
				return "", wrapPgErr("ClaimPhoneNumber(move)", err)
			}
			if _, err := tx.Exec(ctx, clearUserPhoneQuery+` AND phone_number = $4`,
				r.projectID, holder, atMs, phoneNumber); err != nil {
				return "", wrapPgErr("ClaimPhoneNumber(previous holder)", err)
			}
			previous, claimed = holder, true
		}
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM phone_number_claims
		 WHERE project_id = $1 AND user_id = $2 AND phone_number <> $3`,
		r.projectID, userID, phoneNumber); err != nil {
		return "", wrapPgErr("ClaimPhoneNumber(release previous number)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", wrapPgErr("ClaimPhoneNumber", err)
	}
	return previous, nil
}

// lockPhoneClaims locks the claims the users hold, in number order. Every
// write that changes a claim and a user row takes the claims first, so two
// such writes never wait on each other in a cycle.
func lockPhoneClaims(ctx context.Context, tx pgx.Tx, projectID, op string, userIDs ...string) error {
	rows, err := tx.Query(ctx, `
		SELECT phone_number FROM phone_number_claims
		 WHERE project_id = $1 AND user_id = ANY($2)
		 ORDER BY phone_number FOR UPDATE`, projectID, userIDs)
	if err != nil {
		return wrapPgErr(op+"(lock phone claims)", err)
	}
	rows.Close()
	return wrapPgErr(op+"(lock phone claims)", rows.Err())
}

// clearUserPhoneQuery clears one user's phone number and verified state.
const clearUserPhoneQuery = `
	UPDATE users
	   SET phone_number = '', phone_verified = FALSE, phone_verified_at_ms = 0, updated_at_ms = $3
	 WHERE project_id = $1 AND id = $2`

func (r *pgRepository) ReleasePhoneNumber(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("postgres: ReleasePhoneNumber: missing user id")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("ReleasePhoneNumber", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, clearUserPhoneQuery+` AND phone_number <> ''`, r.projectID, userID, atMs); err != nil {
		return wrapPgErr("ReleasePhoneNumber(user)", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM phone_number_claims WHERE project_id = $1 AND user_id = $2`,
		r.projectID, userID); err != nil {
		return wrapPgErr("ReleasePhoneNumber(claim)", err)
	}
	return wrapPgErr("ReleasePhoneNumber", tx.Commit(ctx))
}
