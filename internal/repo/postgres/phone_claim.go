package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// ── Phone number claims ───────────────────────────────────────────────

// ClaimPhoneNumber locks the claims it may change before any user row: the
// number's and the ones the user holds (lockPhoneClaims), so a takeover, a
// release and a merge that touch the same accounts never wait on each other
// in a cycle. The claims table's primary key then decides
// who holds the number, and the user rows follow in id order.
func (r *pgRepository) ClaimPhoneNumber(ctx context.Context, userID, phoneNumber string, atMs, takeOverBeforeMs int64) (string, error) {
	if userID == "" || phoneNumber == "" {
		return "", errors.New("postgres: ClaimPhoneNumber: missing user id or phone number")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("ClaimPhoneNumber", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var known bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE project_id = $1 AND id = $2)`,
		r.projectID, userID).Scan(&known); err != nil {
		return "", wrapPgErr("ClaimPhoneNumber(user)", err)
	}
	if !known {
		return "", fmt.Errorf("postgres: ClaimPhoneNumber: %w", service.ErrNotFound)
	}
	if err := lockPhoneClaims(ctx, tx, r.projectID, "ClaimPhoneNumber", phoneNumber, userID); err != nil {
		return "", err
	}

	// An insert that loses to a concurrent claim of a free number reads the
	// winner's row, waiting on its transaction, and decides again.
	previous := ""
	for claimed := false; !claimed; {
		var holder string
		var claimedAt int64
		err := tx.QueryRow(ctx, `
			SELECT user_id, claimed_at_ms FROM phone_number_claims
			 WHERE project_id = $1 AND phone_number = $2 FOR UPDATE`,
			r.projectID, phoneNumber).Scan(&holder, &claimedAt)
		switch {
		case noRows(err):
			tag, err := tx.Exec(ctx, `
				INSERT INTO phone_number_claims (project_id, phone_number, user_id, claimed_at_ms)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (project_id, phone_number) DO NOTHING`,
				r.projectID, phoneNumber, userID, atMs)
			if err != nil {
				return "", wrapPgErr("ClaimPhoneNumber(claim)", err)
			}
			claimed = tag.RowsAffected() == 1
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
			previous, claimed = holder, true
		}
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM phone_number_claims
		 WHERE project_id = $1 AND user_id = $2 AND phone_number <> $3`,
		r.projectID, userID, phoneNumber); err != nil {
		return "", wrapPgErr("ClaimPhoneNumber(release previous number)", err)
	}

	setClaimer := func() error {
		_, err := tx.Exec(ctx, `
			UPDATE users
			   SET phone_number = $3, phone_verified = TRUE, phone_verified_at_ms = $4, updated_at_ms = $4
			 WHERE project_id = $1 AND id = $2`,
			r.projectID, userID, phoneNumber, atMs)
		return wrapPgErr("ClaimPhoneNumber(user)", err)
	}
	clearPrevious := func() error {
		_, err := tx.Exec(ctx, clearUserPhoneQuery+` AND phone_number = $4`, r.projectID, previous, atMs, phoneNumber)
		return wrapPgErr("ClaimPhoneNumber(previous holder)", err)
	}
	writes := []func() error{setClaimer}
	if previous != "" {
		writes = append(writes, clearPrevious)
		if previous < userID {
			writes[0], writes[1] = clearPrevious, setClaimer
		}
	}
	for _, write := range writes {
		if err := write(); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", wrapPgErr("ClaimPhoneNumber", err)
	}
	return previous, nil
}

// lockPhoneClaims locks the claim on phoneNumber (none when it is empty) and
// every claim the users hold, in number order. Every write that changes a
// claim and a user row takes its claims first, so two such writes never wait
// on each other in a cycle.
func lockPhoneClaims(ctx context.Context, tx pgx.Tx, projectID, op, phoneNumber string, userIDs ...string) error {
	rows, err := tx.Query(ctx, `
		SELECT phone_number FROM phone_number_claims
		 WHERE project_id = $1 AND (phone_number = $2 OR user_id = ANY($3))
		 ORDER BY phone_number FOR UPDATE`, projectID, phoneNumber, userIDs)
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
	// The claim before the user row, as ClaimPhoneNumber takes them.
	if _, err := tx.Exec(ctx, `DELETE FROM phone_number_claims WHERE project_id = $1 AND user_id = $2`,
		r.projectID, userID); err != nil {
		return wrapPgErr("ReleasePhoneNumber(claim)", err)
	}
	if _, err := tx.Exec(ctx, clearUserPhoneQuery+` AND phone_number <> ''`, r.projectID, userID, atMs); err != nil {
		return wrapPgErr("ReleasePhoneNumber(user)", err)
	}
	return wrapPgErr("ReleasePhoneNumber", tx.Commit(ctx))
}
