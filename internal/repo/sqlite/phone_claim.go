package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// ── Phone number claims ───────────────────────────────────────────────

// ClaimPhoneNumber writes the user first, which finds an unknown user
// before anything else and takes SQLite's single writer lock for the
// transaction, then lets the claims table's primary key decide who holds
// the number.
func (r *sqliteRepository) ClaimPhoneNumber(ctx context.Context, userID, phoneNumber string, atMs, takeOverBeforeMs int64) (string, error) {
	if userID == "" || phoneNumber == "" {
		return "", errors.New("sqlite: ClaimPhoneNumber: missing user id or phone number")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", wrapErr("ClaimPhoneNumber", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE users
		   SET phone_number = $3, phone_verified = 1, phone_verified_at_ms = $4, updated_at_ms = $4
		 WHERE project_id = $1 AND id = $2`,
		r.projectID, userID, phoneNumber, atMs)
	if err != nil {
		return "", wrapErr("ClaimPhoneNumber(user)", err)
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("sqlite: ClaimPhoneNumber: %w", service.ErrNotFound)
	}

	// The writer lock is held, so the read after a conflicting insert
	// always finds the claim; the loop only mirrors the Postgres driver.
	previous := ""
	for claimed := false; !claimed; {
		tag, err := tx.Exec(ctx, `
			INSERT INTO phone_number_claims (project_id, phone_number, user_id, claimed_at_ms)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (project_id, phone_number) DO NOTHING`,
			r.projectID, phoneNumber, userID, atMs)
		if err != nil {
			return "", wrapErr("ClaimPhoneNumber(claim)", err)
		}
		if tag.RowsAffected() == 1 {
			break
		}
		var holder string
		var claimedAt int64
		err = tx.QueryRow(ctx, `
			SELECT user_id, claimed_at_ms FROM phone_number_claims
			 WHERE project_id = $1 AND phone_number = $2`,
			r.projectID, phoneNumber).Scan(&holder, &claimedAt)
		switch {
		case noRows(err):
			continue
		case err != nil:
			return "", wrapErr("ClaimPhoneNumber(holder)", err)
		case holder == userID:
			claimed = true
		case claimedAt >= takeOverBeforeMs:
			return "", service.ErrPhoneNumberTaken
		default:
			if _, err := tx.Exec(ctx, `
				UPDATE phone_number_claims SET user_id = $3, claimed_at_ms = $4
				 WHERE project_id = $1 AND phone_number = $2`,
				r.projectID, phoneNumber, userID, atMs); err != nil {
				return "", wrapErr("ClaimPhoneNumber(move)", err)
			}
			if _, err := tx.Exec(ctx, clearUserPhoneQuery+` AND phone_number = $4`,
				r.projectID, holder, atMs, phoneNumber); err != nil {
				return "", wrapErr("ClaimPhoneNumber(previous holder)", err)
			}
			previous, claimed = holder, true
		}
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM phone_number_claims
		 WHERE project_id = $1 AND user_id = $2 AND phone_number <> $3`,
		r.projectID, userID, phoneNumber); err != nil {
		return "", wrapErr("ClaimPhoneNumber(release previous number)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", wrapErr("ClaimPhoneNumber", err)
	}
	return previous, nil
}

// clearUserPhoneQuery clears one user's phone number and verified state.
const clearUserPhoneQuery = `
	UPDATE users
	   SET phone_number = '', phone_verified = 0, phone_verified_at_ms = 0, updated_at_ms = $3
	 WHERE project_id = $1 AND id = $2`

func (r *sqliteRepository) ReleasePhoneNumber(ctx context.Context, userID string, atMs int64) error {
	if userID == "" {
		return errors.New("sqlite: ReleasePhoneNumber: missing user id")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return wrapErr("ReleasePhoneNumber", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, clearUserPhoneQuery+` AND phone_number <> ''`, r.projectID, userID, atMs); err != nil {
		return wrapErr("ReleasePhoneNumber(user)", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM phone_number_claims WHERE project_id = $1 AND user_id = $2`,
		r.projectID, userID); err != nil {
		return wrapErr("ReleasePhoneNumber(claim)", err)
	}
	return wrapErr("ReleasePhoneNumber", tx.Commit(ctx))
}
