package sqlite

import (
	"context"
	"fmt"
)

// Test-support surface.
//
// The integration harness inspects/mutates rows that, on the EntDB-backed
// driver, live in the node/edge graph it reaches via service.DB. The SQLite
// driver intentionally does not implement that graph (it is the embedded /
// single-project tier — see db.go), so it exposes these narrow,
// SQL-backed helpers instead. They are used ONLY by the integration test
// harness (which type-asserts a small interface), never by production code,
// and read/write the same project-scoped tables the Repository methods do.
//
// The *Test suffix marks them as the test-support seam; keeping them on the
// driver (rather than reaching into a *sql.DB from the test) keeps the
// project_id scoping and column mapping in one place.

// CountRefreshTokensForUserTest counts this project's refresh-token rows for a
// user (including consumed ones, matching the EntDB graph count the harness
// asserts against).
func (r *sqliteRepository) CountRefreshTokensForUserTest(ctx context.Context, userID string) (int, error) {
	return r.countRows(ctx, `SELECT COUNT(*) FROM refresh_tokens WHERE project_id = $1 AND user_id = $2`, userID)
}

// CountUsersByEmailTest counts this project's user rows with the given email
// (exact match — the harness seeds lowercase fixtures).
func (r *sqliteRepository) CountUsersByEmailTest(ctx context.Context, email string) (int, error) {
	return r.countRows(ctx, `SELECT COUNT(*) FROM users WHERE project_id = $1 AND email = $2`, email)
}

// CountPasswordResetTokensForUserTest counts this project's password-reset
// rows for a user.
func (r *sqliteRepository) CountPasswordResetTokensForUserTest(ctx context.Context, userID string) (int, error) {
	return r.countRows(ctx, `SELECT COUNT(*) FROM password_reset_tokens WHERE project_id = $1 AND user_id = $2`, userID)
}

func (r *sqliteRepository) countRows(ctx context.Context, q string, arg string) (int, error) {
	var n int
	if err := r.db.QueryRow(ctx, q, r.projectID, arg).Scan(&n); err != nil {
		return 0, wrapErr("countRows", err)
	}
	return n, nil
}

// UpdatePasskeyChallengeTest sets the challenge value on a passkey-challenge
// row. patch is keyed by the EntDB field id the harness uses ("1" =
// challenge); unknown keys are ignored.
func (r *sqliteRepository) UpdatePasskeyChallengeTest(ctx context.Context, nodeID string, patch map[string]any) error {
	v, ok := patch["1"]
	if !ok {
		return nil
	}
	s, ok := nullableString(v)
	if !ok {
		return fmt.Errorf("sqlite: UpdatePasskeyChallengeTest: challenge value not a string: %T", v)
	}
	const q = `UPDATE passkey_challenges SET challenge = $3 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, nodeID, s); err != nil {
		return wrapErr("UpdatePasskeyChallengeTest", err)
	}
	return nil
}

// UpdateQrLoginSessionTest patches a qr-login-session row's expiry/updated
// timestamps. patch is keyed by the EntDB field ids the harness uses
// ("8" = expires_at_ms, "10" = updated_at_ms); unknown keys are ignored.
func (r *sqliteRepository) UpdateQrLoginSessionTest(ctx context.Context, nodeID string, patch map[string]any) error {
	// Both fields are int64 epoch ms; patch each independently.
	if v, ok := patch["8"]; ok {
		n, ok := nullableInt64(v)
		if !ok {
			return fmt.Errorf("sqlite: UpdateQrLoginSessionTest: expires_at not an int: %T", v)
		}
		if _, err := r.db.Exec(ctx,
			`UPDATE qr_login_sessions SET expires_at_ms = $3 WHERE project_id = $1 AND id = $2`,
			r.projectID, nodeID, n); err != nil {
			return wrapErr("UpdateQrLoginSessionTest(expires_at)", err)
		}
	}
	if v, ok := patch["10"]; ok {
		n, ok := nullableInt64(v)
		if !ok {
			return fmt.Errorf("sqlite: UpdateQrLoginSessionTest: updated_at not an int: %T", v)
		}
		if _, err := r.db.Exec(ctx,
			`UPDATE qr_login_sessions SET updated_at_ms = $3 WHERE project_id = $1 AND id = $2`,
			r.projectID, nodeID, n); err != nil {
			return wrapErr("UpdateQrLoginSessionTest(updated_at)", err)
		}
	}
	return nil
}
