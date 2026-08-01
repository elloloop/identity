package postgres

import (
	"context"
	"fmt"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs. It mirrors DeleteStaleAttestedDevices — a batched,
// oldest-first delete keyed on an activity column rather than an expiry —
// and is backed by users_project_anonymous_last_login_idx.
//
// The is_anonymous predicate is the load-bearing part: an upgraded account
// clears the flag, so a user who attached a credential can never be reaped
// by this sweep no matter how long the original anonymous session sat idle.
//
// The four userDeleteNonFKTables are cleared explicitly, exactly as
// DeleteUser does. Their user_id has no FK to users(id) — it defaults to ”
// so they can hold rows with no owning user — so a bare DELETE FROM users
// leaves them behind. That is reachable: BeginPasskeyRegistration writes a
// passkey_challenges row. Every other user-keyed table follows via ON DELETE
// CASCADE. The whole batch runs in one transaction so a mid-sweep failure
// cannot strip a user's rows while leaving the user, or vice versa.
func (r *pgRepository) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("postgres: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const selectVictims = `
		SELECT id FROM users
		 WHERE project_id = $1 AND is_anonymous AND last_login_at_ms < $2
		 ORDER BY last_login_at_ms ASC
		 LIMIT $3`
	rows, err := tx.Query(ctx, selectVictims, r.projectID, beforeMs, limit)
	if err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers(select)", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return wrapPgErr("DeleteStaleAnonymousUsers(scan)", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers(rows)", err)
	}
	if len(ids) == 0 {
		return nil
	}

	for _, tbl := range userDeleteNonFKTables {
		if _, err := tx.Exec(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE project_id = $1 AND user_id = ANY($2)`, tbl),
			r.projectID, ids); err != nil {
			return wrapPgErr("DeleteStaleAnonymousUsers("+tbl+")", err)
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM users WHERE project_id = $1 AND id = ANY($2)`,
		r.projectID, ids); err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers(users)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers(commit)", err)
	}
	return nil
}
