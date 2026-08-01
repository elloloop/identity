package sqlite

import (
	"context"
	"fmt"
	"strings"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs, mirroring the postgres driver: a batched, oldest-first
// delete keyed on last_login_at_ms and gated on is_anonymous, so an upgraded
// account (which clears the flag) is never reachable by this sweep.
//
// The four userDeleteNonFKTables are cleared explicitly, exactly as
// DeleteUser does — their user_id has no FK to users(id), so a bare
// DELETE FROM users leaves them behind. That is reachable:
// BeginPasskeyRegistration writes a passkey_challenges row. Every other
// user-keyed table follows via ON DELETE CASCADE. One transaction for the
// whole batch, so a mid-sweep failure cannot strip a user's rows while
// leaving the user.
func (r *sqliteRepository) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("sqlite: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}

	t, err := r.db.Begin(ctx)
	if err != nil {
		return wrapErr("DeleteStaleAnonymousUsers", err)
	}
	defer func() { _ = t.Rollback(ctx) }()

	const selectVictims = `
		SELECT id FROM users
		 WHERE project_id = $1 AND is_anonymous AND last_login_at_ms < $2
		 ORDER BY last_login_at_ms ASC
		 LIMIT $3`
	rows, err := t.Query(ctx, selectVictims, r.projectID, beforeMs, limit)
	if err != nil {
		return wrapErr("DeleteStaleAnonymousUsers(select)", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return wrapErr("DeleteStaleAnonymousUsers(scan)", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return wrapErr("DeleteStaleAnonymousUsers(rows)", err)
	}
	if len(ids) == 0 {
		return nil
	}

	// SQLite has no array parameter, so the id list expands into
	// placeholders. The count is bounded by limit, which the sweeper caps at
	// its batch size.
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, r.projectID)
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	inClause := "(" + strings.Join(placeholders, ", ") + ")"

	for _, tbl := range userDeleteNonFKTables {
		if _, err := t.Exec(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE project_id = $1 AND user_id IN %s`, tbl, inClause),
			args...); err != nil {
			return wrapErr("DeleteStaleAnonymousUsers("+tbl+")", err)
		}
	}
	if _, err := t.Exec(ctx,
		"DELETE FROM users WHERE project_id = $1 AND id IN "+inClause,
		args...); err != nil {
		return wrapErr("DeleteStaleAnonymousUsers(users)", err)
	}
	if err := t.Commit(ctx); err != nil {
		return wrapErr("DeleteStaleAnonymousUsers(commit)", err)
	}
	return nil
}
