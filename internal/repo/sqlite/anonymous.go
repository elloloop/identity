package sqlite

import (
	"context"
	"fmt"
	"strings"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs, mirroring the postgres driver.
//
// The users DELETE is the DRIVING statement and carries is_anonymous in its
// own WHERE: selecting ids first and deleting by id later applies the
// predicate to the read only, so an upgrade committing in the gap would be
// hard-deleted along with its cascaded rows. RETURNING then drives the
// userDeleteNonFKTables cleanups off the ids actually deleted, so a
// survivor's pending rows are never stripped — those tables have no FK to
// users(id), which is why DeleteUser clears them explicitly too.
func (r *sqliteRepository) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("sqlite: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}

	t, err := r.db.Begin(ctx)
	if err != nil {
		return wrapErr("DeleteStaleAnonymousUsers", err)
	}
	defer func() { _ = t.Rollback(ctx) }()

	const deleteVictims = `
		DELETE FROM users
		 WHERE project_id = $1
		   AND is_anonymous
		   AND anonymous_last_seen_ms < $2
		   AND id IN (
		       SELECT id FROM users
		        WHERE project_id = $1 AND is_anonymous AND anonymous_last_seen_ms < $2
		        ORDER BY anonymous_last_seen_ms ASC
		        LIMIT $3
		   )
		RETURNING id`
	rows, err := t.Query(ctx, deleteVictims, r.projectID, beforeMs, limit)
	if err != nil {
		return wrapErr("DeleteStaleAnonymousUsers(delete)", err)
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
	if err := t.Commit(ctx); err != nil {
		return wrapErr("DeleteStaleAnonymousUsers(commit)", err)
	}
	return nil
}
