package postgres

import (
	"context"
	"fmt"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs, backed by users_project_anonymous_last_seen_idx.
//
// The users DELETE is the DRIVING statement, and its own WHERE carries the
// is_anonymous predicate — not a SELECT that feeds ids to a later delete.
// That ordering is the whole safety property. With a separate select the
// predicate applies only to the read, so an UpgradeAnonymousUser committing
// in the gap leaves the DELETE matching on (project_id, id) alone and
// destroying a now-permanent, credential-bearing account with every
// cascaded child row. The gap is not theoretical: the non-FK child deletes
// used to run inside it. Postgres' EvalPlanQual re-check does not save it
// either, because the DELETE's own qualifiers still hold against the
// updated tuple.
//
// RETURNING then drives the four userDeleteNonFKTables cleanups off the ids
// actually deleted, so a survivor's pending rows are never stripped. Those
// tables' user_id has no FK to users(id) — it defaults to ” so pre-account
// flows can write them — which is why ON DELETE CASCADE does not reach
// them and DeleteUser clears them explicitly too. Reachable here:
// BeginPasskeyRegistration writes a passkey_challenges row.
//
// One transaction, so a mid-sweep failure cannot strip a user's rows while
// leaving the user.
func (r *pgRepository) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("postgres: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

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
	rows, err := tx.Query(ctx, deleteVictims, r.projectID, beforeMs, limit)
	if err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers(delete)", err)
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
	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers(commit)", err)
	}
	return nil
}
