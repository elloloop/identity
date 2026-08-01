package sqlite

import (
	"context"
	"fmt"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs, mirroring the postgres driver: a batched, oldest-first
// delete keyed on last_login_at_ms and gated on is_anonymous, so an upgraded
// account (which clears the flag) is never reachable by this sweep. Child
// rows follow via the users FK cascades.
func (r *sqliteRepository) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("sqlite: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}
	const q = `
		DELETE FROM users
		 WHERE id IN (
		     SELECT id FROM users
		      WHERE project_id = $1 AND is_anonymous AND last_login_at_ms < $2
		      ORDER BY last_login_at_ms ASC
		      LIMIT $3
		 )`
	if _, err := r.db.Exec(ctx, q, r.projectID, beforeMs, limit); err != nil {
		return wrapErr("DeleteStaleAnonymousUsers", err)
	}
	return nil
}
