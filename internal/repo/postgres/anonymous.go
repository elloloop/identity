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
// Child rows (refresh tokens, sessions, OAuth identities, …) follow via the
// users FK cascades.
func (r *pgRepository) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("postgres: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}
	const q = `
		DELETE FROM users
		 WHERE id IN (
		     SELECT id FROM users
		      WHERE project_id = $1 AND is_anonymous AND last_login_at_ms < $2
		      ORDER BY last_login_at_ms ASC
		      LIMIT $3
		 )`
	if _, err := r.pool.Exec(ctx, q, r.projectID, beforeMs, limit); err != nil {
		return wrapPgErr("DeleteStaleAnonymousUsers", err)
	}
	return nil
}
