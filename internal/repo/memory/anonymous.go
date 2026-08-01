package memory

import (
	"context"
	"fmt"
	"sort"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs, oldest first, matching the SQL drivers' batched delete.
//
// Selection and deletion happen under ONE lock. Snapshotting *service.User
// pointers and deleting after releasing it was both a data race (the sweep
// read LastLoginAtMs while touchAnonymousActivity wrote it) and a TOCTOU:
// an account upgraded between the snapshot and the delete was reaped anyway,
// destroying a permanent account with a working credential — the exact
// outcome the is_anonymous predicate exists to prevent. The SQL drivers get
// this from executing one statement; the memory driver has to hold the lock.
func (r *Repo) DeleteStaleAnonymousUsers(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	type victim struct {
		id          string
		lastLoginMs int64
	}
	stale := make([]victim, 0, limit)
	for id, u := range r.users {
		if u.IsAnonymous && u.LastLoginAtMs < beforeMs {
			stale = append(stale, victim{id: id, lastLoginMs: u.LastLoginAtMs})
		}
	}
	// Oldest first, id-tiebroken so a batch boundary is deterministic
	// regardless of map iteration order.
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].lastLoginMs != stale[j].lastLoginMs {
			return stale[i].lastLoginMs < stale[j].lastLoginMs
		}
		return stale[i].id < stale[j].id
	})
	if len(stale) > limit {
		stale = stale[:limit]
	}
	for _, v := range stale {
		r.deleteUserLocked(v.id)
	}
	return nil
}
