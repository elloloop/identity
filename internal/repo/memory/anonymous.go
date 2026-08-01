package memory

import (
	"context"
	"fmt"
	"sort"

	"github.com/elloloop/identity/internal/service"
)

// DeleteStaleAnonymousUsers reaps anonymous users whose last activity
// predates beforeMs, oldest first, matching the SQL drivers' batched delete.
// It selects under the lock and then defers to DeleteUser for each victim so
// the user-owned rows are drained by exactly the same code that backs an
// ordinary account deletion — the in-memory stand-in for the FK cascades.
func (r *Repo) DeleteStaleAnonymousUsers(ctx context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}

	r.mu.Lock()
	stale := make([]*service.User, 0, limit)
	for _, u := range r.users {
		if u.IsAnonymous && u.LastLoginAtMs < beforeMs {
			stale = append(stale, u)
		}
	}
	r.mu.Unlock()

	// Oldest first, id-tiebroken so a batch boundary is deterministic
	// regardless of map iteration order.
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].LastLoginAtMs != stale[j].LastLoginAtMs {
			return stale[i].LastLoginAtMs < stale[j].LastLoginAtMs
		}
		return stale[i].ID < stale[j].ID
	})
	if len(stale) > limit {
		stale = stale[:limit]
	}
	for _, u := range stale {
		if err := r.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
	}
	return nil
}
