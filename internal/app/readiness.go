package app

import (
	"context"

	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// newDBReadinessProbe returns a probe that verifies the configured DB
// is reachable. /readyz hits this on every load-balancer health interval,
// so the probe must be cheap and bounded — we use a no-op QueryNodes on
// the User type which translates to a single round-trip and an empty
// result set (User type_id is required by the schema and always present).
func newDBReadinessProbe(db service.DB) middleware.ReadinessProbe {
	if db == nil {
		return nil
	}
	return dbProbe{db: db}
}

type dbProbe struct{ db service.DB }

func (p dbProbe) Ready(ctx context.Context) error {
	const userTypeID = 1
	// Sentinel filter that matches no row but still exercises the DB
	// round-trip. Empty filter would scan all users; this is bounded.
	_, err := p.db.QueryNodes(ctx, "", "user:readyz", userTypeID, map[string]any{
		"1": "__readyz_probe_no_match__",
	})
	return err
}
