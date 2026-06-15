package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Row-Level Security (RLS) plumbing — the Go half of the defense-in-depth
// boundary established by migration 0016.
//
// Migration 0016 puts a policy on every data-plane table:
//
//	USING (project_id = current_setting('app.current_project_id', true))
//
// For that policy to admit a row, the connection running the query must
// have the `app.current_project_id` GUC set to the bound project. This
// file sets it on EVERY connection the pool hands out, scoped to the
// project the acquiring repository is bound to, via the pgxpool
// PrepareConn hook (wired in New, see repo.go). PrepareConn runs on every
// Acquire — including the implicit acquire inside pool.Query / pool.Exec /
// pool.QueryRow / pool.Begin — so all query paths are covered without
// touching individual SQL call sites.
//
// Leak-safety: PrepareConn ALWAYS overwrites the GUC with the acquiring
// repository's project, so a pooled connection reused by a different
// project can never carry a stale value into that project's query. The
// project to set is read from the context, which the tracedPool injects
// from its bound projectID on every call (see tracepool.go). If the GUC
// is somehow never set (a path that bypasses this hook), the policy's
// `missing_ok = true` makes current_setting return NULL and the row test
// fails closed — zero rows, never a cross-project leak.

// rlsGUC is the session GUC the data-plane RLS policies read. It MUST
// match the name used in migration 0016. The `app.` namespace is a
// custom (non-reserved) GUC class, which Postgres permits via
// set_config / SET without prior registration.
const rlsGUC = "app.current_project_id"

// projectCtxKey is the context key under which the tracedPool stores the
// bound project so the PrepareConn hook can read it at acquire time. A
// dedicated unexported type avoids collisions with any other context
// value in the request context.
type projectCtxKey struct{}

// withProjectGUC returns a context carrying projectID for the PrepareConn
// hook to apply. The tracedPool calls this on every pool operation so the
// hook always has the bound project available.
func withProjectGUC(ctx context.Context, projectID string) context.Context {
	return context.WithValue(ctx, projectCtxKey{}, projectID)
}

// projectFromCtx extracts the bound project a connection should be scoped
// to. The second return is false when no project was injected — the hook
// treats that as an error and fails the acquire closed rather than handing
// out a connection with an unscoped (or stale) GUC.
func projectFromCtx(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(projectCtxKey{}).(string)
	return v, ok
}

// prepareConnForRLS is the pgxpool PrepareConn hook. It runs before a
// connection is handed out of the pool and sets the app.current_project_id
// GUC to the project carried on the acquire context, so the migration-0016
// RLS policies admit exactly that project's rows.
//
// Returning (true, nil) lets the query proceed on the prepared connection.
// Returning (true, err) keeps the connection in the pool but fails the
// instigating query — the right behaviour for "the GUC could not be set",
// since proceeding would let the query run with whatever GUC the
// connection last had (a potential cross-project read). We fail closed.
func prepareConnForRLS(ctx context.Context, conn *pgx.Conn) (bool, error) {
	projectID, ok := projectFromCtx(ctx)
	if !ok {
		// No project bound on the context. Every pgRepository / ProjectStore
		// path injects one via the tracedPool, so reaching here means a
		// query was issued through a path that bypassed that plumbing. Fail
		// closed rather than run with a stale/unset GUC.
		return true, errors.New("postgres: RLS: no project bound on connection acquire context")
	}
	// set_config(name, value, is_local=false) sets the GUC at session scope
	// on this physical connection. Because PrepareConn runs on EVERY acquire
	// and always overwrites it, session scope cannot leak across projects:
	// the next acquirer re-sets it to its own project before its query runs.
	if _, err := conn.Exec(ctx, "SELECT set_config($1, $2, false)", rlsGUC, projectID); err != nil {
		return false, fmt.Errorf("postgres: RLS: set %s: %w", rlsGUC, err)
	}
	return true, nil
}
