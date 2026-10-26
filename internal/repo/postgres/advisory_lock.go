package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// advisoryKey names a transaction-scoped advisory lock: the namespace, then
// each part length-prefixed, so no two distinct part lists in one namespace
// share a key whatever characters they hold.
func advisoryKey(namespace string, parts ...string) string {
	var b strings.Builder
	b.WriteString(namespace)
	for _, p := range parts {
		fmt.Fprintf(&b, ":%d:%s", len(p), p)
	}
	return b.String()
}

// lockXact takes the advisory lock key names, held until tx ends. op names
// the caller in the error.
func lockXact(ctx context.Context, tx pgx.Tx, op, key string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
		return wrapPgErr(op+"(lock)", err)
	}
	return nil
}

// autoformLockKey serialises every write that decides which tenant an email
// domain's signups join within a project: auto-formation, a new claim on the
// domain, and a claim becoming verified.
func autoformLockKey(projectID, domain string) string {
	return advisoryKey("tenant_autoform", projectID, strings.ToLower(domain))
}
