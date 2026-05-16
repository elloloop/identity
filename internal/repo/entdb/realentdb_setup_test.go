//go:build realentdb

package entdb

import (
	"context"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
)

// ensureRealEntDBTenant registers a tenant in the global registry
// before any test issues a tenant-scoped write. tenant-shard-db
// v1.12.1 made tenant registration strictly required — the server
// no longer auto-creates on first write, and an unregistered tenant
// id returns NOT_FOUND. The `system:admin` actor identity uses for
// cross-user reads does not need to be a registered user — `system:`
// is a built-in kind that has tenant-wide read/write.
func ensureRealEntDBTenant(t *testing.T, client *sdk.DbClient, tenantID string) {
	t.Helper()
	ctx := context.Background()

	admin := client.Admin()
	if _, err := admin.CreateTenant(ctx, systemActor, tenantID, tenantID); err != nil && !isAlreadyExists(err) {
		t.Fatalf("admin.CreateTenant(%q): %v", tenantID, err)
	}
}
