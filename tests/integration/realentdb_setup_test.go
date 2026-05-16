//go:build realentdb

// Shared helpers for tests gated by the `realentdb` build tag.
// Compiled into both the CI `-tags=realentdb` job (this file plus
// repo_realentdb_test.go, auth_password_realentdb_test.go,
// issue3_harness_realentdb_test.go) and the nightly
// `-tags=integration,realentdb` job (additionally pulls in
// harness_realentdb_test.go, which uses the helper too).

package integration

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ensureRealEntDBTenant registers a tenant in the global registry
// before any test issues a tenant-scoped write. tenant-shard-db
// v1.12.1 made tenant registration strictly required — the server
// no longer auto-creates on first write, and an unregistered tenant
// id returns NOT_FOUND.
//
// Identity's per-user actors (`user:<id>`) are registered by
// entRepository.CreateUser via the entClient.ensureUserTenantMember
// path. The tenant-admin actor (`system:admin`) used for cross-user
// reads in repo.go does not need to be a registered user — `system:`
// is a built-in kind that has tenant-wide read/write on top of the
// upstream actor isolation model.
func ensureRealEntDBTenant(t *testing.T, client *sdk.DbClient, tenantID string) {
	t.Helper()
	ctx := context.Background()

	admin := client.Admin()
	if _, err := admin.CreateTenant(ctx, "system:admin", tenantID, tenantID); err != nil && !realEntDBIsAlreadyExists(err) {
		t.Fatalf("admin.CreateTenant(%q): %v", tenantID, err)
	}
}

// realEntDBIsAlreadyExists tolerates the upstream Go server's typed
// gRPC AlreadyExists status code and the Python legacy server's
// string-embedded form.
func realEntDBIsAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.AlreadyExists
	}
	msg := err.Error()
	return strings.Contains(msg, "ALREADY_EXISTS") || strings.Contains(msg, "already exists")
}
