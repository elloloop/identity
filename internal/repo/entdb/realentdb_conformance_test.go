//go:build realentdb

package entdb

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/service"
)

// TestConformance runs the driver-agnostic Repository conformance
// suite against the real EntDB server. CI's `Conformance / entdb`
// matrix entry invokes this test with GATEWAY_ENTDB_ADDRESS pointing
// at a live tenant-shard-db service container; locally `make
// conformance-all` does the same after `make services-up`.
//
// Each subtest gets a fresh tenant id so state never leaks between
// subtests (the upstream server creates the tenant lazily on first
// write). The shared sdk.DbClient is reused across subtests because
// Connect is expensive and per-tenant isolation is sufficient.
//
// Tenant ids must match [A-Za-z0-9_-] (the upstream server rejects
// '/' and any other path-unsafe characters) so the per-subtest id is
// a process-unique base + an atomic counter rather than t.Name().
func TestConformance(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset — skipping entdb conformance")
	}

	client, err := sdk.NewClient(addr)
	if err != nil {
		t.Fatalf("sdk.NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("sdk client Connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	base := fmt.Sprintf("entdb-conf-%d", time.Now().UnixNano())
	var seq int64

	conformance.RunConformance(t, conformance.Driver{
		Name: "entdb",
		NewRepo: func(t *testing.T) service.Repository {
			t.Helper()
			n := atomic.AddInt64(&seq, 1)
			return NewRepository(client, fmt.Sprintf("%s-%d", base, n))
		},
	})
}
