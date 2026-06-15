//go:build dockerpostgres

// Build-tag–gated container test for the migration-0016 Row-Level Security
// boundary. Gated behind `dockerpostgres` (like the other *_dockertest_test
// files) so the default `go test ./...` does not require Docker. The shared
// assertion body lives in rls_test.go (untagged) so CI's coverage job — which
// runs the untagged TestPostgres_RLS_Smoke against a live
// GATEWAY_TEST_POSTGRES_DSN — exercises the same proof. Run locally with:
//
//	go test -tags=dockerpostgres -run RLS -timeout=600s ./internal/repo/postgres/...

package postgres

import (
	"context"
	"testing"
	"time"
)

// TestPostgres_RLS_Container drives runRLSProof against a throwaway
// postgres:16.13-alpine3.23 container, proving cross-project isolation is
// enforced by the database (RLS), not merely by the application WHERE clause.
func TestPostgres_RLS_Container(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)
	runRLSProof(t, dsn)
}
