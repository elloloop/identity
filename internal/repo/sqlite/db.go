package sqlite

import (
	"context"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"

	"github.com/elloloop/identity/internal/service"
)

// service.DB graph surface.
//
// The DB graph methods (nodes/edges) are the EntDB two-tier model the
// Groups service rides on. The SQLite backend targets the embedded /
// single-project tier and, like the in-memory driver, does not implement
// the EntDB node/edge graph: it returns the same ErrServiceUnavailable for
// reads and a successful no-op for writes, so a deployment that does not use
// Groups runs cleanly while one that does fails loudly rather than silently
// losing data. (If/when Groups is reworked off the EntDB graph onto plain
// relational tables, this driver gains real nodes/edges tables — tracked
// alongside the entdb-removal work.)

var errSQLiteDBUnsupported = service.ErrServiceUnavailable

func (r *sqliteRepository) GetNode(context.Context, string, string, int, string) (*sdk.Node, error) {
	return nil, errSQLiteDBUnsupported
}

func (r *sqliteRepository) QueryNodes(context.Context, string, string, int, map[string]any) ([]*sdk.Node, error) {
	return nil, errSQLiteDBUnsupported
}

func (r *sqliteRepository) ExecuteAtomic(context.Context, string, string, []sdk.Operation) (*sdk.CommitResult, error) {
	return &sdk.CommitResult{Success: true, Applied: true}, nil
}

func (r *sqliteRepository) GetEdgesFrom(context.Context, string, string, string, int) ([]*sdk.Edge, error) {
	return nil, nil
}

func (r *sqliteRepository) GetEdgesTo(context.Context, string, string, string, int) ([]*sdk.Edge, error) {
	return nil, nil
}

func (r *sqliteRepository) SearchNodes(context.Context, string, string, int, string) ([]*sdk.Node, error) {
	return nil, errSQLiteDBUnsupported
}

// RegisterUserInTenant is a no-op on the SQLite driver: like the in-memory
// driver it bypasses the EntDB two-tier registry/membership model entirely.
func (r *sqliteRepository) RegisterUserInTenant(_ context.Context, _, _, _, _, _ string) error {
	return nil
}
