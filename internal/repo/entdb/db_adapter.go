package entdb

import (
	"context"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

// dbAdapter delegates service.DB calls to a Client.
type dbAdapter struct {
	client Client
}

// NewDBAdapter wraps a *sdk.DbClient as a service.DB. Both the
// per-service raw-node access (admin, groups, help, profile) and the
// audit logger reach EntDB through this adapter — every call goes
// through Client (which itself uses the SDK's PUBLIC typed API),
// not through the unsafe Transport extraction the old implementation
// relied on.
func NewDBAdapter(client *sdk.DbClient) service.DB {
	return &dbAdapter{client: NewSDKClient(client)}
}

// NewDBAdapterWithClient is the test seam: it accepts a Client
// interface so unit tests can drop in a fake.
func NewDBAdapterWithClient(c Client) service.DB {
	return &dbAdapter{client: c}
}

func (a *dbAdapter) GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*sdk.Node, error) {
	return a.client.GetNode(ctx, tenantID, actor, typeID, nodeID)
}

func (a *dbAdapter) QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*sdk.Node, error) {
	return a.client.QueryNodes(ctx, tenantID, actor, typeID, filter)
}

func (a *dbAdapter) ExecuteAtomic(ctx context.Context, tenantID, actor, idempotencyKey string, ops []sdk.Operation) (*sdk.CommitResult, error) {
	return a.client.ExecuteAtomic(ctx, tenantID, actor, idempotencyKey, ops)
}

func (a *dbAdapter) GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	return a.client.GetEdgesFrom(ctx, tenantID, actor, fromNodeID, edgeTypeID)
}

func (a *dbAdapter) SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*sdk.Node, error) {
	return a.client.SearchNodes(ctx, tenantID, actor, typeID, query)
}

// firstCreatedNodeID returns the first node id from a CommitResult.
// Repository CreateXxx methods promise to return the new node's ID,
// so we fail loudly if entdb committed but did not report one.
func firstCreatedNodeID(res *sdk.CommitResult, op string) (string, error) {
	if res == nil {
		return "", fmt.Errorf("repo: %s: nil commit result", op)
	}
	if !res.Success {
		if res.Error != "" {
			return "", fmt.Errorf("repo: %s: %s", op, res.Error)
		}
		return "", fmt.Errorf("repo: %s: commit not successful", op)
	}
	if len(res.CreatedNodeIDs) == 0 {
		return "", fmt.Errorf("repo: %s: commit succeeded but no node id returned", op)
	}
	return res.CreatedNodeIDs[0], nil
}
