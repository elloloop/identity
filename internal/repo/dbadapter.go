package repo

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	"github.com/elloloop/identity/internal/service"
)

const entDBApplyWaitTimeoutMs int32 = 5000

// NewDBAdapter exposes the SDK's raw transport as service.DB. The
// service.DB contract is already the transport contract: tenant id,
// actor, numeric type ids, field-id-keyed filters, and raw
// entdb.Operation batches. Going through the SDK's typed Query/Get
// helpers here loses node ids on query results, so the adapter must
// delegate to the raw transport instead of translating through typed
// witnesses.
func NewDBAdapter(client *sdk.DbClient) (service.DB, error) {
	transport, err := entdbrepo.TransportFromClient(client)
	if err != nil {
		return nil, err
	}
	return &dbAdapter{transport: transport}, nil
}

type dbAdapter struct {
	transport sdk.Transport
}

func (a *dbAdapter) GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*sdk.Node, error) {
	return a.transport.GetNode(ctx, tenantID, actor, typeID, nodeID)
}

func (a *dbAdapter) QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*sdk.Node, error) {
	return a.transport.QueryNodes(ctx, tenantID, actor, typeID, filter)
}

func (a *dbAdapter) ExecuteAtomic(ctx context.Context, tenantID, actor string, ops []sdk.Operation) (*sdk.CommitResult, error) {
	// The EntDB SDK Transport accepts an idempotencyKey we don't use
	// (no service flow needs cross-request retry safety today); pass
	// "" to keep the call shape but not expose it through our interface.
	result, err := a.transport.ExecuteAtomic(ctx, tenantID, actor, "", ops)
	if err != nil {
		return nil, err
	}
	if err := a.waitForApplied(ctx, tenantID, actor, result, len(ops)); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *dbAdapter) GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	return a.transport.GetEdgesFrom(ctx, tenantID, actor, fromNodeID, edgeTypeID)
}

func (a *dbAdapter) GetEdgesTo(ctx context.Context, tenantID, actor, toNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	return a.transport.GetEdgesTo(ctx, tenantID, actor, toNodeID, edgeTypeID)
}

func (a *dbAdapter) SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*sdk.Node, error) {
	return a.transport.SearchNodes(ctx, tenantID, actor, typeID, query)
}

func (a *dbAdapter) waitForApplied(ctx context.Context, tenantID, actor string, result *sdk.CommitResult, opCount int) error {
	if result == nil {
		return errors.New("entdb: nil commit result")
	}
	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("entdb: commit failed: %s", result.Error)
		}
		return errors.New("entdb: commit failed")
	}
	if opCount == 0 || result.Applied {
		return nil
	}
	if result.Receipt == nil || result.Receipt.StreamPosition == "" {
		return errors.New("entdb: commit returned before apply without stream position")
	}
	reached, current, err := a.transport.WaitForOffset(
		ctx,
		tenantID,
		actor,
		result.Receipt.StreamPosition,
		entDBApplyWaitTimeoutMs,
	)
	if err != nil {
		return fmt.Errorf("entdb: wait for commit apply: %w", err)
	}
	if !reached {
		return fmt.Errorf(
			"entdb: commit apply timeout waiting for %q; current offset %q",
			result.Receipt.StreamPosition,
			current,
		)
	}
	result.Applied = true
	return nil
}
