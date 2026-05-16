package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
//
// The adapter also keeps a handle on the typed *sdk.DbClient so it
// can serve service.DB.RegisterUserInTenant via the SDK's Admin RPCs
// (those are not exposed through the raw Transport seam).
func NewDBAdapter(client *sdk.DbClient) (service.DB, error) {
	transport, err := entdbrepo.TransportFromClient(client)
	if err != nil {
		return nil, err
	}
	return &dbAdapter{transport: transport, client: client}, nil
}

type dbAdapter struct {
	transport sdk.Transport
	client    *sdk.DbClient
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

// RegisterUserInTenant registers userID globally and adds it as a
// tenant member with the given role. v1.12+ enforces that every actor
// be a registered user and a tenant member before issuing tenant-
// scoped writes of their own; the typed entRepository.CreateUser path
// has its own wiring for this, but the raw service.DB path (admin
// invites, system bookkeeping) needs the same registration step on
// any user it creates outside the typed repo.
func (a *dbAdapter) RegisterUserInTenant(ctx context.Context, tenantID, userID, email, name, role string) error {
	if userID == "" {
		return errors.New("entdb: RegisterUserInTenant: empty user id")
	}
	// The global registry's Admin.CreateUser rejects empty name with
	// VALIDATION_ERROR; default to the local-part of the email so
	// flows that don't carry a display name still register cleanly.
	if name == "" {
		name = userID
		if i := strings.IndexByte(email, '@'); email != "" && i > 0 {
			name = email[:i]
		}
	}
	const adminActor = "system:admin"
	admin := a.client.Admin()
	if _, err := admin.CreateUser(ctx, adminActor, userID, email, name); err != nil && !dbAdapterIsAlreadyExists(err) {
		return fmt.Errorf("entdb: register user %q: %w", userID, err)
	}
	if err := admin.AddTenantMember(ctx, adminActor, tenantID, userID, role); err != nil && !dbAdapterIsAlreadyExists(err) {
		return fmt.Errorf("entdb: add tenant member %q: %w", userID, err)
	}
	return nil
}

// dbAdapterIsAlreadyExists tolerates the upstream Go server's typed
// gRPC AlreadyExists status code and the Python legacy server's
// string-embedded form.
func dbAdapterIsAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.AlreadyExists
	}
	msg := err.Error()
	return strings.Contains(msg, "ALREADY_EXISTS") || strings.Contains(msg, "already exists")
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
