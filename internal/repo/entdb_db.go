// Package repo provides the EntDB-backed implementation of
// service.Repository and service.DB used by the production identity
// binary.
//
// The package wraps a *entdb.DbClient with two adapters:
//
//   - NewDBAdapter returns a service.DB suitable for use by services
//     that operate on raw nodes (admin, groups, help, profile) and by
//     the audit logger.
//
//   - NewEntDBRepository returns a service.Repository providing the
//     typed CRUD operations the AuthService uses (users, refresh
//     tokens, passkeys, TOTP, recovery codes, login challenges,
//     invitations, password-reset and email-verification tokens).
//
// All operations use the entdb.Transport surface (raw type IDs and
// numeric field IDs as decimal strings). The Transport is reachable
// through *entdb.DbClient via the (intentionally narrow) reflection
// helper extractTransport — the public DbClient API is heavily proto-
// typed and identity stores raw node payloads keyed by field id, so
// we go through the lower-level Transport that *DbClient already
// owns. See README of tenant-shard-db-go for the rationale of the
// public-typed/internal-raw split.
package repo

import (
	"context"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

// entdbClient captures the subset of the entdb.Transport API that the
// repo package depends on. Both *entdb.DbClient (via the unwrapped
// transport) and the test fake satisfy this interface so the repo
// can be unit-tested without a live gRPC connection.
type entdbClient interface {
	GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*entdb.Node, error)
	QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*entdb.Node, error)
	ExecuteAtomic(ctx context.Context, tenantID, actor, idempotencyKey string, ops []entdb.Operation) (*entdb.CommitResult, error)
	GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*entdb.Edge, error)
	SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*entdb.Node, error)
}

// extractTransport pulls the (private) transport field out of a
// *entdb.DbClient. The Transport interface is exported by the entdb
// package; only the field accessor on DbClient is unexported. We use
// unsafe to read the field — a brittle but bounded coupling that lets
// the production binary use the raw-payload Transport surface while
// still letting the entdb SDK keep its public typed-message API.
//
// If the field layout ever changes upstream, this fails fast at
// startup (the type assertion panics) rather than silently corrupting
// data.
func extractTransport(c *entdb.DbClient) entdb.Transport {
	if c == nil {
		return nil
	}
	v := reflect.ValueOf(c).Elem().FieldByName("transport")
	if !v.IsValid() {
		panic("repo: entdb.DbClient.transport field not found — entdb SDK layout changed")
	}
	t, ok := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(entdb.Transport)
	if !ok {
		panic("repo: entdb.DbClient.transport is not entdb.Transport")
	}
	return t
}

// dbAdapter delegates service.DB calls to an entdbClient.
type dbAdapter struct {
	client entdbClient
}

// NewDBAdapter wraps a *entdb.DbClient as a service.DB. The returned
// DB also satisfies audit.NodeWriter, so a single adapter serves
// both the per-service raw-node access and the audit logger.
func NewDBAdapter(client *entdb.DbClient) service.DB {
	return &dbAdapter{client: extractTransport(client)}
}

// newDBAdapterFromClient lets tests inject a fake entdbClient.
func newDBAdapterFromClient(c entdbClient) service.DB {
	return &dbAdapter{client: c}
}

func (a *dbAdapter) GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*entdb.Node, error) {
	return a.client.GetNode(ctx, tenantID, actor, typeID, nodeID)
}

func (a *dbAdapter) QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*entdb.Node, error) {
	return a.client.QueryNodes(ctx, tenantID, actor, typeID, filter)
}

func (a *dbAdapter) ExecuteAtomic(ctx context.Context, tenantID, actor, idempotencyKey string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	return a.client.ExecuteAtomic(ctx, tenantID, actor, idempotencyKey, ops)
}

func (a *dbAdapter) GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	return a.client.GetEdgesFrom(ctx, tenantID, actor, fromNodeID, edgeTypeID)
}

func (a *dbAdapter) SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*entdb.Node, error) {
	return a.client.SearchNodes(ctx, tenantID, actor, typeID, query)
}

// firstCreatedNodeID returns the first node id from a CommitResult.
// Repository CreateXxx methods promise to return the new node's ID,
// so we fail loudly if entdb committed but did not report one.
func firstCreatedNodeID(res *entdb.CommitResult, op string) (string, error) {
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
