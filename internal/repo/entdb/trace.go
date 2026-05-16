package entdb

import (
	"context"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/proto"

	"github.com/elloloop/identity/internal/observability"
)

// tracedClient wraps an entClient with per-call OpenTelemetry spans.
// Outbound spans show in distributed traces as the cost of reaching
// tenant-shard-db; deployers pivot on the entdb.message_type attribute
// to ask "where is the time going for User reads?".
//
// The upstream tenant-shard-db SDK does not expose an interceptor /
// hook seam. Wrapping at the repo-layer entClient is the right local
// boundary either way: it captures the full logical operation (e.g.
// plan + commit + visibility wait) as one span rather than the SDK's
// lower-level RPCs. See the M8 PR description for the upstream issue
// link.
type tracedClient struct {
	inner entClient
}

// tracedRawClient is the tracedClient variant for entClient impls that
// also satisfy rawUpdateClient (currently only *sdkScope when the raw
// transport is reachable). Returning a distinct type from
// newTracedClient preserves the repo's `r.client.(rawUpdateClient)`
// fast path while keeping rawUpdate-less impls (the in-memory test
// fake) from accidentally satisfying the interface.
type tracedRawClient struct {
	tracedClient
	raw rawUpdateClient
}

// newTracedClient wraps inner with per-call spans. When inner also
// satisfies rawUpdateClient, the returned value does too.
func newTracedClient(inner entClient) entClient {
	tc := tracedClient{inner: inner}
	if raw, ok := inner.(rawUpdateClient); ok {
		return &tracedRawClient{tracedClient: tc, raw: raw}
	}
	return &tc
}

func (t *tracedClient) get(ctx context.Context, actor string, dst proto.Message, nodeID string) error {
	ctx, end := observability.StartClient(ctx, "entdb.get", entAttrs(actor, dst, nodeID)...)
	err := t.inner.get(ctx, actor, dst, nodeID)
	end(err)
	return err
}

func (t *tracedClient) findByKey(ctx context.Context, actor string, key sdk.UniqueKey[string], value string, dst proto.Message) (string, error) {
	ctx, end := observability.StartClient(ctx, "entdb.findByKey", entAttrs(actor, dst, "")...)
	id, err := t.inner.findByKey(ctx, actor, key, value, dst)
	end(err)
	return id, err
}

func (t *tracedClient) query(ctx context.Context, actor string, witness proto.Message, filter map[string]any) ([]queriedNode, error) {
	ctx, end := observability.StartClient(ctx, "entdb.query", entAttrs(actor, witness, "")...)
	rows, err := t.inner.query(ctx, actor, witness, filter)
	end(err)
	return rows, err
}

func (t *tracedClient) create(ctx context.Context, actor string, msg proto.Message) (string, error) {
	ctx, end := observability.StartClient(ctx, "entdb.create", entAttrs(actor, msg, "")...)
	id, err := t.inner.create(ctx, actor, msg)
	end(err)
	return id, err
}

func (t *tracedClient) update(ctx context.Context, actor string, nodeID string, msg proto.Message) error {
	ctx, end := observability.StartClient(ctx, "entdb.update", entAttrs(actor, msg, nodeID)...)
	err := t.inner.update(ctx, actor, nodeID, msg)
	end(err)
	return err
}

func (t *tracedClient) delete(ctx context.Context, actor string, witness proto.Message, nodeID string) error {
	ctx, end := observability.StartClient(ctx, "entdb.delete", entAttrs(actor, witness, nodeID)...)
	err := t.inner.delete(ctx, actor, witness, nodeID)
	end(err)
	return err
}

func (t *tracedClient) deleteExpired(ctx context.Context, actor string, witness proto.Message, beforeMs int64, limit int) (int, error) {
	attrs := append(entAttrs(actor, witness, ""),
		attribute.Int64("entdb.before_ms", beforeMs),
		attribute.Int("entdb.limit", limit),
	)
	ctx, end := observability.StartClient(ctx, "entdb.deleteExpired", attrs...)
	deleted, err := t.inner.deleteExpired(ctx, actor, witness, beforeMs, limit)
	end(err)
	return deleted, err
}

func (t *tracedClient) ensureUserTenantMember(ctx context.Context, userID, emailAddr, name, role string) error {
	ctx, end := observability.StartClient(ctx, "entdb.ensureUserTenantMember",
		attribute.String("entdb.actor", systemActor),
		attribute.String("entdb.user_id", userID),
		attribute.String("entdb.role", role),
	)
	err := t.inner.ensureUserTenantMember(ctx, userID, emailAddr, name, role)
	end(err)
	return err
}

func (t *tracedRawClient) rawUpdate(ctx context.Context, actor string, typeID int, nodeID string, patch map[string]any) error {
	ctx, end := observability.StartClient(ctx, "entdb.rawUpdate",
		attribute.String("entdb.actor", actor),
		attribute.Int("entdb.type_id", typeID),
		attribute.String("entdb.node_id", nodeID),
	)
	err := t.raw.rawUpdate(ctx, actor, typeID, nodeID, patch)
	end(err)
	return err
}

func entAttrs(actor string, msg proto.Message, nodeID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("entdb.actor", actor),
	}
	if msg != nil {
		attrs = append(attrs, attribute.String("entdb.message_type", fmt.Sprintf("%T", msg)))
	}
	if nodeID != "" {
		attrs = append(attrs, attribute.String("entdb.node_id", nodeID))
	}
	return attrs
}
