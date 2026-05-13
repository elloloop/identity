//go:build integration

package integration

import (
	"context"
	"sync"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

// RecordingDB is a service.DB / audit.NodeWriter implementation that
// captures every ExecuteAtomic call so integration tests can assert
// audit events were written. All other methods return
// service.ErrServiceUnavailable, matching service.StubDB — the binary
// only writes audit events through ExecuteAtomic, so this is enough
// to exercise the audit-logging code path.
type RecordingDB struct {
	mu     sync.Mutex
	events []AuditCall
}

// AuditCall captures the parameters of one ExecuteAtomic call. The
// audit.Logger writes a single CreateNode operation per event with
// the AuditEvent type ID (26) and field-id-keyed data.
type AuditCall struct {
	TenantID string
	Actor    string
	Ops      []entdb.Operation
}

// NewRecordingDB returns an empty RecordingDB.
func NewRecordingDB() *RecordingDB { return &RecordingDB{} }

// Events returns a copy of every captured ExecuteAtomic invocation.
func (d *RecordingDB) Events() []AuditCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]AuditCall, len(d.events))
	copy(out, d.events)
	return out
}

// CountByEventType returns the number of recorded events whose first
// op carries field "1" (event_type) equal to the given value. The
// audit.Logger always uses field "1" for event_type.
func (d *RecordingDB) CountByEventType(eventType string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, e := range d.events {
		if len(e.Ops) == 0 {
			continue
		}
		v, ok := e.Ops[0].Data["1"]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && s == eventType {
			n++
		}
	}
	return n
}

// ExecuteAtomic records the call and returns a successful no-op
// result. Returning success keeps audit logger logs at the success
// level, mirroring real EntDB behaviour.
func (d *RecordingDB) ExecuteAtomic(_ context.Context, tenantID, actor string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	d.mu.Lock()
	cp := make([]entdb.Operation, len(ops))
	copy(cp, ops)
	d.events = append(d.events, AuditCall{
		TenantID: tenantID,
		Actor:    actor,
		Ops:      cp,
	})
	d.mu.Unlock()
	return &entdb.CommitResult{}, nil
}

// The remaining methods are unused by the integration suite but must
// satisfy service.DB. They mirror service.StubDB's "service unavailable"
// behaviour so any accidental call surfaces clearly.

func (d *RecordingDB) GetNode(context.Context, string, string, int, string) (*entdb.Node, error) {
	return nil, service.ErrServiceUnavailable
}

func (d *RecordingDB) QueryNodes(context.Context, string, string, int, map[string]any) ([]*entdb.Node, error) {
	return nil, service.ErrServiceUnavailable
}

func (d *RecordingDB) GetEdgesFrom(context.Context, string, string, string, int) ([]*entdb.Edge, error) {
	return nil, service.ErrServiceUnavailable
}

func (d *RecordingDB) GetEdgesTo(context.Context, string, string, string, int) ([]*entdb.Edge, error) {
	return nil, service.ErrServiceUnavailable
}

func (d *RecordingDB) SearchNodes(context.Context, string, string, int, string) ([]*entdb.Node, error) {
	return nil, service.ErrServiceUnavailable
}

// compile-time interface assertion
var _ service.DB = (*RecordingDB)(nil)
