package service

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// projectPartitionedDB is a postgres-shaped DB fake for the audit project-scope
// regression: it implements WithProject (binds a project and IGNORES the
// per-call tenant argument, exactly like internal/repo/postgres.pgRepository),
// and stores every node under the bound project. A request that resolves to
// project A therefore writes and reads only A's partition. WithProject siblings
// share one backing store so the boot writer and a rebound writer agree.
type projectPartitionedDB struct {
	// Repository is embedded only to satisfy the interface WithProject must
	// return; none of its methods are exercised by the audit path (audit
	// reads/writes go through the DB methods below), so it is left nil and any
	// stray call panics loudly rather than passing silently.
	Repository

	mu      *sync.Mutex
	byProj  map[string]map[string]*entdb.Node // projectID -> nodeID -> node
	seq     *int64
	boundTo string // project this handle is bound to ("" before WithProject)
}

func newProjectPartitionedDB() *projectPartitionedDB {
	var seq int64
	return &projectPartitionedDB{
		mu:     &sync.Mutex{},
		byProj: map[string]map[string]*entdb.Node{},
		seq:    &seq,
	}
}

func (d *projectPartitionedDB) WithProject(projectID string) Repository {
	return &projectPartitionedDB{Repository: d.Repository, mu: d.mu, byProj: d.byProj, seq: d.seq, boundTo: projectID}
}

func (d *projectPartitionedDB) partition() map[string]*entdb.Node {
	p, ok := d.byProj[d.boundTo]
	if !ok {
		p = map[string]*entdb.Node{}
		d.byProj[d.boundTo] = p
	}
	return p
}

// seedUser inserts a user node directly into projectID's partition.
func (d *projectPartitionedDB) seedUser(projectID, id, role string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.byProj[projectID]
	if !ok {
		p = map[string]*entdb.Node{}
		d.byProj[projectID] = p
	}
	p[id] = &entdb.Node{NodeID: id, TypeID: typeUser, Payload: map[string]any{ufRole: role}}
}

func (d *projectPartitionedDB) GetNode(_ context.Context, _, _ string, typeID int, nodeID string) (*entdb.Node, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, ok := d.partition()[nodeID]
	if !ok || n.TypeID != typeID {
		return nil, nil
	}
	return n, nil
}

func (d *projectPartitionedDB) QueryNodes(_ context.Context, _, _ string, typeID int, filter map[string]any) ([]*entdb.Node, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*entdb.Node
	for _, n := range d.partition() {
		if n.TypeID != typeID {
			continue
		}
		if fakeMatchFilter(n.Payload, filter) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (d *projectPartitionedDB) ExecuteAtomic(_ context.Context, _, _ string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var created []string
	for _, op := range ops {
		if op.Type != entdb.OpCreateNode {
			continue
		}
		*d.seq++
		id := op.NodeID
		if id == "" {
			id = "ppdb-node-" + strconv.FormatInt(*d.seq, 10)
		}
		d.partition()[id] = &entdb.Node{NodeID: id, TypeID: op.TypeID, Payload: fdbCopyMap(op.Data)}
		created = append(created, id)
	}
	return &entdb.CommitResult{Success: true, Applied: true, CreatedNodeIDs: created}, nil
}

func (d *projectPartitionedDB) GetEdgesFrom(context.Context, string, string, string, int) ([]*entdb.Edge, error) {
	return nil, nil
}

func (d *projectPartitionedDB) GetEdgesTo(context.Context, string, string, string, int) ([]*entdb.Edge, error) {
	return nil, nil
}

func (d *projectPartitionedDB) SearchNodes(context.Context, string, string, int, string) ([]*entdb.Node, error) {
	return nil, nil
}

func (d *projectPartitionedDB) RegisterUserInTenant(context.Context, string, string, string, string, string) error {
	return nil
}

// auditLoggerForDB builds an audit.Logger wired exactly as internal/app wires
// it: its ProjectScoper resolves the request's project from the ProjectScope
// and rebinds the writer via service.ScopedDB, so a write lands under the
// request's project.
func auditLoggerForDB(db DB, defaultProjectID string) *audit.Logger {
	return audit.NewLogger(db, defaultProjectID, zap.NewNop()).
		WithProjectScoper(func(ctx context.Context) (audit.NodeWriter, string) {
			scoped, projectID := ScopedDB(ctx, db, defaultProjectID)
			if scoped == nil {
				return nil, projectID
			}
			return scoped, projectID
		})
}

// TestAuditEvent_RoundTripsUnderRequestProject is the service-level regression
// for issue #21: an audit event logged under a request scoped to project A is
// readable via ListAuditEvents scoped to A, and is NOT visible from project B.
// Before the fix, writes were pinned to the boot-default project while reads
// were per-request, so the event was unreadable from A entirely.
func TestAuditEvent_RoundTripsUnderRequestProject(t *testing.T) {
	const (
		defaultProj = "default"
		projA       = "project-a"
		projB       = "project-b"
		adminID     = "admin-1"
	)

	db := newProjectPartitionedDB()
	// An admin must exist in BOTH partitions so ListAuditEvents (which gates on
	// an admin role lookup in the request's project) is authorized from either.
	db.seedUser(projA, adminID, "admin")
	db.seedUser(projB, adminID, "admin")

	auditLog := auditLoggerForDB(db, defaultProj)
	svc := NewProfileService(nil, db, defaultProj, auditLog, zap.NewNop())

	// Log a password-change audit event under a request scoped to project A.
	ctxA := WithProjectScope(context.Background(), &ProjectScope{ProjectID: projA})
	svc.audit.Log(ctxA, audit.EventPasswordChanged, audit.WithActor(adminID))

	// Read back from project A: the event must be present.
	eventsA, _, err := svc.ListAuditEvents(ctxA, adminID, "", "", 0, 0, "", 0)
	if err != nil {
		t.Fatalf("ListAuditEvents(A): %v", err)
	}
	if len(eventsA) != 1 {
		t.Fatalf("project A: expected 1 audit event, got %d", len(eventsA))
	}
	if eventsA[0].EventType != string(audit.EventPasswordChanged) {
		t.Errorf("project A: unexpected event type %q", eventsA[0].EventType)
	}

	// Read from project B: the event must NOT leak across the project boundary.
	ctxB := WithProjectScope(context.Background(), &ProjectScope{ProjectID: projB})
	eventsB, _, err := svc.ListAuditEvents(ctxB, adminID, "", "", 0, 0, "", 0)
	if err != nil {
		t.Fatalf("ListAuditEvents(B): %v", err)
	}
	if len(eventsB) != 0 {
		t.Fatalf("project B: expected 0 audit events, got %d", len(eventsB))
	}
}
