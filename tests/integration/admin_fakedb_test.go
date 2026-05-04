//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

// adminFakeDB is a minimal in-memory implementation of service.DB used
// only by integration tests that exercise AdminService directly (e.g.
// the invitation-email regression test). It mirrors fakeDB in the
// service package — kept here because that one is in _test.go and not
// importable across packages.
type adminFakeDB struct {
	mu    sync.Mutex
	nodes map[string]*entdb.Node
	edges []*entdb.Edge
	seq   int64
}

func newAdminFakeDB() *adminFakeDB {
	return &adminFakeDB{nodes: make(map[string]*entdb.Node)}
}

const (
	adminTypeUser = 1

	adminUfEmail  = "1"
	adminUfName   = "2"
	adminUfRole   = "3"
	adminUfStatus = "11"
)

func (f *adminFakeDB) nextID() string {
	f.seq++
	return fmt.Sprintf("afdb-%d", f.seq)
}

func (f *adminFakeDB) addUser(id, email, name, role, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &entdb.Node{
		NodeID: id, TypeID: adminTypeUser,
		Payload: map[string]any{
			adminUfEmail: email, adminUfName: name,
			adminUfRole: role, adminUfStatus: status,
		},
	}
}

func (f *adminFakeDB) GetNode(_ context.Context, _, _ string, typeID int, nodeID string) (*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[nodeID]
	if !ok || n.TypeID != typeID {
		return nil, nil
	}
	return n, nil
}

func (f *adminFakeDB) QueryNodes(_ context.Context, _, _ string, typeID int, filter map[string]any) ([]*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entdb.Node
	for _, n := range f.nodes {
		if n.TypeID != typeID {
			continue
		}
		match := true
		for k, v := range filter {
			pv, ok := n.Payload[k]
			if !ok || fmt.Sprint(pv) != fmt.Sprint(v) {
				match = false
				break
			}
		}
		if match {
			out = append(out, n)
		}
	}
	return out, nil
}

func (f *adminFakeDB) ExecuteAtomic(_ context.Context, _, _, _ string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var created []string
	for _, op := range ops {
		switch op.Type {
		case entdb.OpCreateNode:
			id := f.nextID()
			f.nodes[id] = &entdb.Node{
				NodeID: id, TypeID: op.TypeID,
				Payload: copyPayload(op.Data),
			}
			created = append(created, id)
		case entdb.OpUpdateNode:
			n, ok := f.nodes[op.NodeID]
			if ok && n.TypeID == op.TypeID {
				for k, v := range op.Patch {
					n.Payload[k] = v
				}
			}
		case entdb.OpDeleteNode:
			delete(f.nodes, op.NodeID)
		}
	}
	return &entdb.CommitResult{Success: true, Applied: true, CreatedNodeIDs: created}, nil
}

func (f *adminFakeDB) GetEdgesFrom(_ context.Context, _, _, fromNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entdb.Edge
	for _, e := range f.edges {
		if e.EdgeTypeID == edgeTypeID && e.FromNodeID == fromNodeID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *adminFakeDB) SearchNodes(_ context.Context, _, _ string, typeID int, query string) ([]*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := strings.ToLower(query)
	var out []*entdb.Node
	for _, n := range f.nodes {
		if n.TypeID != typeID {
			continue
		}
		for _, v := range n.Payload {
			if s, ok := v.(string); ok && strings.Contains(strings.ToLower(s), q) {
				out = append(out, n)
				break
			}
		}
	}
	return out, nil
}

func copyPayload(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

var _ service.DB = (*adminFakeDB)(nil)
