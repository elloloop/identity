package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/elloloop/identity/internal/graph"
)

// fakeDB is an in-memory implementation of the DB interface for tests
// of AdminService, GroupService, HelpService, and ProfileService.
type fakeDB struct {
	mu    sync.Mutex
	nodes map[string]*graph.Node // nodeID -> node
	edges []*graph.Edge
	seq   int64
	err   error // if set, all calls return this error

	// lastEdgesFromActor / lastEdgesToActor record the actor passed to the
	// most recent GetEdgesFrom / GetEdgesTo call, so tests can assert
	// cross-user reads use tenantAdminActor (a per-user actor would silently
	// return zero rows on a graph backend).
	lastEdgesFromActor string
	lastEdgesToActor   string
}

func newFakeDB() *fakeDB {
	return &fakeDB{nodes: make(map[string]*graph.Node)}
}

func (f *fakeDB) nextID() string {
	f.seq++
	return fmt.Sprintf("fdb-node-%d", f.seq)
}

func (f *fakeDB) GetNode(_ context.Context, _, _ string, typeID int, nodeID string) (*graph.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	n, ok := f.nodes[nodeID]
	if !ok || n.TypeID != typeID {
		return nil, nil
	}
	return n, nil
}

func (f *fakeDB) QueryNodes(_ context.Context, _, _ string, typeID int, filter map[string]any) ([]*graph.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var result []*graph.Node
	for _, n := range f.nodes {
		if n.TypeID != typeID {
			continue
		}
		if fakeMatchFilter(n.Payload, filter) {
			result = append(result, n)
		}
	}
	return result, nil
}

func fakeMatchFilter(payload map[string]any, filter map[string]any) bool {
	if filter == nil {
		return true
	}
	for k, v := range filter {
		pv, ok := payload[k]
		if !ok {
			return false
		}
		if fmt.Sprint(pv) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}

func (f *fakeDB) ExecuteAtomic(_ context.Context, _, _ string, ops []graph.Operation) (*graph.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var createdIDs []string
	for _, op := range ops {
		switch op.Type {
		case graph.OpCreateNode:
			id := f.nextID()
			f.nodes[id] = &graph.Node{
				NodeID:  id,
				TypeID:  op.TypeID,
				Payload: fdbCopyMap(op.Data),
			}
			createdIDs = append(createdIDs, id)
		case graph.OpUpdateNode:
			n, ok := f.nodes[op.NodeID]
			if ok && n.TypeID == op.TypeID {
				for k, v := range op.Patch {
					n.Payload[k] = v
				}
			}
		case graph.OpDeleteNode:
			delete(f.nodes, op.NodeID)
		case graph.OpCreateEdge:
			f.edges = append(f.edges, &graph.Edge{
				EdgeTypeID: op.EdgeTypeID,
				FromNodeID: op.FromNodeID,
				ToNodeID:   op.ToNodeID,
			})
		case graph.OpDeleteEdge:
			var keep []*graph.Edge
			for _, e := range f.edges {
				if e.EdgeTypeID != op.EdgeTypeID || e.FromNodeID != op.FromNodeID || e.ToNodeID != op.ToNodeID {
					keep = append(keep, e)
				}
			}
			f.edges = keep
		}
	}
	return &graph.CommitResult{Success: true, Applied: true, CreatedNodeIDs: createdIDs}, nil
}

func (f *fakeDB) GetEdgesFrom(_ context.Context, _, actor, fromNodeID string, edgeTypeID int) ([]*graph.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastEdgesFromActor = actor
	if f.err != nil {
		return nil, f.err
	}
	var result []*graph.Edge
	for _, e := range f.edges {
		if e.EdgeTypeID == edgeTypeID && e.FromNodeID == fromNodeID {
			result = append(result, e)
		}
	}
	return result, nil
}

func (f *fakeDB) GetEdgesTo(_ context.Context, _, actor, toNodeID string, edgeTypeID int) ([]*graph.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastEdgesToActor = actor
	if f.err != nil {
		return nil, f.err
	}
	var result []*graph.Edge
	for _, e := range f.edges {
		if e.EdgeTypeID == edgeTypeID && e.ToNodeID == toNodeID {
			result = append(result, e)
		}
	}
	return result, nil
}

func (f *fakeDB) SearchNodes(_ context.Context, _, _ string, typeID int, query string) ([]*graph.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	q := strings.ToLower(query)
	var result []*graph.Node
	for _, n := range f.nodes {
		if n.TypeID != typeID {
			continue
		}
		for _, v := range n.Payload {
			if s, ok := v.(string); ok && strings.Contains(strings.ToLower(s), q) {
				result = append(result, n)
				break
			}
		}
	}
	return result, nil
}

// RegisterUserInTenant is a no-op on the in-memory fake. The fake
// has no global registry / tenant-membership model — every node lives
// in a single flat store.
func (f *fakeDB) RegisterUserInTenant(_ context.Context, _, _, _, _, _ string) error {
	return nil
}

// ── fakeDB seed helpers ───────────────────────────────────────────────

func (f *fakeDB) addUser(id, email, name, role, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &graph.Node{
		NodeID: id,
		TypeID: typeUser,
		Payload: map[string]any{
			ufEmail:  email,
			ufName:   name,
			ufRole:   role,
			ufStatus: status,
		},
	}
}

func (f *fakeDB) addUserWithPassword(id, email, name, role, status, pwHash string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &graph.Node{
		NodeID: id,
		TypeID: typeUser,
		Payload: map[string]any{
			ufEmail:        email,
			ufName:         name,
			ufRole:         role,
			ufStatus:       status,
			ufPasswordHash: pwHash,
		},
	}
}

func (f *fakeDB) addHelpRequest(id, email, status string, createdAt int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &graph.Node{
		NodeID: id,
		TypeID: typeAdminHelpReq,
		Payload: map[string]any{
			hfEmail:     email,
			hfStatus:    status,
			hfCreatedAt: createdAt,
		},
	}
}

func (f *fakeDB) addRefreshToken(id, userID string, expiresAt int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &graph.Node{
		NodeID: id,
		TypeID: typeRefreshToken,
		Payload: map[string]any{
			rfUserID:    userID,
			rfExpiresAt: expiresAt,
			rfCreatedAt: nowMs(),
		},
	}
}

func (f *fakeDB) addPasskey(id, userID, credentialID, deviceName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &graph.Node{
		NodeID: id,
		TypeID: typePasskeyCredCred,
		Payload: map[string]any{
			pkfCredentialID: credentialID,
			pkfUserID:       userID,
			pkfDeviceName:   deviceName,
		},
	}
}

func (f *fakeDB) addGroup(id, name, description string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[id] = &graph.Node{
		NodeID: id,
		TypeID: typeWorkingGroup,
		Payload: map[string]any{
			gfName:        name,
			gfDescription: description,
		},
	}
}

func fdbCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
