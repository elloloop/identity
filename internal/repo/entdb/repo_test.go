package entdb_test

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/repo/conformance"
	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	"github.com/elloloop/identity/internal/service"
)

// fakeClient is an in-memory entdbrepo.Client that records every
// call. It models enough of the EntDB semantics for the conformance
// suite — a node store keyed by node id, primitive uniqueness on the
// caller-supplied filter map, and atomic-commit semantics for
// ExecuteAtomic. Filter equality is exact-match on a single
// (key, value) pair, which is what the entdb repo emits.
//
// fakeClient deliberately does NOT implement the SDK's
// MongoDB-style operator vocabulary — the production driver passes
// only equality filters today.
type fakeClient struct {
	mu    sync.Mutex
	store map[string]*sdk.Node
	seq   int64
}

func newFakeClient() *fakeClient {
	return &fakeClient{store: make(map[string]*sdk.Node)}
}

func (f *fakeClient) nextID() string {
	f.seq++
	return fmt.Sprintf("fake-%d", f.seq)
}

func (f *fakeClient) GetNode(_ context.Context, _ string, _ string, typeID int, nodeID string) (*sdk.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.store[nodeID]
	if !ok || n.TypeID != typeID {
		return nil, nil
	}
	cp := *n
	cp.Payload = clonePayload(n.Payload)
	return &cp, nil
}

func (f *fakeClient) QueryNodes(_ context.Context, _ string, _ string, typeID int, filter map[string]any) ([]*sdk.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*sdk.Node
	for _, n := range f.store {
		if n.TypeID != typeID {
			continue
		}
		match := true
		for k, want := range filter {
			got, ok := n.Payload[k]
			if !ok || !sameValue(got, want) {
				match = false
				break
			}
		}
		if match {
			cp := *n
			cp.Payload = clonePayload(n.Payload)
			out = append(out, &cp)
		}
	}
	return out, nil
}

// uniqueFields is the set of (typeID → field-id) pairs that the
// production schema annotates with (entdb.field).unique = true. The
// fake enforces them so the conformance suite exercises the same
// reject-duplicate semantics the real server would.
var uniqueFields = map[int][]string{
	1:  {"1"},      // User.email
	5:  {"1"},      // RefreshToken.token_hash
	19: {"1"},      // PasswordResetToken.token_hash
	20: {"1"},      // PasskeyCredential.credential_id
	21: {"1"},      // PasskeyChallenge.challenge
	22: {"1"},      // QrLoginSession.session_id
	24: {"2"},      // RecoveryCode.code_hash
	25: {"1"},      // LoginChallenge.challenge_id
	27: {"1", "2"}, // UserInvitation.token_hash, email
	29: {"1"},      // EmailVerificationToken.token_hash
	30: {"1"},      // EmailChangeToken.token_hash
	// OAuthIdentity (31) has composite (provider, provider_user_id)
	// uniqueness — service-layer enforced. The fake handles it
	// specially below.
}

func (f *fakeClient) ExecuteAtomic(_ context.Context, _ string, _ string, _ string, ops []sdk.Operation) (*sdk.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	created := make([]string, 0, len(ops))
	for _, op := range ops {
		switch op.Type {
		case sdk.OpCreateNode:
			// Enforce schema-declared uniqueness. The legacy
			// repo emits payloads keyed by field-id-as-decimal-
			// string; matching against op.Data is exact.
			for _, fid := range uniqueFields[op.TypeID] {
				want, ok := op.Data[fid]
				if !ok {
					continue
				}
				for _, n := range f.store {
					if n.TypeID != op.TypeID {
						continue
					}
					if got, ok := n.Payload[fid]; ok && sameValue(got, want) {
						return nil, fmt.Errorf("entdb: unique constraint violated on type_id=%d field_id=%s", op.TypeID, fid)
					}
				}
			}
			// OAuthIdentity composite (provider, provider_user_id).
			if op.TypeID == 31 {
				prov, _ := op.Data["2"].(string)
				sub, _ := op.Data["3"].(string)
				if prov != "" && sub != "" {
					for _, n := range f.store {
						if n.TypeID != 31 {
							continue
						}
						if p, _ := n.Payload["2"].(string); p == prov {
							if s, _ := n.Payload["3"].(string); s == sub {
								return nil, fmt.Errorf("entdb: composite unique violated (%s, %s)", prov, sub)
							}
						}
					}
				}
			}
			id := f.nextID()
			f.store[id] = &sdk.Node{
				NodeID:  id,
				TypeID:  op.TypeID,
				Payload: clonePayload(op.Data),
			}
			created = append(created, id)
		case sdk.OpUpdateNode:
			n, ok := f.store[op.NodeID]
			if !ok {
				return &sdk.CommitResult{Error: fmt.Sprintf("node %s missing", op.NodeID)}, nil
			}
			// Both the legacy code and the new Plan-marshalled
			// payload land in op.Patch; tolerate op.Data too in
			// case a caller routed it that way.
			merge(n.Payload, op.Patch)
			merge(n.Payload, op.Data)
		case sdk.OpDeleteNode:
			delete(f.store, op.NodeID)
		case sdk.OpCreateEdge, sdk.OpDeleteEdge:
			// edges are not exercised by the conformance suite.
		}
	}
	return &sdk.CommitResult{Success: true, Applied: true, CreatedNodeIDs: created}, nil
}

func (f *fakeClient) GetEdgesFrom(context.Context, string, string, string, int) ([]*sdk.Edge, error) {
	return nil, nil
}

func (f *fakeClient) SearchNodes(context.Context, string, string, int, string) ([]*sdk.Node, error) {
	return nil, nil
}

func clonePayload(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

// sameValue compares filter and payload values tolerantly so that an
// int64 from one side and a json-decoded float from the other still
// match.
func sameValue(got, want any) bool {
	if got == want {
		return true
	}
	switch g := got.(type) {
	case string:
		w, ok := want.(string)
		return ok && g == w
	case int64:
		switch w := want.(type) {
		case int64:
			return g == w
		case int:
			return g == int64(w)
		case float64:
			return g == int64(w)
		case string:
			n, err := strconv.ParseInt(w, 10, 64)
			return err == nil && g == n
		}
	case bool:
		w, ok := want.(bool)
		return ok && g == w
	}
	return false
}

// TestEntDBConformance runs the driver-agnostic Repository
// conformance suite against the entdb driver wired with an in-memory
// fake Client. Production wiring uses NewSDKClient(*sdk.DbClient);
// this test bypasses the gRPC connection by injecting a fake
// implementation of the Client interface directly via
// NewRepositoryWithClient.
func TestEntDBConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, func(_ *testing.T) service.Repository {
		return entdbrepo.NewRepositoryWithClient(newFakeClient(), "test-tenant")
	})
}
