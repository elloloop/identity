package repo

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

// ── fakeClient ─────────────────────────────────────────────────────
//
// fakeClient is an in-memory entdbClient that records every call and
// can be configured to return canned responses or errors. It is the
// single test seam for the repo package — both NewEntDBRepository
// and NewDBAdapter accept an entdbClient (via the package-private
// constructors), so tests never need a live gRPC connection.

type fakeCall struct {
	method   string
	tenantID string
	actor    string
	typeID   int
	nodeID   string
	filter   map[string]any
	ops      []entdb.Operation
	query    string
}

type fakeClient struct {
	mu sync.Mutex

	// fault injection — all set to nil/zero by default for the happy path.
	getErr     error
	queryErr   error
	executeErr error
	edgesErr   error
	searchErr  error

	// canned responses
	getNode    *entdb.Node
	queryNodes []*entdb.Node
	executeRes *entdb.CommitResult
	edges      []*entdb.Edge
	searchRes  []*entdb.Node

	// recorded calls
	calls []fakeCall

	// node store: nodes keyed by node id, used when executeRes is nil
	// so tests can rely on a built-in "create then read" round-trip.
	store map[string]*entdb.Node
	seq   int64
}

func newFakeClient() *fakeClient {
	return &fakeClient{store: make(map[string]*entdb.Node)}
}

func (f *fakeClient) record(c fakeCall) {
	f.calls = append(f.calls, c)
}

func (f *fakeClient) GetNode(_ context.Context, tenantID, actor string, typeID int, nodeID string) (*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeCall{method: "GetNode", tenantID: tenantID, actor: actor, typeID: typeID, nodeID: nodeID})
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getNode != nil {
		return f.getNode, nil
	}
	if n, ok := f.store[nodeID]; ok && n.TypeID == typeID {
		return n, nil
	}
	return nil, nil
}

func (f *fakeClient) QueryNodes(_ context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeCall{method: "QueryNodes", tenantID: tenantID, actor: actor, typeID: typeID, filter: cloneMap(filter)})
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	if f.queryNodes != nil {
		return f.queryNodes, nil
	}
	var out []*entdb.Node
	for _, n := range f.store {
		if n.TypeID != typeID {
			continue
		}
		match := true
		for k, want := range filter {
			if got, ok := n.Payload[k]; !ok || !sameValue(got, want) {
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

func (f *fakeClient) ExecuteAtomic(_ context.Context, tenantID, actor, idem string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeCall{method: "ExecuteAtomic", tenantID: tenantID, actor: actor, ops: cloneOps(ops)})
	if f.executeErr != nil {
		return nil, f.executeErr
	}
	if f.executeRes != nil {
		return f.executeRes, nil
	}
	// Default behaviour: apply ops to the in-memory store.
	res := &entdb.CommitResult{Success: true, Applied: true}
	for _, op := range ops {
		switch op.Type {
		case entdb.OpCreateNode:
			f.seq++
			id := "n-" + strconv.FormatInt(f.seq, 10)
			payload := cloneMap(op.Data)
			f.store[id] = &entdb.Node{NodeID: id, TypeID: op.TypeID, Payload: payload}
			res.CreatedNodeIDs = append(res.CreatedNodeIDs, id)
		case entdb.OpUpdateNode:
			n, ok := f.store[op.NodeID]
			if !ok {
				return nil, errors.New("fakeClient: update of missing node " + op.NodeID)
			}
			for k, v := range op.Patch {
				n.Payload[k] = v
			}
		case entdb.OpDeleteNode:
			delete(f.store, op.NodeID)
		}
	}
	return res, nil
}

func (f *fakeClient) GetEdgesFrom(_ context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeCall{method: "GetEdgesFrom", tenantID: tenantID, actor: actor, nodeID: fromNodeID, typeID: edgeTypeID})
	return f.edges, f.edgesErr
}

func (f *fakeClient) SearchNodes(_ context.Context, tenantID, actor string, typeID int, query string) ([]*entdb.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeCall{method: "SearchNodes", tenantID: tenantID, actor: actor, typeID: typeID, query: query})
	return f.searchRes, f.searchErr
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneOps(ops []entdb.Operation) []entdb.Operation {
	if ops == nil {
		return nil
	}
	out := make([]entdb.Operation, len(ops))
	copy(out, ops)
	return out
}

func sameValue(a, b any) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	}
	// Fall back to %v comparison via fmt-free path: int kinds.
	if ai, ok := toInt64Strict(a); ok {
		if bi, ok := toInt64Strict(b); ok {
			return ai == bi
		}
	}
	return false
}

func toInt64Strict(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

func newRepo(t *testing.T) (*entRepository, *fakeClient) {
	t.Helper()
	c := newFakeClient()
	return newEntRepositoryFromClient(c, "tenant-1"), c
}

func ctx() context.Context { return context.Background() }

// ── Users ─────────────────────────────────────────────────────────

func TestCreateAndGetUser(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)

	u := &service.User{
		Email:        "alice@example.com",
		Name:         "Alice",
		Role:         "member",
		Status:       "active",
		PasswordHash: "hash",
	}
	id, err := r.CreateUser(ctx(), u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if id == "" {
		t.Fatalf("CreateUser returned empty id")
	}

	got, err := r.GetUser(ctx(), id)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got == nil {
		t.Fatalf("GetUser returned nil")
	}
	if got.Email != "alice@example.com" || got.Role != "member" || got.Status != "active" {
		t.Fatalf("unexpected user round-trip: %+v", got)
	}
	// At least 2 calls (create + get) on tenant-1.
	if len(c.calls) < 2 {
		t.Fatalf("expected >=2 calls, got %d", len(c.calls))
	}
	for _, call := range c.calls {
		if call.tenantID != "tenant-1" {
			t.Fatalf("call %s tenant=%q want tenant-1", call.method, call.tenantID)
		}
	}
}

func TestGetUser_Empty(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	got, err := r.GetUser(ctx(), "")
	if err != nil || got != nil {
		t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
	}
}

func TestFindUserByEmail_NotFound(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	got, err := r.FindUserByEmail(ctx(), "nobody@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestFindUserByEmail_Found(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreateUser(ctx(), &service.User{Email: "bob@example.com", Name: "Bob"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := r.FindUserByEmail(ctx(), "bob@example.com")
	if err != nil || got == nil {
		t.Fatalf("FindUserByEmail returned (%v,%v)", got, err)
	}
	if got.ID != id {
		t.Fatalf("FindUserByEmail id=%q want %q", got.ID, id)
	}
}

func TestFindUserByEmail_QueryError(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("boom")
	if _, err := r.FindUserByEmail(ctx(), "x@x"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestCreateUser_NilRecord(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if _, err := r.CreateUser(ctx(), nil); err == nil {
		t.Fatalf("expected error on nil user")
	}
}

func TestCreateUser_ExecuteError(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.executeErr = errors.New("rate limit")
	if _, err := r.CreateUser(ctx(), &service.User{Email: "x@x", Name: "x"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestUpdateUser_TranslatesFields(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	id, err := r.CreateUser(ctx(), &service.User{Email: "carol@example.com", Name: "Carol"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	err = r.UpdateUser(ctx(), id, map[string]any{
		"name":               "Carol R",
		"failed_login_count": 3,
		"locked_until":       int64(123),
		"updated_at":         int64(456),
		"unknown_field":      "ignored",
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	// Verify in-store state.
	got, err := r.GetUser(ctx(), id)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Name != "Carol R" || got.FailedLoginCount != 3 || got.LockedUntil != 123 {
		t.Fatalf("unexpected user after update: %+v", got)
	}
	// Make sure the patch sent to entdb was keyed by field id.
	last := c.calls[len(c.calls)-2] // ExecuteAtomic for the update; last is GetNode
	if last.method != "ExecuteAtomic" {
		t.Fatalf("expected ExecuteAtomic call, got %s", last.method)
	}
	if len(last.ops) != 1 || last.ops[0].Type != entdb.OpUpdateNode {
		t.Fatalf("unexpected ops: %+v", last.ops)
	}
	if _, ok := last.ops[0].Patch[ufName]; !ok {
		t.Fatalf("patch missing %q (name field id)", ufName)
	}
	if _, ok := last.ops[0].Patch["name"]; ok {
		t.Fatalf("patch should not contain raw 'name' key — must use field id")
	}
}

func TestUpdateUser_EmptyFieldsNoOp(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	if err := r.UpdateUser(ctx(), "u1", map[string]any{}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if err := r.UpdateUser(ctx(), "u1", map[string]any{"unknown": 1}); err != nil {
		t.Fatalf("UpdateUser unknown: %v", err)
	}
	for _, call := range c.calls {
		if call.method == "ExecuteAtomic" {
			t.Fatalf("unexpected ExecuteAtomic for empty field patch")
		}
	}
}

func TestUpdateUser_MissingID(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if err := r.UpdateUser(ctx(), "", map[string]any{"name": "x"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestUpdateUser_ExecuteError(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.executeErr = errors.New("boom")
	if err := r.UpdateUser(ctx(), "u1", map[string]any{"name": "x"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestSetUserEmailVerified(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, _ := r.CreateUser(ctx(), &service.User{Email: "v@example.com", Name: "V"})
	if err := r.SetUserEmailVerified(ctx(), id, 999); err != nil {
		t.Fatalf("SetUserEmailVerified: %v", err)
	}
	got, _ := r.GetUser(ctx(), id)
	if !got.EmailVerified || got.EmailVerifiedAt != 999 {
		t.Fatalf("email verified not propagated: %+v", got)
	}
}

func TestSetUserEmailVerified_MissingID(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if err := r.SetUserEmailVerified(ctx(), "", 1); err == nil {
		t.Fatalf("expected error")
	}
}

// ── Refresh tokens ────────────────────────────────────────────────

func TestRefreshTokenLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreateRefreshToken(ctx(), &service.RefreshTokenRecord{
		TokenHash:  "hash1",
		UserID:     "u1",
		DeviceInfo: "Chrome on macOS",
		IPAddress:  "1.2.3.4",
		UserAgent:  "Mozilla",
		ExpiresAt:  100,
		CreatedAt:  10,
		LastUsedAt: 10,
	})
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	got, err := r.FindRefreshTokenByHash(ctx(), "hash1")
	if err != nil || got == nil {
		t.Fatalf("FindRefreshTokenByHash: %v %+v", err, got)
	}
	if got.UserID != "u1" || got.NodeID != id {
		t.Fatalf("unexpected token: %+v", got)
	}
	if err := r.DeleteRefreshToken(ctx(), id); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	got, _ = r.FindRefreshTokenByHash(ctx(), "hash1")
	if got != nil {
		t.Fatalf("token not deleted: %+v", got)
	}
}

func TestDeleteRefreshTokensForUser(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	for i := 0; i < 3; i++ {
		_, err := r.CreateRefreshToken(ctx(), &service.RefreshTokenRecord{
			TokenHash: "h" + strconv.Itoa(i), UserID: "u1", ExpiresAt: 1, CreatedAt: 1, LastUsedAt: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := r.DeleteRefreshTokensForUser(ctx(), "u1"); err != nil {
		t.Fatalf("DeleteRefreshTokensForUser: %v", err)
	}
	for i := 0; i < 3; i++ {
		got, _ := r.FindRefreshTokenByHash(ctx(), "h"+strconv.Itoa(i))
		if got != nil {
			t.Fatalf("token %d not deleted", i)
		}
	}
}

func TestDeleteRefreshTokensForUser_NoMatches(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	if err := r.DeleteRefreshTokensForUser(ctx(), "does-not-exist"); err != nil {
		t.Fatal(err)
	}
	// Should issue a query but no commit.
	hadExecute := false
	for _, call := range c.calls {
		if call.method == "ExecuteAtomic" {
			hadExecute = true
		}
	}
	if hadExecute {
		t.Fatalf("expected no ExecuteAtomic when no matches")
	}
}

func TestDeleteRefreshTokensForUser_QueryError(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("boom")
	if err := r.DeleteRefreshTokensForUser(ctx(), "u1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateRefreshToken_NilRecord(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if _, err := r.CreateRefreshToken(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestFindRefreshTokenByHash_Empty(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	got, err := r.FindRefreshTokenByHash(ctx(), "")
	if err != nil || got != nil {
		t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
	}
}

// ── Passkey credentials ───────────────────────────────────────────

func TestPasskeyCredentialLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreatePasskeyCredential(ctx(), &service.PasskeyCredRecord{
		CredentialID: "cid1",
		UserID:       "u1",
		PublicKey:    "pk",
		SignCount:    1,
		DeviceName:   "Phone",
		AAGUID:       "aaa",
		Transports:   "internal",
		CreatedAt:    1,
		LastUsedAt:   1,
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCredential: %v", err)
	}

	got, err := r.GetPasskeyCredentialByCredID(ctx(), "cid1")
	if err != nil || got == nil || got.NodeID != id {
		t.Fatalf("GetPasskeyCredentialByCredID: %v %+v", err, got)
	}
	list, err := r.ListPasskeyCredentials(ctx(), "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPasskeyCredentials: %v len=%d", err, len(list))
	}
	if err := r.UpdatePasskeyCredential(ctx(), id, map[string]any{"sign_count": int64(7), "last_used_at": int64(50), "device_name": "x"}); err != nil {
		t.Fatalf("UpdatePasskeyCredential: %v", err)
	}
	got, _ = r.GetPasskeyCredentialByCredID(ctx(), "cid1")
	if got.SignCount != 7 || got.LastUsedAt != 50 {
		t.Fatalf("update did not persist: %+v", got)
	}
}

func TestPasskeyCredentialEdgeCases(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if list, err := r.ListPasskeyCredentials(ctx(), ""); err != nil || list != nil {
		t.Fatalf("empty user list: %v %+v", err, list)
	}
	if got, err := r.GetPasskeyCredentialByCredID(ctx(), ""); err != nil || got != nil {
		t.Fatalf("empty cred id: %v %+v", err, got)
	}
	if _, err := r.CreatePasskeyCredential(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdatePasskeyCredential(ctx(), "", map[string]any{"sign_count": int64(1)}); err == nil {
		t.Fatal("expected error")
	}
	// no-op patch
	if err := r.UpdatePasskeyCredential(ctx(), "n", map[string]any{"unknown": 1}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestPasskeyCredentialErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("q")
	if _, err := r.ListPasskeyCredentials(ctx(), "u1"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := r.GetPasskeyCredentialByCredID(ctx(), "cid"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if _, err := r.CreatePasskeyCredential(ctx(), &service.PasskeyCredRecord{CredentialID: "x", UserID: "u", PublicKey: "p"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdatePasskeyCredential(ctx(), "n", map[string]any{"sign_count": int64(1)}); err == nil {
		t.Fatal("expected error")
	}
}

// ── Passkey challenges ────────────────────────────────────────────

func TestPasskeyChallengeLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreatePasskeyChallenge(ctx(), &service.PasskeyChallengeRecord{
		Challenge:     "abc",
		UserID:        "u1",
		ChallengeType: "registration",
		ExpiresAt:     5,
		CreatedAt:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetPasskeyChallenge(ctx(), id)
	if err != nil || got == nil || got.Challenge != "abc" {
		t.Fatalf("GetPasskeyChallenge: %v %+v", err, got)
	}
	if err := r.DeletePasskeyChallenge(ctx(), id); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetPasskeyChallenge(ctx(), id)
	if got != nil {
		t.Fatalf("not deleted: %+v", got)
	}
}

func TestPasskeyChallengeEdges(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if got, err := r.GetPasskeyChallenge(ctx(), ""); err != nil || got != nil {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := r.CreatePasskeyChallenge(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeletePasskeyChallenge(ctx(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyChallengeErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.getErr = errors.New("g")
	if _, err := r.GetPasskeyChallenge(ctx(), "n"); err == nil {
		t.Fatal("expected error")
	}
	c.getErr = nil
	c.executeErr = errors.New("e")
	if _, err := r.CreatePasskeyChallenge(ctx(), &service.PasskeyChallengeRecord{Challenge: "c", ChallengeType: "registration"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeletePasskeyChallenge(ctx(), "n"); err == nil {
		t.Fatal("expected error")
	}
}

// ── QR login sessions ─────────────────────────────────────────────

func TestQrSessionLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreateQrLoginSession(ctx(), &service.QrLoginSessionRecord{
		SessionID:     "sid1",
		Status:        "pending",
		NewDeviceInfo: "info",
		ExpiresAt:     100, CreatedAt: 1, UpdatedAt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.FindQrLoginSession(ctx(), "sid1")
	if err != nil || got == nil || got.NodeID != id {
		t.Fatalf("Find: %v %+v", err, got)
	}
	err = r.UpdateQrLoginSession(ctx(), id, map[string]any{
		"status":               "approved",
		"user_id":              "u1",
		"approved_device_info": "phone",
		"updated_at":           int64(99),
		"unknown":              "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = r.FindQrLoginSession(ctx(), "sid1")
	if got.Status != "approved" || got.UserID != "u1" || got.UpdatedAt != 99 {
		t.Fatalf("update not applied: %+v", got)
	}
}

func TestQrSessionEdges(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if got, err := r.FindQrLoginSession(ctx(), ""); err != nil || got != nil {
		t.Fatalf("empty session id: %+v %v", got, err)
	}
	if _, err := r.CreateQrLoginSession(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateQrLoginSession(ctx(), "", map[string]any{"status": "x"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateQrLoginSession(ctx(), "n", map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestQrSessionErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("q")
	if _, err := r.FindQrLoginSession(ctx(), "x"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if _, err := r.CreateQrLoginSession(ctx(), &service.QrLoginSessionRecord{SessionID: "s", Status: "pending"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateQrLoginSession(ctx(), "n", map[string]any{"status": "x"}); err == nil {
		t.Fatal("expected error")
	}
}

// ── TOTP credentials ──────────────────────────────────────────────

func TestTotpCredentialLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreateTotpCredential(ctx(), &service.TotpCredRecord{
		UserID: "u1", SecretEncrypted: "ENC", Verified: false, CreatedAt: 1, LastUsedAt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetTotpCredential(ctx(), "u1")
	if err != nil || got == nil || got.NodeID != id {
		t.Fatalf("GetTotpCredential: %v %+v", err, got)
	}
	if err := r.UpdateTotpCredential(ctx(), id, map[string]any{
		"verified":         true,
		"last_used_at":     int64(123),
		"secret_encrypted": "NEW",
		"unknown":          "x",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetTotpCredential(ctx(), "u1")
	if !got.Verified || got.LastUsedAt != 123 || got.SecretEncrypted != "NEW" {
		t.Fatalf("update not applied: %+v", got)
	}
	if err := r.DeleteTotpCredential(ctx(), id); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetTotpCredential(ctx(), "u1")
	if got != nil {
		t.Fatalf("not deleted: %+v", got)
	}
}

func TestDeleteTotpCredentialsForUser(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	_, _ = r.CreateTotpCredential(ctx(), &service.TotpCredRecord{UserID: "u1", SecretEncrypted: "a"})
	_, _ = r.CreateTotpCredential(ctx(), &service.TotpCredRecord{UserID: "u1", SecretEncrypted: "b"})
	if err := r.DeleteTotpCredentialsForUser(ctx(), "u1"); err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetTotpCredential(ctx(), "u1")
	if got != nil {
		t.Fatalf("not deleted: %+v", got)
	}
	// no-op when no creds exist.
	if err := r.DeleteTotpCredentialsForUser(ctx(), "u1"); err != nil {
		t.Fatal(err)
	}
}

func TestTotpCredentialEdges(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if got, err := r.GetTotpCredential(ctx(), ""); err != nil || got != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := r.CreateTotpCredential(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateTotpCredential(ctx(), "", map[string]any{}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteTotpCredential(ctx(), ""); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteTotpCredentialsForUser(ctx(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestTotpCredentialErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("q")
	if _, err := r.GetTotpCredential(ctx(), "u"); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteTotpCredentialsForUser(ctx(), "u"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if _, err := r.CreateTotpCredential(ctx(), &service.TotpCredRecord{UserID: "u", SecretEncrypted: "s"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateTotpCredential(ctx(), "n", map[string]any{"verified": true}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteTotpCredential(ctx(), "n"); err == nil {
		t.Fatal("expected error")
	}
}

// ── Recovery codes ────────────────────────────────────────────────

func TestRecoveryCodeLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreateRecoveryCode(ctx(), &service.RecoveryCodeRecord{
		UserID: "u1", CodeHash: "ch1", Used: false, CreatedAt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.FindRecoveryCodeByHash(ctx(), "u1", "ch1")
	if err != nil || got == nil || got.NodeID != id {
		t.Fatalf("Find: %v %+v", err, got)
	}
	if err := r.UpdateRecoveryCode(ctx(), id, map[string]any{"used": true, "used_at": int64(50), "unknown": 1}); err != nil {
		t.Fatal(err)
	}
	got, _ = r.FindRecoveryCodeByHash(ctx(), "u1", "ch1")
	if !got.Used || got.UsedAt != 50 {
		t.Fatalf("update not applied: %+v", got)
	}
	if err := r.DeleteRecoveryCodesForUser(ctx(), "u1"); err != nil {
		t.Fatal(err)
	}
	got, _ = r.FindRecoveryCodeByHash(ctx(), "u1", "ch1")
	if got != nil {
		t.Fatalf("not deleted: %+v", got)
	}
}

func TestRecoveryCodeEdges(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if got, err := r.FindRecoveryCodeByHash(ctx(), "", ""); err != nil || got != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := r.CreateRecoveryCode(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateRecoveryCode(ctx(), "", map[string]any{}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteRecoveryCodesForUser(ctx(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCodeErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("q")
	if _, err := r.FindRecoveryCodeByHash(ctx(), "u", "h"); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteRecoveryCodesForUser(ctx(), "u"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if _, err := r.CreateRecoveryCode(ctx(), &service.RecoveryCodeRecord{UserID: "u", CodeHash: "c"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateRecoveryCode(ctx(), "n", map[string]any{"used": true}); err == nil {
		t.Fatal("expected error")
	}
}

// ── Login challenges ──────────────────────────────────────────────

func TestLoginChallengeLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	id, err := r.CreateLoginChallenge(ctx(), &service.LoginChallengeRecord{
		ChallengeID: "ch1", UserID: "u1", ExpiresAt: 5, CreatedAt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetLoginChallengeByChallengeID(ctx(), "ch1")
	if err != nil || got == nil || got.NodeID != id {
		t.Fatalf("Get: %v %+v", err, got)
	}
	if err := r.DeleteLoginChallenge(ctx(), id); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetLoginChallengeByChallengeID(ctx(), "ch1")
	if got != nil {
		t.Fatalf("not deleted: %+v", got)
	}
}

func TestLoginChallengeEdges(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if got, err := r.GetLoginChallengeByChallengeID(ctx(), ""); err != nil || got != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := r.CreateLoginChallenge(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteLoginChallenge(ctx(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestLoginChallengeErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.queryErr = errors.New("q")
	if _, err := r.GetLoginChallengeByChallengeID(ctx(), "x"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if _, err := r.CreateLoginChallenge(ctx(), &service.LoginChallengeRecord{ChallengeID: "c", UserID: "u"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.DeleteLoginChallenge(ctx(), "n"); err == nil {
		t.Fatal("expected error")
	}
}

// ── User invitations ──────────────────────────────────────────────

func TestInvitationFindAndUpdate(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	// Seed an invitation directly into the fake store so we can find it.
	c.seq++
	c.store["inv1"] = &entdb.Node{
		NodeID: "inv1", TypeID: typeUserInvitation,
		Payload: map[string]any{
			invTokenHash: "h", invEmail: "x@y", invInvitedBy: "admin",
			invRole: "member", invExpiresAt: int64(100), invCreatedAt: int64(1),
		},
	}
	got, err := r.FindInvitationByHash(ctx(), "h")
	if err != nil || got == nil || got.NodeID != "inv1" {
		t.Fatalf("FindInvitationByHash: %v %+v", err, got)
	}
	if err := r.UpdateInvitation(ctx(), "inv1", map[string]any{
		"accepted_at": int64(50), "user_id": "u9", "ignored": "x",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = r.FindInvitationByHash(ctx(), "h")
	if got.AcceptedAt != 50 || got.UserID != "u9" {
		t.Fatalf("not applied: %+v", got)
	}
}

func TestInvitationEdgesAndErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	if got, err := r.FindInvitationByHash(ctx(), ""); err != nil || got != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := r.UpdateInvitation(ctx(), "", map[string]any{"accepted_at": int64(1)}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.UpdateInvitation(ctx(), "n", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	c.queryErr = errors.New("q")
	if _, err := r.FindInvitationByHash(ctx(), "h"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if err := r.UpdateInvitation(ctx(), "n", map[string]any{"accepted_at": int64(1)}); err == nil {
		t.Fatal("expected error")
	}
}

// ── Password-reset tokens ─────────────────────────────────────────

func TestPasswordResetTokenLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	tok := &service.PasswordResetToken{TokenHash: "h", UserID: "u1", ExpiresAt: 100, CreatedAt: 1}
	if err := r.CreatePasswordResetToken(ctx(), tok); err != nil {
		t.Fatal(err)
	}
	if tok.NodeID == "" {
		t.Fatal("NodeID not populated")
	}
	got, err := r.FindPasswordResetTokenByHash(ctx(), "h")
	if err != nil || got == nil || got.NodeID != tok.NodeID {
		t.Fatalf("Find: %v %+v", err, got)
	}
	if err := r.MarkPasswordResetTokenConsumed(ctx(), tok.NodeID, 50); err != nil {
		t.Fatal(err)
	}
	got, _ = r.FindPasswordResetTokenByHash(ctx(), "h")
	if got.ConsumedAt != 50 {
		t.Fatalf("consumed not set: %+v", got)
	}
}

func TestPasswordResetTokenEdgesAndErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	if got, err := r.FindPasswordResetTokenByHash(ctx(), ""); err != nil || got != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := r.CreatePasswordResetToken(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.MarkPasswordResetTokenConsumed(ctx(), "", 1); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = errors.New("q")
	if _, err := r.FindPasswordResetTokenByHash(ctx(), "h"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if err := r.CreatePasswordResetToken(ctx(), &service.PasswordResetToken{TokenHash: "h", UserID: "u"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.MarkPasswordResetTokenConsumed(ctx(), "n", 1); err == nil {
		t.Fatal("expected error")
	}
}

// ── Email-verification tokens ─────────────────────────────────────

func TestEmailVerificationTokenLifecycle(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	tok := &service.EmailVerificationToken{TokenHash: "h", UserID: "u1", Email: "u@e", ExpiresAt: 100, CreatedAt: 1}
	if err := r.CreateEmailVerificationToken(ctx(), tok); err != nil {
		t.Fatal(err)
	}
	if tok.NodeID == "" {
		t.Fatal("NodeID not populated")
	}
	got, err := r.FindEmailVerificationTokenByHash(ctx(), "h")
	if err != nil || got == nil || got.NodeID != tok.NodeID {
		t.Fatalf("Find: %v %+v", err, got)
	}
	if got.Email != "u@e" {
		t.Fatalf("email round-trip: %+v", got)
	}
	if err := r.MarkEmailVerificationTokenConsumed(ctx(), tok.NodeID, 70); err != nil {
		t.Fatal(err)
	}
	got, _ = r.FindEmailVerificationTokenByHash(ctx(), "h")
	if got.ConsumedAt != 70 {
		t.Fatalf("consumed not set: %+v", got)
	}
}

func TestEmailVerificationTokenEdgesAndErrors(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	if got, err := r.FindEmailVerificationTokenByHash(ctx(), ""); err != nil || got != nil {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := r.CreateEmailVerificationToken(ctx(), nil); err == nil {
		t.Fatal("expected error")
	}
	if err := r.MarkEmailVerificationTokenConsumed(ctx(), "", 1); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = errors.New("q")
	if _, err := r.FindEmailVerificationTokenByHash(ctx(), "h"); err == nil {
		t.Fatal("expected error")
	}
	c.queryErr = nil
	c.executeErr = errors.New("e")
	if err := r.CreateEmailVerificationToken(ctx(), &service.EmailVerificationToken{TokenHash: "h", Email: "e"}); err == nil {
		t.Fatal("expected error")
	}
	if err := r.MarkEmailVerificationTokenConsumed(ctx(), "n", 1); err == nil {
		t.Fatal("expected error")
	}
}

// ── Commit-result error paths ─────────────────────────────────────

func TestCreateUser_CommitFailure(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.executeRes = &entdb.CommitResult{Success: false, Error: "unique constraint violation"}
	if _, err := r.CreateUser(ctx(), &service.User{Email: "x@x", Name: "x"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateUser_CommitNoNodeID(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	c.executeRes = &entdb.CommitResult{Success: true} // no created node ids
	if _, err := r.CreateUser(ctx(), &service.User{Email: "x@x", Name: "x"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateUser_CommitNilResult(t *testing.T) {
	t.Parallel()
	c := newFakeClient()
	// Override ExecuteAtomic to return (nil, nil).
	r := newEntRepositoryFromClient(&nilCommitClient{fakeClient: c}, "tenant-1")
	if _, err := r.CreateUser(ctx(), &service.User{Email: "x@x", Name: "x"}); err == nil {
		t.Fatal("expected error")
	}
}

// nilCommitClient is a fakeClient that returns (nil, nil) from
// ExecuteAtomic, exercising firstCreatedNodeID's nil-result branch.
type nilCommitClient struct{ *fakeClient }

func (n *nilCommitClient) ExecuteAtomic(_ context.Context, _, _, _ string, _ []entdb.Operation) (*entdb.CommitResult, error) {
	return nil, nil
}

// ── DB adapter ────────────────────────────────────────────────────

func TestDBAdapter_Delegates(t *testing.T) {
	t.Parallel()
	c := newFakeClient()
	c.seq++
	c.store["n1"] = &entdb.Node{NodeID: "n1", TypeID: 7, Payload: map[string]any{"1": "v"}}
	db := newDBAdapterFromClient(c)

	if got, err := db.GetNode(ctx(), "t", "user:a", 7, "n1"); err != nil || got == nil {
		t.Fatalf("GetNode: %v %+v", err, got)
	}
	if got, err := db.QueryNodes(ctx(), "t", "user:a", 7, map[string]any{"1": "v"}); err != nil || len(got) != 1 {
		t.Fatalf("QueryNodes: %v len=%d", err, len(got))
	}
	if _, err := db.ExecuteAtomic(ctx(), "t", "user:a", "", []entdb.Operation{{Type: entdb.OpCreateNode, TypeID: 7, Data: map[string]any{"1": "v2"}}}); err != nil {
		t.Fatalf("ExecuteAtomic: %v", err)
	}
	if got, err := db.GetEdgesFrom(ctx(), "t", "user:a", "n1", 100); err != nil || got != nil {
		t.Fatalf("GetEdgesFrom: %v %+v", err, got)
	}
	if got, err := db.SearchNodes(ctx(), "t", "user:a", 7, "q"); err != nil || got != nil {
		t.Fatalf("SearchNodes: %v %+v", err, got)
	}
}

func TestDBAdapter_PropagatesErrors(t *testing.T) {
	t.Parallel()
	c := newFakeClient()
	c.getErr = errors.New("g")
	c.queryErr = errors.New("q")
	c.executeErr = errors.New("x")
	c.edgesErr = errors.New("e")
	c.searchErr = errors.New("s")
	db := newDBAdapterFromClient(c)
	if _, err := db.GetNode(ctx(), "t", "a", 1, "n"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := db.QueryNodes(ctx(), "t", "a", 1, nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := db.ExecuteAtomic(ctx(), "t", "a", "", nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := db.GetEdgesFrom(ctx(), "t", "a", "n", 1); err == nil {
		t.Fatal("expected error")
	}
	if _, err := db.SearchNodes(ctx(), "t", "a", 1, "q"); err == nil {
		t.Fatal("expected error")
	}
}

// ── Real entdb.DbClient bridging ──────────────────────────────────

// TestExtractTransport_RealClient verifies that we can pull the
// transport interface out of a freshly-constructed *entdb.DbClient
// via reflection. This guards against a future entdb SDK that
// renames the field — the panic at construction would surface
// immediately rather than silently producing a non-functional
// adapter.
func TestExtractTransport_RealClient(t *testing.T) {
	t.Parallel()
	c, err := entdb.NewClient("localhost:50051")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	tr := extractTransport(c)
	if tr == nil {
		t.Fatal("extractTransport returned nil")
	}
}

func TestExtractTransport_NilClient(t *testing.T) {
	t.Parallel()
	if got := extractTransport(nil); got != nil {
		t.Fatalf("expected nil, got %T", got)
	}
}

func TestNewEntDBRepository_WrapsRealClient(t *testing.T) {
	t.Parallel()
	c, err := entdb.NewClient("localhost:50051")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	repo := NewEntDBRepository(c, "tenant-1")
	if repo == nil {
		t.Fatal("nil repo")
	}
	// Compile-time assertion already enforces it implements the
	// interface — this just exercises the constructor path.
}

func TestNewDBAdapter_WrapsRealClient(t *testing.T) {
	t.Parallel()
	c, err := entdb.NewClient("localhost:50051")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	db := NewDBAdapter(c)
	if db == nil {
		t.Fatal("nil db")
	}
}

// ── Concurrent unique-constraint behaviour ────────────────────────

// TestCreateRefreshToken_PropagatesUniqueConstraint validates that an
// entdb-side unique-constraint violation surfaces as a wrapped error
// from the repo, mirroring the behaviour the auth service relies on
// when two refresh tokens with the same hash are created
// concurrently.
func TestCreateRefreshToken_PropagatesUniqueConstraint(t *testing.T) {
	t.Parallel()
	r, c := newRepo(t)
	uniqueErr := entdb.NewUniqueConstraintError("tenant-1", typeRefreshToken, 1, "h")
	c.executeErr = uniqueErr
	_, err := r.CreateRefreshToken(ctx(), &service.RefreshTokenRecord{
		TokenHash: "h", UserID: "u", ExpiresAt: 1, CreatedAt: 1, LastUsedAt: 1,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, uniqueErr) {
		// The repo wraps with %w, so errors.Is must succeed.
		t.Fatalf("expected wrapped unique-constraint error, got %v", err)
	}
}
