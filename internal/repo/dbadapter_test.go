package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	entclient "github.com/elloloop/identity/internal/repo/entdb/entclient"
	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

func TestNewDBAdapter_NilClient(t *testing.T) {
	t.Parallel()

	if _, err := NewDBAdapter(nil); err == nil {
		t.Fatal("NewDBAdapter(nil) succeeded, want error")
	}
}

func TestNewDBAdapter_DelegatesToClientTransport(t *testing.T) {
	t.Parallel()

	client, err := entclient.New("localhost:50051")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	db, err := NewDBAdapter(client)
	if err != nil {
		t.Fatalf("NewDBAdapter: %v", err)
	}

	if _, err := db.GetNode(context.Background(), "tenant-1", "user:alice", 1, "node-1"); err == nil {
		t.Fatal("GetNode without Connect succeeded, want connection error")
	}
}

func TestDBAdapter_WaitsForRawCommitBeforeReturning(t *testing.T) {
	transport := &staleUpdateTransport{}
	db := &dbAdapter{transport: transport}
	groups := service.NewGroupService(
		db,
		"tenant-1",
		audit.NewLogger(nil, "tenant-1", zap.NewNop()),
		zap.NewNop(),
	)

	group, err := groups.UpdateGroup(context.Background(), "admin-1", "grp-1", "Platform", "Updated description")
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if group.Name != "Platform" {
		t.Fatalf("updated group name = %q, want Platform", group.Name)
	}
	if !transport.waited {
		t.Fatal("ExecuteAtomic returned before waiting for the commit offset")
	}
}

func TestDBAdapter_ExecuteAtomicRejectsFailedCommit(t *testing.T) {
	transport := &commitResultTransport{
		result: &sdk.CommitResult{
			Success: false,
			Error:   "write rejected",
		},
	}
	db := &dbAdapter{transport: transport}

	_, err := db.ExecuteAtomic(context.Background(), "tenant-1", "user:admin-1", []sdk.Operation{{
		Type:   sdk.OpUpdateNode,
		TypeID: 2,
		NodeID: "grp-1",
		Patch:  map[string]any{"1": "Platform"},
	}})
	if err == nil || !strings.Contains(err.Error(), "write rejected") {
		t.Fatalf("ExecuteAtomic error = %v, want commit failure", err)
	}
	if transport.waitCalls != 0 {
		t.Fatalf("WaitForOffset called %d times for failed commit, want 0", transport.waitCalls)
	}
}

func TestDBAdapter_ExecuteAtomicRequiresReceiptForUnappliedCommit(t *testing.T) {
	transport := &commitResultTransport{
		result: &sdk.CommitResult{Success: true, Applied: false},
	}
	db := &dbAdapter{transport: transport}

	_, err := db.ExecuteAtomic(context.Background(), "tenant-1", "user:admin-1", []sdk.Operation{{
		Type:   sdk.OpUpdateNode,
		TypeID: 2,
		NodeID: "grp-1",
		Patch:  map[string]any{"1": "Platform"},
	}})
	if err == nil || !strings.Contains(err.Error(), "without stream position") {
		t.Fatalf("ExecuteAtomic error = %v, want missing stream position", err)
	}
	if transport.waitCalls != 0 {
		t.Fatalf("WaitForOffset called %d times without stream position, want 0", transport.waitCalls)
	}
}

func TestDBAdapter_ExecuteAtomicReturnsApplyTimeout(t *testing.T) {
	transport := &commitResultTransport{
		result: &sdk.CommitResult{
			Success: true,
			Applied: false,
			Receipt: &sdk.Receipt{
				StreamPosition: "offset-10",
			},
		},
		reached: false,
		current: "offset-9",
	}
	db := &dbAdapter{transport: transport}

	_, err := db.ExecuteAtomic(context.Background(), "tenant-1", "user:admin-1", []sdk.Operation{{
		Type:   sdk.OpUpdateNode,
		TypeID: 2,
		NodeID: "grp-1",
		Patch:  map[string]any{"1": "Platform"},
	}})
	if err == nil || !strings.Contains(err.Error(), "commit apply timeout") {
		t.Fatalf("ExecuteAtomic error = %v, want apply timeout", err)
	}
	if transport.waitCalls != 1 {
		t.Fatalf("WaitForOffset called %d times, want 1", transport.waitCalls)
	}
}

func TestDBAdapter_ExecuteAtomicSkipsWaitForAppliedCommit(t *testing.T) {
	transport := &commitResultTransport{
		result: &sdk.CommitResult{Success: true, Applied: true},
	}
	db := &dbAdapter{transport: transport}

	if _, err := db.ExecuteAtomic(context.Background(), "tenant-1", "user:admin-1", []sdk.Operation{{
		Type:   sdk.OpUpdateNode,
		TypeID: 2,
		NodeID: "grp-1",
		Patch:  map[string]any{"1": "Platform"},
	}}); err != nil {
		t.Fatalf("ExecuteAtomic: %v", err)
	}
	if transport.waitCalls != 0 {
		t.Fatalf("WaitForOffset called %d times for already-applied commit, want 0", transport.waitCalls)
	}
}

type staleUpdateTransport struct {
	sdk.Transport
	waited bool
	patch  map[string]any
}

func (t *staleUpdateTransport) GetNode(_ context.Context, _, _ string, typeID int, nodeID string) (*sdk.Node, error) {
	switch {
	case typeID == 1 && nodeID == "admin-1":
		return &sdk.Node{
			NodeID: "admin-1",
			TypeID: 1,
			Payload: map[string]any{
				"1":  "admin@example.com",
				"2":  "Admin",
				"3":  "admin",
				"11": "active",
			},
		}, nil
	case typeID == 2 && nodeID == "grp-1":
		name := "Engineering"
		description := "Original description"
		if t.waited {
			name = t.patchString("1", name)
			description = t.patchString("2", description)
		}
		return &sdk.Node{
			NodeID: "grp-1",
			TypeID: 2,
			Payload: map[string]any{
				"1": name,
				"2": description,
				"4": int64(1000),
				"5": int64(2000),
			},
		}, nil
	default:
		return nil, nil
	}
}

func (t *staleUpdateTransport) ExecuteAtomic(
	_ context.Context,
	tenantID,
	_ string,
	_ string,
	ops []sdk.Operation,
	_ ...sdk.CommitOption,
) (*sdk.CommitResult, error) {
	if len(ops) != 1 {
		return nil, nil
	}
	t.patch = ops[0].Patch
	return &sdk.CommitResult{
		Success: true,
		Applied: false,
		Receipt: &sdk.Receipt{
			TenantID:       tenantID,
			StreamPosition: "offset-1",
		},
	}, nil
}

func (t *staleUpdateTransport) WaitForOffset(_ context.Context, _, _, streamPosition string, _ int32) (bool, string, error) {
	t.waited = true
	return true, streamPosition, nil
}

func (t *staleUpdateTransport) patchString(key, fallback string) string {
	v, ok := t.patch[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	return s
}

type commitResultTransport struct {
	sdk.Transport
	result    *sdk.CommitResult
	reached   bool
	current   string
	waitCalls int
}

func (t *commitResultTransport) ExecuteAtomic(
	context.Context,
	string,
	string,
	string,
	[]sdk.Operation,
	...sdk.CommitOption,
) (*sdk.CommitResult, error) {
	return t.result, nil
}

func (t *commitResultTransport) WaitForOffset(context.Context, string, string, string, int32) (bool, string, error) {
	t.waitCalls++
	return t.reached, t.current, nil
}

// ── Passthrough method tests ───────────────────────────────────────

type passthroughTransport struct {
	sdk.Transport
	queryNodesCalled   bool
	getEdgesFromCalled bool
	getEdgesToCalled   bool
	searchNodesCalled  bool
	queryNodesResult   []*sdk.Node
	getEdgesFromResult []*sdk.Edge
	getEdgesToResult   []*sdk.Edge
	searchNodesResult  []*sdk.Node
	queryNodesErr      error
	getEdgesFromErr    error
	getEdgesToErr      error
	searchNodesErr     error
}

func (t *passthroughTransport) QueryNodes(context.Context, string, string, int, map[string]any, int) ([]*sdk.Node, error) {
	t.queryNodesCalled = true
	return t.queryNodesResult, t.queryNodesErr
}

func (t *passthroughTransport) GetEdgesFrom(context.Context, string, string, string, int) ([]*sdk.Edge, error) {
	t.getEdgesFromCalled = true
	return t.getEdgesFromResult, t.getEdgesFromErr
}

func (t *passthroughTransport) GetEdgesTo(context.Context, string, string, string, int) ([]*sdk.Edge, error) {
	t.getEdgesToCalled = true
	return t.getEdgesToResult, t.getEdgesToErr
}

func (t *passthroughTransport) SearchNodes(context.Context, string, string, int, string, int32, int32) ([]*sdk.Node, bool, error) {
	t.searchNodesCalled = true
	return t.searchNodesResult, false, t.searchNodesErr
}

func TestDBAdapter_QueryNodesDelegatesToTransport(t *testing.T) {
	t.Parallel()
	transport := &passthroughTransport{queryNodesResult: []*sdk.Node{{NodeID: "n1"}}}
	db := &dbAdapter{transport: transport}
	got, err := db.QueryNodes(context.Background(), "tenant-1", "user:alice", 1, map[string]any{"x": "y"})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if !transport.queryNodesCalled {
		t.Fatal("transport.QueryNodes not called")
	}
	if len(got) != 1 || got[0].NodeID != "n1" {
		t.Fatalf("QueryNodes result = %+v, want one node \"n1\"", got)
	}
}

func TestDBAdapter_GetEdgesFromDelegatesToTransport(t *testing.T) {
	t.Parallel()
	transport := &passthroughTransport{getEdgesFromResult: []*sdk.Edge{{FromNodeID: "a"}}}
	db := &dbAdapter{transport: transport}
	got, err := db.GetEdgesFrom(context.Background(), "tenant-1", "user:alice", "a", 1)
	if err != nil {
		t.Fatalf("GetEdgesFrom: %v", err)
	}
	if !transport.getEdgesFromCalled {
		t.Fatal("transport.GetEdgesFrom not called")
	}
	if len(got) != 1 {
		t.Fatalf("got %d edges, want 1", len(got))
	}
}

func TestDBAdapter_GetEdgesToDelegatesToTransport(t *testing.T) {
	t.Parallel()
	transport := &passthroughTransport{getEdgesToResult: []*sdk.Edge{{ToNodeID: "b"}}}
	db := &dbAdapter{transport: transport}
	got, err := db.GetEdgesTo(context.Background(), "tenant-1", "user:alice", "b", 1)
	if err != nil {
		t.Fatalf("GetEdgesTo: %v", err)
	}
	if !transport.getEdgesToCalled {
		t.Fatal("transport.GetEdgesTo not called")
	}
	if len(got) != 1 {
		t.Fatalf("got %d edges, want 1", len(got))
	}
}

func TestDBAdapter_SearchNodesDelegatesToTransport(t *testing.T) {
	t.Parallel()
	transport := &passthroughTransport{searchNodesResult: []*sdk.Node{{NodeID: "found"}}}
	db := &dbAdapter{transport: transport}
	got, err := db.SearchNodes(context.Background(), "tenant-1", "user:alice", 1, "q")
	if err != nil {
		t.Fatalf("SearchNodes: %v", err)
	}
	if !transport.searchNodesCalled {
		t.Fatal("transport.SearchNodes not called")
	}
	if len(got) != 1 || got[0].NodeID != "found" {
		t.Fatalf("SearchNodes result = %+v, want one node \"found\"", got)
	}
}

// ── RegisterUserInTenant tests ─────────────────────────────────────

type registerTransport struct {
	sdk.Transport
	createUserCalls       []registerCreateUserCall
	addMemberCalls        []registerAddMemberCall
	createUserErr         error
	addMemberErr          error
	createUserAfterCalled func()
}

type registerCreateUserCall struct {
	actor, userID, email, name string
}

type registerAddMemberCall struct {
	actor, tenantID, userID, role string
}

func (t *registerTransport) CreateUser(_ context.Context, actor, userID, email, name string) (*sdk.UserInfo, error) {
	t.createUserCalls = append(t.createUserCalls, registerCreateUserCall{actor, userID, email, name})
	if t.createUserAfterCalled != nil {
		t.createUserAfterCalled()
	}
	if t.createUserErr != nil {
		return nil, t.createUserErr
	}
	return &sdk.UserInfo{}, nil
}

func (t *registerTransport) AddTenantMember(_ context.Context, actor, tenantID, userID, role string) error {
	t.addMemberCalls = append(t.addMemberCalls, registerAddMemberCall{actor, tenantID, userID, role})
	return t.addMemberErr
}

func TestDBAdapter_RegisterUserInTenant_HappyPath(t *testing.T) {
	t.Parallel()

	transport := &registerTransport{}
	db := &dbAdapter{transport: transport}

	if err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "alice@example.com", "Alice", "member"); err != nil {
		t.Fatalf("RegisterUserInTenant: %v", err)
	}
	if len(transport.createUserCalls) != 1 {
		t.Fatalf("CreateUser called %d times, want 1", len(transport.createUserCalls))
	}
	if got := transport.createUserCalls[0]; got != (registerCreateUserCall{"system:admin", "user-1", "alice@example.com", "Alice"}) {
		t.Fatalf("CreateUser call = %+v, want system:admin/user-1/alice@example.com/Alice", got)
	}
	if len(transport.addMemberCalls) != 1 {
		t.Fatalf("AddTenantMember called %d times, want 1", len(transport.addMemberCalls))
	}
	if got := transport.addMemberCalls[0]; got != (registerAddMemberCall{"system:admin", "tenant-1", "user-1", "member"}) {
		t.Fatalf("AddTenantMember call = %+v", got)
	}
}

func TestDBAdapter_RegisterUserInTenant_EmptyUserID(t *testing.T) {
	t.Parallel()

	db := &dbAdapter{transport: &registerTransport{}}
	err := db.RegisterUserInTenant(context.Background(), "tenant-1", "", "alice@example.com", "Alice", "member")
	if err == nil || !strings.Contains(err.Error(), "empty user id") {
		t.Fatalf("err = %v, want empty user id error", err)
	}
}

func TestDBAdapter_RegisterUserInTenant_EmptyNameDefaultsToEmailLocalPart(t *testing.T) {
	t.Parallel()

	transport := &registerTransport{}
	db := &dbAdapter{transport: transport}

	if err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "alice@example.com", "", "member"); err != nil {
		t.Fatalf("RegisterUserInTenant: %v", err)
	}
	if got := transport.createUserCalls[0].name; got != "alice" {
		t.Fatalf("CreateUser name = %q, want \"alice\" (local-part of email)", got)
	}
}

func TestDBAdapter_RegisterUserInTenant_EmptyNameAndEmailDefaultsToUserID(t *testing.T) {
	t.Parallel()

	transport := &registerTransport{}
	db := &dbAdapter{transport: transport}

	if err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "", "", "member"); err != nil {
		t.Fatalf("RegisterUserInTenant: %v", err)
	}
	if got := transport.createUserCalls[0].name; got != "user-1" {
		t.Fatalf("CreateUser name = %q, want \"user-1\" (userID fallback)", got)
	}
}

func TestDBAdapter_RegisterUserInTenant_ToleratesAlreadyExistsOnCreateUser(t *testing.T) {
	t.Parallel()

	// tenant-shard-db v1.14.0 surfaces the duplicate as a typed
	// *sdk.UniqueConstraintError (the SDK parses the ALREADY_EXISTS
	// gRPC status and wraps it). Older string-only assertions were
	// removed: the SDK no longer leaks the underlying message
	// verbatim, and identity should not match against the SEC-5
	// sanitized text either.
	transport := &registerTransport{
		createUserErr: sdk.NewUniqueConstraintError("tenant-1", 1, 1, "u"),
	}
	db := &dbAdapter{transport: transport}

	if err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "alice@example.com", "Alice", "member"); err != nil {
		t.Fatalf("RegisterUserInTenant: %v, want nil (ALREADY_EXISTS is idempotent)", err)
	}
	if len(transport.addMemberCalls) != 1 {
		t.Fatalf("AddTenantMember calls = %d, want 1 (must run after CreateUser tolerates dup)", len(transport.addMemberCalls))
	}
}

func TestDBAdapter_RegisterUserInTenant_PropagatesNonAlreadyExistsCreateError(t *testing.T) {
	t.Parallel()

	transport := &registerTransport{
		createUserErr: errors.New("entdb INTERNAL: server exploded"),
	}
	db := &dbAdapter{transport: transport}

	err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "alice@example.com", "Alice", "member")
	if err == nil || !strings.Contains(err.Error(), "register user") {
		t.Fatalf("err = %v, want register user wrapped error", err)
	}
	if len(transport.addMemberCalls) != 0 {
		t.Fatalf("AddTenantMember called %d times after CreateUser failure, want 0", len(transport.addMemberCalls))
	}
}

func TestDBAdapter_RegisterUserInTenant_ToleratesAlreadyExistsOnAddTenantMember(t *testing.T) {
	t.Parallel()

	transport := &registerTransport{
		addMemberErr: &sdk.EntDBError{Code: "ALREADY_EXISTS", Message: "user is already a member"},
	}
	db := &dbAdapter{transport: transport}

	if err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "alice@example.com", "Alice", "member"); err != nil {
		t.Fatalf("RegisterUserInTenant: %v, want nil (membership ALREADY_EXISTS is idempotent)", err)
	}
}

func TestDBAdapter_RegisterUserInTenant_PropagatesNonAlreadyExistsMemberError(t *testing.T) {
	t.Parallel()

	transport := &registerTransport{
		addMemberErr: errors.New("entdb INTERNAL: db unreachable"),
	}
	db := &dbAdapter{transport: transport}

	err := db.RegisterUserInTenant(context.Background(), "tenant-1", "user-1", "alice@example.com", "Alice", "member")
	if err == nil || !strings.Contains(err.Error(), "add tenant member") {
		t.Fatalf("err = %v, want add tenant member wrapped error", err)
	}
}

// ── TenantAdmin tests ─────────────────────────────────────────────

type tenantAdminTransport struct {
	sdk.Transport
	createTenantCalls []tenantAdminCreateTenantCall
	changeRoleCalls   []tenantAdminChangeRoleCall
	removeMemberCalls []tenantAdminRemoveMemberCall
	createTenantErr   error
	changeRoleErr     error
	removeMemberErr   error
}

type tenantAdminCreateTenantCall struct {
	actor, tenantID, name string
}
type tenantAdminChangeRoleCall struct {
	actor, tenantID, userID, role string
}
type tenantAdminRemoveMemberCall struct {
	actor, tenantID, userID string
}

func (t *tenantAdminTransport) CreateTenant(_ context.Context, actor, tenantID, name string, _ ...sdk.CreateTenantOption) (*sdk.TenantDetail, error) {
	t.createTenantCalls = append(t.createTenantCalls, tenantAdminCreateTenantCall{actor, tenantID, name})
	if t.createTenantErr != nil {
		return nil, t.createTenantErr
	}
	return &sdk.TenantDetail{}, nil
}

func (t *tenantAdminTransport) ChangeMemberRole(_ context.Context, actor, tenantID, userID, role string) error {
	t.changeRoleCalls = append(t.changeRoleCalls, tenantAdminChangeRoleCall{actor, tenantID, userID, role})
	return t.changeRoleErr
}

func (t *tenantAdminTransport) RemoveTenantMember(_ context.Context, actor, tenantID, userID string) error {
	t.removeMemberCalls = append(t.removeMemberCalls, tenantAdminRemoveMemberCall{actor, tenantID, userID})
	return t.removeMemberErr
}

func TestTenantAdmin_CreateTenant_HappyPath(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{}
	a := &tenantAdmin{transport: tp}
	if err := a.CreateTenant(context.Background(), "acme", "Acme Corp"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if len(tp.createTenantCalls) != 1 {
		t.Fatalf("CreateTenant called %d times, want 1", len(tp.createTenantCalls))
	}
	got := tp.createTenantCalls[0]
	if got != (tenantAdminCreateTenantCall{"system:admin", "acme", "Acme Corp"}) {
		t.Fatalf("CreateTenant call = %+v", got)
	}
}

func TestTenantAdmin_CreateTenant_AlreadyExists_NormalisesSentinel(t *testing.T) {
	t.Parallel()
	// tenant-shard-db v1.14.0 surfaces the duplicate as a typed
	// *sdk.EntDBError with Code == "ALREADY_EXISTS".
	tp := &tenantAdminTransport{createTenantErr: &sdk.EntDBError{Code: "ALREADY_EXISTS", Message: "tenant acme exists"}}
	a := &tenantAdmin{transport: tp}
	err := a.CreateTenant(context.Background(), "acme", "Acme Corp")
	if !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestTenantAdmin_CreateTenant_OtherError_Propagated(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{createTenantErr: errors.New("INTERNAL: storage down")}
	a := &tenantAdmin{transport: tp}
	err := a.CreateTenant(context.Background(), "acme", "Acme Corp")
	if err == nil || errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("expected non-AlreadyExists error, got %v", err)
	}
}

func TestTenantAdmin_PromoteTenantMember_HappyPath(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{}
	a := &tenantAdmin{transport: tp}
	if err := a.PromoteTenantMember(context.Background(), "acme", "alice", "admin"); err != nil {
		t.Fatalf("PromoteTenantMember: %v", err)
	}
	if len(tp.changeRoleCalls) != 1 {
		t.Fatalf("ChangeMemberRole called %d times, want 1", len(tp.changeRoleCalls))
	}
	got := tp.changeRoleCalls[0]
	if got != (tenantAdminChangeRoleCall{"system:admin", "acme", "alice", "admin"}) {
		t.Fatalf("ChangeMemberRole call = %+v", got)
	}
}

func TestTenantAdmin_PromoteTenantMember_AlreadyAtRole_Idempotent(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{changeRoleErr: &sdk.EntDBError{Code: "ALREADY_EXISTS", Message: "alice is already admin in acme"}}
	a := &tenantAdmin{transport: tp}
	if err := a.PromoteTenantMember(context.Background(), "acme", "alice", "admin"); err != nil {
		t.Fatalf("expected idempotent success, got %v", err)
	}
}

func TestTenantAdmin_PromoteTenantMember_AlreadyAtRoleViaSubstring_Idempotent(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{changeRoleErr: errors.New("user is already admin")}
	a := &tenantAdmin{transport: tp}
	if err := a.PromoteTenantMember(context.Background(), "acme", "alice", "admin"); err != nil {
		t.Fatalf("expected idempotent success, got %v", err)
	}
}

func TestTenantAdmin_PromoteTenantMember_OtherError_Propagated(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{changeRoleErr: errors.New("INTERNAL: storage down")}
	a := &tenantAdmin{transport: tp}
	if err := a.PromoteTenantMember(context.Background(), "acme", "alice", "admin"); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestTenantAdmin_RemoveTenantMember_HappyPath(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{}
	a := &tenantAdmin{transport: tp}
	if err := a.RemoveTenantMember(context.Background(), "acme", "alice"); err != nil {
		t.Fatalf("RemoveTenantMember: %v", err)
	}
	if len(tp.removeMemberCalls) != 1 {
		t.Fatalf("RemoveTenantMember called %d times, want 1", len(tp.removeMemberCalls))
	}
	got := tp.removeMemberCalls[0]
	if got != (tenantAdminRemoveMemberCall{"system:admin", "acme", "alice"}) {
		t.Fatalf("RemoveTenantMember call = %+v", got)
	}
}

func TestTenantAdmin_RemoveTenantMember_NotFound_Idempotent(t *testing.T) {
	t.Parallel()
	// tenant-shard-db v1.14.0 surfaces missing membership as the
	// typed *sdk.NotFoundError. The "no membership" substring path is
	// for the legacy FailedPrecondition case that the test below
	// covers.
	tp := &tenantAdminTransport{removeMemberErr: &sdk.NotFoundError{EntDBError: sdk.EntDBError{Code: "NOT_FOUND", Message: "membership for alice not found"}}}
	a := &tenantAdmin{transport: tp}
	if err := a.RemoveTenantMember(context.Background(), "acme", "alice"); err != nil {
		t.Fatalf("expected idempotent success, got %v", err)
	}
}

func TestTenantAdmin_RemoveTenantMember_NoMembershipSubstring_Idempotent(t *testing.T) {
	t.Parallel()
	// Some legacy server paths surface FailedPrecondition with a
	// "no membership" message rather than NotFound. Keep the
	// substring fallback for that path.
	tp := &tenantAdminTransport{removeMemberErr: &sdk.EntDBError{Code: "FailedPrecondition", Message: "no membership for alice in acme"}}
	a := &tenantAdmin{transport: tp}
	if err := a.RemoveTenantMember(context.Background(), "acme", "alice"); err != nil {
		t.Fatalf("expected idempotent success, got %v", err)
	}
}

func TestTenantAdmin_RemoveTenantMember_OtherError_Propagated(t *testing.T) {
	t.Parallel()
	tp := &tenantAdminTransport{removeMemberErr: errors.New("INTERNAL: storage down")}
	a := &tenantAdmin{transport: tp}
	if err := a.RemoveTenantMember(context.Background(), "acme", "alice"); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// ── PostgresTenantAdmin tests ──────────────────────────────────────

func TestPostgresTenantAdmin_CreateTenant_Idempotent(t *testing.T) {
	t.Parallel()
	a := NewPostgresTenantAdmin()
	if err := a.CreateTenant(context.Background(), "acme", "Acme Corp"); err != nil {
		t.Fatalf("first CreateTenant: %v", err)
	}
	if err := a.CreateTenant(context.Background(), "acme", "Acme Corp"); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("second CreateTenant: want ErrAlreadyExists, got %v", err)
	}
	if err := a.CreateTenant(context.Background(), "other", "Other"); err != nil {
		t.Fatalf("different tenant: %v", err)
	}
}

func TestPostgresTenantAdmin_PromoteTenantMember_NoOp(t *testing.T) {
	t.Parallel()
	a := NewPostgresTenantAdmin()
	if err := a.PromoteTenantMember(context.Background(), "acme", "alice", "admin"); err != nil {
		t.Fatalf("PromoteTenantMember: %v", err)
	}
}

func TestPostgresTenantAdmin_RemoveTenantMember_NoOp(t *testing.T) {
	t.Parallel()
	a := NewPostgresTenantAdmin()
	if err := a.RemoveTenantMember(context.Background(), "acme", "alice"); err != nil {
		t.Fatalf("RemoveTenantMember: %v", err)
	}
}

func TestDBAdapterIsAlreadyExists(t *testing.T) {
	t.Parallel()

	// tenant-shard-db v1.14.0 wraps every ALREADY_EXISTS gRPC status
	// into a typed *sdk.EntDBError or *sdk.UniqueConstraintError. The
	// v1.13.x raw status-error and free-form string paths no longer
	// reach identity, so the matcher rejects them (SEC-5 sanitization
	// audit — see docs/IDENTITY.md §9).
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			name: "typed_entdb_already_exists",
			err:  &sdk.EntDBError{Code: "ALREADY_EXISTS", Message: "x"},
			want: true,
		},
		{
			name: "typed_unique_constraint",
			err:  sdk.NewUniqueConstraintError("t", 1, 1, "v"),
			want: true,
		},
		{
			name: "wrapped_typed_already_exists",
			err:  fmt.Errorf("add member: %w", &sdk.EntDBError{Code: "ALREADY_EXISTS", Message: "x"}),
			want: true,
		},
		{
			name: "typed_internal_error",
			err:  &sdk.EntDBError{Code: "Internal", Message: "internal error"},
			want: false,
		},
		{
			name: "untyped_string",
			err:  errors.New("user already exists"),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dbAdapterIsAlreadyExists(tc.err); got != tc.want {
				t.Fatalf("dbAdapterIsAlreadyExists(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
