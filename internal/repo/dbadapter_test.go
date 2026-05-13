package repo

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
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

	client, err := sdk.NewClient("localhost:50051")
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
) (*sdk.CommitResult, error) {
	return t.result, nil
}

func (t *commitResultTransport) WaitForOffset(context.Context, string, string, string, int32) (bool, string, error) {
	t.waitCalls++
	return t.reached, t.current, nil
}
