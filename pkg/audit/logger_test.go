package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// fakeWriter is a test double for the NodeWriter interface.
type fakeWriter struct {
	mu           sync.Mutex
	calls        []fakeCall
	returnErr    error
	beforeReturn func() // optional gate used by async tests
}

type fakeCall struct {
	TenantID string
	Actor    string
	Ops      []entdb.Operation
}

func (f *fakeWriter) ExecuteAtomic(
	_ context.Context,
	tenantID, actor string,
	ops []entdb.Operation,
) (*entdb.CommitResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{
		TenantID: tenantID,
		Actor:    actor,
		Ops:      ops,
	})
	hook := f.beforeReturn
	rerr := f.returnErr
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if rerr != nil {
		return nil, rerr
	}
	return &entdb.CommitResult{Success: true, Applied: true}, nil
}

func (f *fakeWriter) lastCall() fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return fakeCall{}
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeWriter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestLog_CreatesNode verifies that Log calls ExecuteAtomic with a
// create-node operation for the AuditEvent type.
func TestLog_CreatesNode(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "tenant-1", zap.NewNop())

	l.Log(context.Background(), EventLoginSuccess, WithActor("user-42"))

	if w.callCount() != 1 {
		t.Fatalf("expected 1 call, got %d", w.callCount())
	}
	call := w.lastCall()
	if call.TenantID != "tenant-1" {
		t.Errorf("expected tenant-1, got %q", call.TenantID)
	}
	if call.Actor != "user:system" {
		t.Errorf("expected actor user:system, got %q", call.Actor)
	}
	if len(call.Ops) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(call.Ops))
	}
	op := call.Ops[0]
	if op.Type != entdb.OpCreateNode {
		t.Errorf("expected OpCreateNode, got %v", op.Type)
	}
	if op.TypeID != 26 {
		t.Errorf("expected type_id 26, got %d", op.TypeID)
	}
	if op.Data[fieldEventType] != "login_success" {
		t.Errorf("expected event_type login_success, got %v", op.Data[fieldEventType])
	}
}

// TestLog_NeverPanics verifies that passing a nil writer does not panic.
func TestLog_NeverPanics(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	// nil writer — should not panic.
	l := NewLogger(nil, "t", logger)
	l.Log(context.Background(), EventLoginSuccess)

	if logs.Len() == 0 {
		t.Error("expected a warning log for nil client")
	}
	found := false
	for _, entry := range logs.All() {
		if entry.Message == "audit_log_skipped_nil_client" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit_log_skipped_nil_client warning")
	}
}

// TestLog_NeverReturnsError verifies that EntDB errors are swallowed.
func TestLog_NeverReturnsError(t *testing.T) {
	w := &fakeWriter{returnErr: errors.New("entdb unavailable")}
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)
	l := NewLogger(w, "t", logger)

	// This must not panic or propagate the error.
	l.Log(context.Background(), EventLoginFailure, WithActor("user-1"))

	if w.callCount() != 1 {
		t.Fatalf("expected 1 call, got %d", w.callCount())
	}
	if logs.Len() == 0 {
		t.Error("expected an error log for failed write")
	}
	found := false
	for _, entry := range logs.All() {
		if entry.Message == "audit_log_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit_log_failed error log")
	}
}

// TestLog_SetsAllFields verifies that all option values are written
// into the operation data.
func TestLog_SetsAllFields(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "tenant-1", zap.NewNop())
	fixedTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	l.nowFunc = func() time.Time { return fixedTime }

	l.Log(
		context.Background(), EventPasswordChanged,
		WithActor("user-10"),
		WithTarget("user-20"),
		WithIP("192.168.1.1"),
		WithUserAgent("TestAgent/1.0"),
		WithSuccess(false),
		WithDetails(map[string]any{"reason": "expired"}),
	)

	call := w.lastCall()
	op := call.Ops[0]
	data := op.Data

	checks := map[string]any{
		fieldEventType:    "password_changed",
		fieldActorUserID:  "user-10",
		fieldTargetUserID: "user-20",
		fieldIPAddress:    "192.168.1.1",
		fieldUserAgent:    "TestAgent/1.0",
		fieldSuccess:      false,
		fieldCreatedAt:    fixedTime.UnixMilli(),
	}
	for k, want := range checks {
		got := data[k]
		if got != want {
			t.Errorf("field %q: want %v (%T), got %v (%T)", k, want, want, got, got)
		}
	}
	// Details should be JSON-encoded.
	details, ok := data[fieldDetails].(string)
	if !ok {
		t.Fatalf("expected details to be string, got %T", data[fieldDetails])
	}
	if details != `{"reason":"expired"}` {
		t.Errorf("expected details JSON, got %q", details)
	}
}

// TestWithActor verifies the WithActor option.
func TestWithActor(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(context.Background(), EventLogout, WithActor("user-99"))

	data := w.lastCall().Ops[0].Data
	if data[fieldActorUserID] != "user-99" {
		t.Errorf("expected actor user-99, got %v", data[fieldActorUserID])
	}
	// When no target is set, target defaults to actor.
	if data[fieldTargetUserID] != "user-99" {
		t.Errorf("expected target to default to actor user-99, got %v", data[fieldTargetUserID])
	}
}

// TestWithTarget verifies the WithTarget option overrides the default.
func TestWithTarget(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(
		context.Background(), EventAdminResetPassword,
		WithActor("admin-1"),
		WithTarget("user-50"),
	)

	data := w.lastCall().Ops[0].Data
	if data[fieldActorUserID] != "admin-1" {
		t.Errorf("expected actor admin-1, got %v", data[fieldActorUserID])
	}
	if data[fieldTargetUserID] != "user-50" {
		t.Errorf("expected target user-50, got %v", data[fieldTargetUserID])
	}
}

// TestWithIP verifies the WithIP option.
func TestWithIP(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(context.Background(), EventLoginSuccess, WithIP("10.0.0.1"))

	data := w.lastCall().Ops[0].Data
	if data[fieldIPAddress] != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %v", data[fieldIPAddress])
	}
}

// TestWithDetails verifies the WithDetails option encodes as sorted JSON.
func TestWithDetails(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(
		context.Background(), EventOAuthLogin,
		WithDetails(map[string]any{
			"provider": "google",
			"email":    "test@example.com",
		}),
	)

	data := w.lastCall().Ops[0].Data
	details := data[fieldDetails].(string)
	// Keys should be sorted: email before provider.
	expected := `{"email":"test@example.com","provider":"google"}`
	if details != expected {
		t.Errorf("expected sorted JSON %q, got %q", expected, details)
	}
}

// TestLog_UnknownEventType verifies that an unknown event type is
// logged as a warning but the write still proceeds.
func TestLog_UnknownEventType(t *testing.T) {
	w := &fakeWriter{}
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)
	l := NewLogger(w, "t", logger)

	l.Log(context.Background(), EventType("totally_made_up"))

	// Should still write.
	if w.callCount() != 1 {
		t.Fatalf("expected 1 call, got %d", w.callCount())
	}
	// Should warn.
	found := false
	for _, entry := range logs.All() {
		if entry.Message == "audit_unknown_event_type" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit_unknown_event_type warning")
	}
}

// TestLog_DefaultSuccessIsTrue verifies that success defaults to true
// when WithSuccess is not called.
func TestLog_DefaultSuccessIsTrue(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(context.Background(), EventLoginSuccess)

	data := w.lastCall().Ops[0].Data
	if data[fieldSuccess] != true {
		t.Errorf("expected success=true by default, got %v", data[fieldSuccess])
	}
}

// TestLog_EmptyDetailsEncodesAsEmptyJSON verifies that omitting
// WithDetails produces "{}".
func TestLog_EmptyDetailsEncodesAsEmptyJSON(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(context.Background(), EventLogout)

	data := w.lastCall().Ops[0].Data
	details := data[fieldDetails].(string)
	if details != "{}" {
		t.Errorf("expected empty JSON object, got %q", details)
	}
}

// TestLog_NilLoggerDoesNotPanic verifies that passing a nil zap.Logger
// to NewLogger does not panic.
func TestLog_NilLoggerDoesNotPanic(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", nil) // nil logger

	// Should not panic.
	l.Log(context.Background(), EventLoginSuccess, WithActor("user-1"))

	if w.callCount() != 1 {
		t.Errorf("expected 1 call, got %d", w.callCount())
	}
}

// TestSortedJSON verifies deterministic key ordering.
func TestSortedJSON(t *testing.T) {
	m := map[string]any{
		"zebra":  1,
		"apple":  "fruit",
		"mango":  true,
		"banana": 3.14,
	}
	got := sortedJSON(m)
	expected := `{"apple":"fruit","banana":3.14,"mango":true,"zebra":1}`
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// ── Async mode ─────────────────────────────────────────────────────────

func TestLog_AsyncBuffersAndFlushes(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(64)
	defer stop()

	for i := 0; i < 5; i++ {
		l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	}
	// Calling stop drains the queue.
	stop()
	if w.callCount() != 5 {
		t.Fatalf("async flush: expected 5 calls, got %d", w.callCount())
	}
	if l.DroppedCount() != 0 {
		t.Fatalf("unexpected drops: %d", l.DroppedCount())
	}
}

func TestLog_AsyncDropsOnFullQueue(t *testing.T) {
	// Blocking writer ensures the flusher cannot drain — the queue
	// fills and the producer-side drops kick in.
	block := make(chan struct{})
	w := &fakeWriter{}
	w.beforeReturn = func() { <-block }
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(2) // tiny queue
	defer func() { close(block); stop() }()

	for i := 0; i < 50; i++ {
		l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	}
	if l.DroppedCount() == 0 {
		t.Fatalf("expected drops when queue is full, got 0")
	}
}

func TestLog_AsyncDoesNotBlockCallerOnSlowWriter(t *testing.T) {
	block := make(chan struct{})
	w := &fakeWriter{}
	w.beforeReturn = func() { <-block }
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(1024)
	defer func() { close(block); stop() }()

	start := time.Now()
	for i := 0; i < 50; i++ {
		l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("async log appeared to block the caller: %v", elapsed)
	}
}

func TestStartAsync_TwiceIsNoOp(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", nil)
	stop1 := l.StartAsync(8)
	stop2 := l.StartAsync(8)
	defer stop1()
	defer stop2()
	l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	stop1()
	if w.callCount() != 1 {
		t.Fatalf("expected 1 call after drain, got %d", w.callCount())
	}
}

func TestStartAsync_ZeroQueueSize_UsesDefault(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(0)
	defer stop()
	l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	stop()
	if w.callCount() != 1 {
		t.Fatalf("expected 1 call, got %d", w.callCount())
	}
}

func TestClose_TwiceIsSafe(t *testing.T) {
	w := &fakeWriter{}
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(8)
	stop()
	stop() // second call must be safe
}

func TestWriteOne_RecoversFromPanic(t *testing.T) {
	w := &fakeWriter{}
	w.beforeReturn = func() { panic("simulated transport panic") }
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(8)

	l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	stop() // drain
	// If the panic propagated, the test would have crashed.
}

func TestWriteOne_LogsTransportError(t *testing.T) {
	w := &fakeWriter{returnErr: errors.New("entdb unreachable")}
	l := NewLogger(w, "t", nil)
	stop := l.StartAsync(8)
	l.Log(context.Background(), EventLoginSuccess, WithActor("u"))
	stop()
	if w.callCount() != 1 {
		t.Fatalf("expected 1 call (writer called even on error), got %d", w.callCount())
	}
}
