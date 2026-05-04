package audit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestSortedJSON_NonMarshalableValue exercises the fallback path in
// sortedJSON when json.Marshal returns an error. Channels and functions
// cannot be JSON-encoded — they trigger json.UnsupportedTypeError and
// the function falls back to a quoted string representation.
func TestSortedJSON_NonMarshalableValue(t *testing.T) {
	t.Parallel()

	ch := make(chan int)
	got := sortedJSON(map[string]any{
		"a": "ok",
		"b": ch, // not marshalable
	})

	// Keys are sorted, "a" first, "b" present and quoted.
	if !strings.HasPrefix(got, `{"a":"ok","b":"`) {
		t.Errorf("expected fallback quoted form for non-marshalable value, got %q", got)
	}
	if !strings.HasSuffix(got, `"}`) {
		t.Errorf("expected JSON object terminator, got %q", got)
	}
}

// TestLog_RecoversFromPanic verifies that a panic inside Log is recovered
// and reported via zap rather than propagated to the caller.
func TestLog_RecoversFromPanic(t *testing.T) {
	t.Parallel()

	w := &fakeWriter{}
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)
	l := NewLogger(w, "tenant-1", logger)
	// Force a panic by setting a panicking nowFunc.
	l.nowFunc = func() time.Time { panic("nowFunc boom") }

	// Must not panic — Log must recover internally.
	l.Log(context.Background(), EventLoginSuccess, WithActor("user-1"))

	// Writer should never have been called (panic happened before write).
	if w.callCount() != 0 {
		t.Errorf("expected 0 calls after panic, got %d", w.callCount())
	}

	found := false
	for _, entry := range logs.All() {
		if entry.Message == "audit_log_panic" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit_log_panic error log")
	}
}

// TestLog_ConcurrentEmission verifies that Log is safe to call from many
// goroutines simultaneously.
func TestLog_ConcurrentEmission(t *testing.T) {
	t.Parallel()

	w := &fakeWriter{}
	l := NewLogger(w, "tenant-1", zap.NewNop())

	const goroutines = 32
	const perGoroutine = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				l.Log(context.Background(), EventLoginSuccess,
					WithActor("user-x"),
					WithDetails(map[string]any{"j": j}),
				)
			}
		}()
	}
	wg.Wait()

	expected := goroutines * perGoroutine
	if got := w.callCount(); got != expected {
		t.Errorf("expected %d calls, got %d", expected, got)
	}
}

// TestLog_NilDetailsEncodesAsEmptyJSON verifies that explicit nil details
// produce the canonical "{}" payload (same as omitting the option).
func TestLog_NilDetailsEncodesAsEmptyJSON(t *testing.T) {
	t.Parallel()

	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(context.Background(), EventLogout, WithDetails(nil))

	data := w.lastCall().Ops[0].Data
	if got := data[fieldDetails].(string); got != "{}" {
		t.Errorf("expected empty JSON object for nil details, got %q", got)
	}
}

// TestLog_NestedDetails verifies that nested maps and non-string values
// are JSON-encoded structurally (not stringified).
func TestLog_NestedDetails(t *testing.T) {
	t.Parallel()

	w := &fakeWriter{}
	l := NewLogger(w, "t", zap.NewNop())

	l.Log(context.Background(), EventLoginSuccess,
		WithDetails(map[string]any{
			"nested": map[string]any{"k": "v"},
			"count":  42,
			"flag":   true,
			"list":   []int{1, 2, 3},
		}),
	)

	data := w.lastCall().Ops[0].Data
	got := data[fieldDetails].(string)
	// Keys sorted alphabetically: count, flag, list, nested.
	expected := `{"count":42,"flag":true,"list":[1,2,3],"nested":{"k":"v"}}`
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
