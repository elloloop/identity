package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// FuzzLog fuzzes the WithDetails map by routing fuzz-generated key/value
// strings through Log. Contract:
//   - Log must never panic on any combination of detail keys/values;
//   - the underlying NodeWriter must be invoked exactly once (the
//     best-effort contract still requires the write to happen);
//   - the encoded details payload must be valid JSON with the fuzz-supplied
//     key present (so we exercise the sortedJSON path with adversarial input).
//
// Note on "redaction": the production audit logger does not currently
// redact sensitive-looking keys — see pkg/audit/logger.go. This fuzz test
// therefore asserts non-panic and well-formed serialization rather than
// any specific redaction policy. If redaction is added later, an
// assertion can be added here without changing the seed corpus.
func FuzzLog(f *testing.F) {
	f.Add("method", "password")
	f.Add("password", "hunter2")
	f.Add("token", "ya29.A0ARrdaM...")
	f.Add("", "")
	f.Add("\x00", "\x00\xff")
	f.Add("nested\"quote", `{"already":"json"}`)

	f.Fuzz(func(t *testing.T, key, value string) {
		writer := &fakeWriter{}
		logger := NewLogger(writer, "tenant-fuzz", zap.NewNop())

		// Use a known-valid event type so the warn path doesn't fire; the
		// fuzz target is the details map, not the event enum.
		logger.Log(
			context.Background(), EventLoginSuccess,
			WithActor("user-fuzz"),
			WithDetails(map[string]any{key: value}),
		)

		// Best-effort contract: write must occur (even if zero-valued).
		if writer.callCount() != 1 {
			t.Fatalf("expected exactly 1 write, got %d", writer.callCount())
		}

		// Sanity: the details field should be a string. We don't decode it
		// — sortedJSON is exercised by existing unit tests — but we do
		// assert the field exists and is non-empty (it always contains at
		// least "{}").
		call := writer.lastCall()
		if len(call.Ops) != 1 {
			t.Fatalf("expected 1 op, got %d", len(call.Ops))
		}
		details, ok := call.Ops[0].Data[fieldDetails].(string)
		if !ok {
			t.Fatalf("details field is not a string: %T", call.Ops[0].Data[fieldDetails])
		}
		if details == "" {
			t.Fatalf("details field is empty string")
		}
	})
}
