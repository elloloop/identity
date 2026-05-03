package email

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogOnlySendLogsAtWarn(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	tr := NewLogOnly(logger)
	err := tr.Send(context.Background(), Message{
		To:      "user@example.com",
		Subject: "Welcome",
		Text:    "hello there",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Level != zapcore.WarnLevel {
		t.Errorf("level: got %v want warn", e.Level)
	}
	if e.Message != "email_disabled_no_transport" {
		t.Errorf("message: got %q want email_disabled_no_transport", e.Message)
	}

	fields := e.ContextMap()
	if got := fields["to"]; got != "user@example.com" {
		t.Errorf("to field: got %v", got)
	}
	if got := fields["subject"]; got != "Welcome" {
		t.Errorf("subject field: got %v", got)
	}
	if _, ok := fields["preview"]; !ok {
		t.Errorf("missing preview field")
	}
}

func TestLogOnlyTruncatesPreview(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)
	tr := NewLogOnly(logger)

	long := strings.Repeat("a", previewLen+50)
	if err := tr.Send(context.Background(), Message{
		To:      "u@example.com",
		Subject: "S",
		Text:    long,
	}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	got := logs.All()[0].ContextMap()["preview"].(string)
	if len(got) != previewLen {
		t.Fatalf("preview len: got %d want %d", len(got), previewLen)
	}
}

func TestLogOnlyFallsBackToHTMLPreview(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)
	tr := NewLogOnly(logger)

	if err := tr.Send(context.Background(), Message{
		To:      "u@example.com",
		Subject: "S",
		HTML:    "<p>html-only</p>",
	}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	got := logs.All()[0].ContextMap()["preview"].(string)
	if !strings.Contains(got, "html-only") {
		t.Fatalf("expected html preview, got %q", got)
	}
}

func TestLogOnlyValidates(t *testing.T) {
	t.Parallel()

	tr := NewLogOnly(nil) // nil logger should not panic
	err := tr.Send(context.Background(), Message{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("want ErrInvalidMessage, got %v", err)
	}
}
