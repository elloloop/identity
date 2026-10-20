package sms

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"+15551234567": "+1********67",
		"+123":         "***", // <= 4 chars
		"":             "***",
		"+123456":      "+1***56",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// The log-only sender runs whenever SMS is not enabled; its line must never
// carry the one-time code in the body or the full number.
func TestLogOnlySender_LogsNeitherTheBodyNorTheNumber(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	const (
		number = "+14155550123"
		code   = "482915"
	)
	if err := NewLogOnly(zap.New(core)).Send(context.Background(), Message{To: number, Body: "Your verification code is " + code}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if logs.Len() != 1 {
		t.Fatalf("got %d log entries, want 1", logs.Len())
	}
	fields := logs.All()[0].ContextMap()
	if fields["to"] != Redact(number) {
		t.Errorf("to = %v, want the redacted number", fields["to"])
	}
	for k, v := range fields {
		s := fmt.Sprint(v)
		if strings.Contains(s, code) || strings.Contains(s, number) {
			t.Errorf("field %q = %q carries the code or the full number", k, s)
		}
	}
}
