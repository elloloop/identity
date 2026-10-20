package email

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogOnlySendLogsAtWarn(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.WarnLevel)
	tr := NewLogOnly(zap.New(core))
	err := tr.Send(context.Background(), Message{
		To:      "user@example.com",
		Subject: "Welcome",
		Text:    "hello there",
		HTML:    "<p>hello there</p>",
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
	if got := fields["to"]; got != "u***@example.com" {
		t.Errorf("to field: got %v, want the redacted address", got)
	}
	if got := fields["subject"]; got != "Welcome" {
		t.Errorf("subject field: got %v", got)
	}
	if got := fields["text_bytes"]; got != int64(len("hello there")) {
		t.Errorf("text_bytes field: got %v", got)
	}
	if got := fields["html_bytes"]; got != int64(len("<p>hello there</p>")) {
		t.Errorf("html_bytes field: got %v", got)
	}
}

// The log-only transport is the tail of every SMTP chain, so it runs in
// production whenever every provider fails. Its line must never carry the
// credential a sign-in or reset message holds, nor the full address.
func TestLogOnlyNeverLogsTheBodyOrTheFullAddress(t *testing.T) {
	t.Parallel()

	const (
		to   = "alice@example.com"
		code = "731904"
		link = "https://auth.example.test/reset?token=s3cr3t-reset-token"
	)
	for name, m := range map[string]Message{
		"text": {To: to, Subject: "Your sign-in code", Text: "Your code is " + code + ". It expires in 10 minutes."},
		"html": {To: to, Subject: "Reset your password", HTML: `<p><a href="` + link + `">Reset</a></p>`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			core, logs := observer.New(zapcore.WarnLevel)
			if err := NewLogOnly(zap.New(core)).Send(context.Background(), m); err != nil {
				t.Fatalf("Send: %v", err)
			}
			for k, v := range logs.All()[0].ContextMap() {
				s := fmt.Sprint(v)
				for _, secret := range []string{code, "s3cr3t-reset-token", to} {
					if strings.Contains(s, secret) {
						t.Errorf("field %q = %q carries %q", k, s, secret)
					}
				}
			}
		})
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
