package templatemsg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/sms"
)

func TestMessage_Validate(t *testing.T) {
	t.Parallel()
	ok := Message{To: "+14155550123", Template: "verification_code", Params: []string{"482915"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate(%+v): %v", ok, err)
	}
	for name, m := range map[string]Message{
		"no number":       {Template: "verification_code"},
		"no plus":         {To: "14155550123", Template: "verification_code"},
		"letters":         {To: "+1415555O123", Template: "verification_code"},
		"sixteen digits":  {To: "+1234567890123456", Template: "verification_code"},
		"no template":     {To: "+14155550123"},
		"blank template":  {To: "+14155550123", Template: "  "},
		"plus alone":      {To: "+", Template: "verification_code"},
		"spaces in digit": {To: "+1 415 555 0123", Template: "verification_code"},
	} {
		if err := m.Validate(); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: want ErrInvalidMessage, got %v", name, err)
		}
	}
}

// The log-only sender is what runs when no provider is wired; its line must
// never carry the one-time code or the full number.
func TestLogOnlySender_LogsNeitherTheParamsNorTheNumber(t *testing.T) {
	t.Parallel()
	core, logs := observer.New(zapcore.WarnLevel)
	const (
		number = "+14155550123"
		code   = "482915"
	)
	m := Message{To: number, Template: "verification_code", Language: "en", Params: []string{code}}
	if err := NewLogOnly(zap.New(core)).Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if logs.Len() != 1 {
		t.Fatalf("got %d log entries, want 1", logs.Len())
	}
	fields := logs.All()[0].ContextMap()
	if fields["to"] != sms.Redact(number) || fields["template"] != "verification_code" {
		t.Errorf("fields = %v, want the redacted number and the template's name", fields)
	}
	for k, v := range fields {
		if s := fmt.Sprint(v); strings.Contains(s, code) || strings.Contains(s, number) {
			t.Errorf("field %q = %q carries the code or the full number", k, s)
		}
	}
}

func TestLogOnlySender_RefusesAMalformedMessageAndTakesANilLogger(t *testing.T) {
	t.Parallel()
	s := NewLogOnly(nil)
	if err := s.Send(context.Background(), Message{To: "nope", Template: "t"}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("malformed message: want ErrInvalidMessage, got %v", err)
	}
	if err := s.Send(context.Background(), Message{To: "+14155550123", Template: "t"}); err != nil {
		t.Fatalf("Send with a nil logger: %v", err)
	}
}
