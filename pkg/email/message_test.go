package email

import (
	"errors"
	"testing"
)

func TestMessageValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		msg     Message
		wantErr bool
	}{
		{
			name: "valid html only",
			msg: Message{
				To:      "user@example.com",
				From:    "noreply@example.com",
				Subject: "Hi",
				HTML:    "<p>hi</p>",
			},
		},
		{
			name: "valid text only",
			msg: Message{
				To:      "user@example.com",
				Subject: "Hi",
				Text:    "hi",
			},
		},
		{
			name: "valid named address",
			msg: Message{
				To:      "Alice <alice@example.com>",
				Subject: "Hello",
				Text:    "hi",
			},
		},
		{
			name: "valid both bodies",
			msg: Message{
				To:      "u@example.com",
				Subject: "S",
				HTML:    "<p>x</p>",
				Text:    "x",
			},
		},
		{
			name:    "missing to",
			msg:     Message{Subject: "x", Text: "x"},
			wantErr: true,
		},
		{
			name:    "blank to",
			msg:     Message{To: "   ", Subject: "x", Text: "x"},
			wantErr: true,
		},
		{
			name:    "bad to",
			msg:     Message{To: "not-an-email", Subject: "x", Text: "x"},
			wantErr: true,
		},
		{
			name:    "bad from",
			msg:     Message{To: "user@example.com", From: "garbage@@", Subject: "x", Text: "x"},
			wantErr: true,
		},
		{
			name:    "missing subject",
			msg:     Message{To: "user@example.com", Text: "x"},
			wantErr: true,
		},
		{
			name:    "blank subject",
			msg:     Message{To: "user@example.com", Subject: "  ", Text: "x"},
			wantErr: true,
		},
		{
			name:    "no body",
			msg:     Message{To: "user@example.com", Subject: "x"},
			wantErr: true,
		},
		{
			name:    "whitespace body",
			msg:     Message{To: "user@example.com", Subject: "x", HTML: "  ", Text: "  "},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.msg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidMessage) {
					t.Fatalf("expected ErrInvalidMessage, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewMessage(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		m, err := NewMessage("u@example.com", "f@example.com", "s", "<p>h</p>", "t")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.To != "u@example.com" {
			t.Fatalf("To: got %q want u@example.com", m.To)
		}
	})

	t.Run("invalid wraps sentinel", func(t *testing.T) {
		t.Parallel()
		_, err := NewMessage("", "", "", "", "")
		if err == nil {
			t.Fatalf("expected error")
		}
		if !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("want ErrInvalidMessage, got %v", err)
		}
	})
}
