package email

import "testing"

func TestRedact(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alice@example.com", "a***@example.com"},
		{"a@example.com", "a***@example.com"},
		{"", ""},
		{"no-at-sign", "no-at-sign"},
		{"@nodomain", "@nodomain"},
		{"bob.smith+tag@sub.example.co.uk", "b***@sub.example.co.uk"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
