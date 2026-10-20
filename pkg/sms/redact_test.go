package sms

import "testing"

func TestRedact(t *testing.T) {
	t.Parallel()

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
