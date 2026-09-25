package service

import (
	"strings"
	"testing"
)

func TestFoldEmail(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"alice@example.com":      "alice@example.com",
		"Alice@EXAMPLE.Com":      "alice@example.com",
		"ÉMILE@EXAMPLE.COM":      "Émile@example.com",
		"\u212aATE@example.com":  "\u212aate@example.com", // KELVIN SIGN is not an ASCII letter
		"\u0130STANBUL@x.test":   "\u0130stanbul@x.test",  // nor is a dotted capital I
		"E\u0301MILE@x.test":     "e\u0301mile@x.test",    // a combining accent is kept, its base letter folded
		"\xffBAD@x.test":         "\xffbad@x.test",        // bytes that are not UTF-8 pass through unchanged
		"[]^_`{}@@AZaz09.-+test": "[]^_`{}@@azaz09.-+test",
	} {
		if got := FoldEmail(in); got != want {
			t.Errorf("FoldEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

// On ASCII input the fold is exactly strings.ToLower, over every byte value.
func TestFoldEmail_MatchesToLowerOnASCII(t *testing.T) {
	var b strings.Builder
	for c := 0; c < 0x80; c++ {
		b.WriteByte(byte(c))
	}
	ascii := b.String()
	if got, want := FoldEmail(ascii), strings.ToLower(ascii); got != want {
		t.Fatalf("FoldEmail(ascii) = %q, want %q", got, want)
	}
}

// A folded address folds to itself, so a stored key and a key computed from
// it again never disagree.
func TestFoldEmail_Idempotent(t *testing.T) {
	for _, in := range []string{"Alice@Example.com", "ÉMILE@X.TEST", "\u212aATE@x.test"} {
		once := FoldEmail(in)
		if twice := FoldEmail(once); twice != once {
			t.Errorf("FoldEmail(FoldEmail(%q)) = %q, want %q", in, twice, once)
		}
	}
}
