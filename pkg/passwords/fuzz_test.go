package passwords

import (
	"testing"
)

// FuzzValidatePasswordStrength fuzzes ValidateStrength with arbitrary strings.
// Contract:
//   - never panic;
//   - empty input must produce at least one issue (clearly invalid);
//   - any input shorter than MinPasswordLength must produce at least one
//     issue mentioning the length requirement.
func FuzzValidatePasswordStrength(f *testing.F) {
	// Seed corpus: a few good and bad passwords plus odd shapes.
	f.Add("")                                 // empty
	f.Add("a")                                // too short
	f.Add("password")                         // common, no upper/digit/special
	f.Add("Str0ng!Password")                  // strong
	f.Add("\x00\x00\x00\x00\x00\x00\x00\x00") // null bytes, length 8
	f.Add("日本語パスワード!Aa1")                     // unicode

	f.Fuzz(func(t *testing.T, pw string) {
		issues := ValidateStrength(pw)
		// Must not panic — reaching here means it didn't.

		// Clearly-invalid: empty string must produce issues.
		if pw == "" && len(issues) == 0 {
			t.Fatalf("expected issues for empty password, got none")
		}

		// A string strictly shorter than MinPasswordLength must produce at
		// least one issue (length-related).
		if len(pw) < MinPasswordLength && len(issues) == 0 {
			t.Fatalf("expected issues for short password (len=%d), got none", len(pw))
		}

		// A string strictly longer than MaxPasswordLength must produce at
		// least one issue (length-related).
		if len(pw) > MaxPasswordLength && len(issues) == 0 {
			t.Fatalf("expected issues for over-long password (len=%d), got none", len(pw))
		}
	})
}

// FuzzHashAndVerify fuzzes the round-trip Hash -> Verify property:
//   - Hash(p) must succeed for any p whose byte length fits within bcrypt's
//     72-byte limit (longer inputs are explicitly rejected by golang.org/x/crypto).
//   - Verify(p, Hash(p)) must return true.
//   - Verify(p2, Hash(p)) must return false when p2 != p (within bcrypt's
//     72-byte truncation horizon).
//   - Neither call must panic on any input.
func FuzzHashAndVerify(f *testing.F) {
	f.Add("password", "Password")
	f.Add("Str0ng!Password", "str0ng!password")
	f.Add("", "x")
	f.Add("a", "b")
	f.Add("MyP@ssw0rd!", "MyP@ssw0rd?")

	f.Fuzz(func(t *testing.T, p1, p2 string) {
		// bcrypt rejects passwords longer than 72 bytes outright. This is
		// part of the documented contract, not a panic. Skip those inputs
		// — they're not in scope for round-trip verification.
		if len(p1) > 72 || len(p2) > 72 {
			return
		}

		hash, err := Hash(p1)
		if err != nil {
			t.Fatalf("Hash(%q) returned error: %v", p1, err)
		}

		if !Verify(p1, hash) {
			t.Fatalf("Verify(%q, hash) returned false; expected true", p1)
		}

		// Negative case: only assert when the two passwords differ.
		// Note: bcrypt truncates at 72 bytes, but with both lengths capped
		// at 72 above, byte-equal strings are the only collision risk.
		if p1 != p2 {
			if Verify(p2, hash) {
				t.Fatalf("Verify(%q, Hash(%q)) returned true; expected false", p2, p1)
			}
		}
	})
}
