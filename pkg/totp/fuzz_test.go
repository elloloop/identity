package totp

import (
	"testing"
)

// FuzzVerify fuzzes the user-supplied code argument of VerifyCode.
// Contract:
//   - never panic on any string input;
//   - return false for any code that, after stripping non-digits, is not
//     exactly 6 digits long (these are clearly invalid).
//
// VerifyCode normalizes by stripping non-digit runes, so we mirror that
// rule when asserting clearly-invalid inputs.
func FuzzVerify(f *testing.F) {
	// A throwaway secret is fine — VerifyCode will fail signature checks
	// for fuzzed codes regardless. We only care about the parsing path.
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- deterministic TOTP test vector.

	f.Add("")
	f.Add("123456")
	f.Add("000000")
	f.Add("abcdef")
	f.Add("12345")            // too short
	f.Add("1234567")          // too long
	f.Add("1 2 3 4 5 6")      // digits with whitespace -> 6 digits after strip
	f.Add("\x00\x00\x00\x00") // control bytes

	f.Fuzz(func(t *testing.T, code string) {
		ok := VerifyCode(secret, code)
		// Must not panic — reaching here proves that.

		// Count digits in the input (mirroring VerifyCode's normalization).
		digits := 0
		for _, ch := range code {
			if ch >= '0' && ch <= '9' {
				digits++
			}
		}

		// If the normalized form is not exactly 6 digits, the result must
		// be false. (We don't assert the converse: a 6-digit input may be
		// false too if it doesn't match the current TOTP window.)
		if digits != 6 && ok {
			t.Fatalf("VerifyCode returned true for code %q (normalized digits=%d)", code, digits)
		}
	})
}
