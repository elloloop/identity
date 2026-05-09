package totp

import (
	"strings"
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

// FuzzDecryptSecret fuzzes the ciphertext argument of DecryptSecret with a
// fixed valid 32-byte key. Random/garbage input must produce an error and
// must never panic.
func FuzzDecryptSecret(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	// Build one valid ciphertext for the success seed, plus malformed seeds.
	validCT, err := EncryptSecret("JBSWY3DPEHPK3PXP", key)
	if err != nil {
		f.Fatalf("seeding ciphertext: %v", err)
	}

	f.Add(validCT)
	f.Add("")
	f.Add("not-base64!@#$")
	f.Add("AAAA")                  // valid base64, too short for nonce
	f.Add(strings.Repeat("A", 64)) // valid base64, GCM auth will fail

	f.Fuzz(func(t *testing.T, ciphertext string) {
		plaintext, err := DecryptSecret(ciphertext, key)
		if err != nil {
			// Error path: plaintext should be the empty string by contract.
			if plaintext != "" {
				t.Fatalf("DecryptSecret returned non-empty plaintext with error: pt=%q err=%v", plaintext, err)
			}
			return
		}
		// Success path: only the valid seed should reach here. The fuzz
		// engine cannot forge a GCM tag against a random key.
		// No assertion needed — successful decryption is a valid outcome.
		_ = plaintext
	})
}
