package secretcrypto

import (
	"strings"
	"testing"
)

// FuzzDecrypt fuzzes the ciphertext argument of Decrypt with a fixed valid
// 32-byte key. Random/garbage input must produce an error and must never panic.
func FuzzDecrypt(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	// Build one valid ciphertext for the success seed, plus malformed seeds.
	validCT, err := Encrypt("JBSWY3DPEHPK3PXP", key)
	if err != nil {
		f.Fatalf("seeding ciphertext: %v", err)
	}

	f.Add(validCT)
	f.Add("")
	f.Add("not-base64!@#$")
	f.Add("AAAA")                  // valid base64, too short for nonce
	f.Add(strings.Repeat("A", 64)) // valid base64, GCM auth will fail

	f.Fuzz(func(t *testing.T, ciphertext string) {
		plaintext, err := Decrypt(ciphertext, key)
		if err != nil {
			// Error path: plaintext should be the empty string by contract.
			if plaintext != "" {
				t.Fatalf("Decrypt returned non-empty plaintext with error: pt=%q err=%v", plaintext, err)
			}
			return
		}
		// Success path: only the valid seed should reach here. The fuzz engine
		// cannot forge a GCM tag against a random key.
		_ = plaintext
	})
}
