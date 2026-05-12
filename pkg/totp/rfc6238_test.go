package totp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ── RFC 6238 Appendix B Test Vectors ───────────────────────────────────
//
// RFC 6238 defines official test vectors for TOTP (SHA1).
// The test secret is "12345678901234567890" (20 bytes) encoded as base32.
// The expected values below are the full 8-digit TOTP codes from the RFC.
// Our implementation uses 6-digit SHA1 codes via pquerna/otp, so we:
//   - Generate the full code using the RFC test secret
//   - Verify the last 6 digits match the truncated RFC expectation

// RFC 6238 test secret: ASCII "12345678901234567890" base32-encoded.
const rfcTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // #nosec G101 -- RFC 6238 test vector.

func rfcGenerateCode(t *testing.T, secret string, timestamp time.Time, digits otp.Digits) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, timestamp, totp.ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    digits,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generating RFC test code: %v", err)
	}
	return code
}

func TestRFC6238_Vector_Time59(t *testing.T) {
	t.Parallel()
	ts := time.Unix(59, 0)
	code := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsEight)
	// RFC 6238 Appendix B: SHA1, time=59 -> 94287082
	if code != "94287082" {
		t.Errorf("time=59: got %s, want 94287082", code)
	}

	// 6-digit truncation: last 6 digits
	code6 := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsSix)
	// 6-digit version should be 287082
	if code6 != "287082" {
		t.Errorf("time=59 (6-digit): got %s, want 287082", code6)
	}
}

func TestRFC6238_Vector_Time1111111109(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1111111109, 0)
	code := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsEight)
	// RFC 6238: 07081804
	if code != "07081804" {
		t.Errorf("time=1111111109: got %s, want 07081804", code)
	}
}

func TestRFC6238_Vector_Time1111111111(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1111111111, 0)
	code := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsEight)
	// RFC 6238: 14050471
	if code != "14050471" {
		t.Errorf("time=1111111111: got %s, want 14050471", code)
	}
}

func TestRFC6238_Vector_Time1234567890(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1234567890, 0)
	code := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsEight)
	// RFC 6238: 89005924
	if code != "89005924" {
		t.Errorf("time=1234567890: got %s, want 89005924", code)
	}
}

func TestRFC6238_Vector_Time2000000000(t *testing.T) {
	t.Parallel()
	ts := time.Unix(2000000000, 0)
	code := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsEight)
	// RFC 6238: 69279037
	if code != "69279037" {
		t.Errorf("time=2000000000: got %s, want 69279037", code)
	}
}

func TestRFC6238_Vector_Time20000000000(t *testing.T) {
	t.Parallel()
	ts := time.Unix(20000000000, 0)
	code := rfcGenerateCode(t, rfcTestSecret, ts, otp.DigitsEight)
	// RFC 6238: 65353130
	if code != "65353130" {
		t.Errorf("time=20000000000: got %s, want 65353130", code)
	}
}

// ── Our VerifyCode function with live secret ───────────────────────────

func TestRFC6238_VerifyCode_WithLiveSecret(t *testing.T) {
	t.Parallel()
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	now := time.Now()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generating code: %v", err)
	}

	if !VerifyCode(secret, code) {
		t.Errorf("VerifyCode should accept freshly generated code %s", code)
	}
}

// ── Recovery code format ───────────────────────────────────────────────

func TestRFC6238_RecoveryCodeFormat(t *testing.T) {
	t.Parallel()
	pattern := regexp.MustCompile(`^[A-Z2-7]{10}$`)
	codes := GenerateRecoveryCodes(100)

	for _, code := range codes {
		if !pattern.MatchString(code) {
			t.Errorf("code %q is not 10 chars of RFC 4648 base32", code)
		}
		if len(code) != RecoveryCodeLength {
			t.Errorf("code %q length = %d, want %d", code, len(code), RecoveryCodeLength)
		}
	}
}

func TestRFC6238_RecoveryCodeEntropy(t *testing.T) {
	t.Parallel()
	// RFC 4648 base32 alphabet: A-Z (26) + 2-7 (6) = 32 characters.
	// 10 positions: 32^10 = 2^50 ≈ 1.13 * 10^15 combinations.
	// Minimum acceptable for backup codes: 1e12 (~40 bits).
	charsetSize := 32
	positions := RecoveryCodeLength
	combinations := 1.0
	for i := 0; i < positions; i++ {
		combinations *= float64(charsetSize)
	}

	minRequired := 1e12
	if combinations < minRequired {
		t.Errorf("recovery code entropy: %.2e combinations < %.2e required", combinations, minRequired)
	}
}

func TestRFC6238_RecoveryCode_NoDuplicates(t *testing.T) {
	t.Parallel()
	codes := GenerateRecoveryCodes(200)
	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		if seen[code] {
			t.Errorf("duplicate recovery code: %s", code)
		}
		seen[code] = true
	}
}

// ── AES-GCM encryption: ciphertext length ──────────────────────────────

func TestRFC6238_AESGCM_CiphertextLength(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	testCases := []string{
		"short",
		"JBSWY3DPEHPK3PXP",
		"A" + fmt.Sprintf("%0160d", 0), // longer plaintext
	}

	for _, plaintext := range testCases {
		encrypted, err := EncryptSecret(plaintext, key)
		if err != nil {
			t.Fatalf("EncryptSecret(%q): %v", plaintext, err)
		}

		// Decrypt raw ciphertext to check its structure.
		raw, err := base64.StdEncoding.DecodeString(encrypted)
		if err != nil {
			t.Fatalf("decoding base64: %v", err)
		}

		// AES-GCM: ciphertext = nonce(12) + ciphertext(len(plaintext)) + tag(16)
		expectedLen := 12 + len(plaintext) + 16
		if len(raw) != expectedLen {
			t.Errorf("for plaintext len %d: raw ciphertext len = %d, want %d (12+%d+16)",
				len(plaintext), len(raw), expectedLen, len(plaintext))
		}
	}
}

func TestRFC6238_AESGCM_NonceUniqueness(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	plaintext := "JBSWY3DPEHPK3PXP"
	nonces := make(map[string]bool)

	for i := 0; i < 50; i++ {
		encrypted, err := EncryptSecret(plaintext, key)
		if err != nil {
			t.Fatalf("EncryptSecret: %v", err)
		}

		raw, _ := base64.StdEncoding.DecodeString(encrypted)
		nonce := string(raw[:12])
		if nonces[nonce] {
			t.Error("nonce reuse detected (extremely unlikely)")
		}
		nonces[nonce] = true
	}
}

func TestRFC6238_AESGCM_DecryptionPreservesPlaintext(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	plaintexts := []string{
		"",
		"A",
		"JBSWY3DPEHPK3PXP",
		"Hello, World! 12345",
	}

	for _, pt := range plaintexts {
		encrypted, err := EncryptSecret(pt, key)
		if err != nil {
			t.Fatalf("EncryptSecret(%q): %v", pt, err)
		}
		decrypted, err := DecryptSecret(encrypted, key)
		if err != nil {
			t.Fatalf("DecryptSecret: %v", err)
		}
		if decrypted != pt {
			t.Errorf("round-trip failed: got %q, want %q", decrypted, pt)
		}
	}
}
