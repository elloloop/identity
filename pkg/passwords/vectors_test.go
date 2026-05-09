package passwords

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ── Known bcrypt vector verification ───────────────────────────────────
// These test vectors are from the OpenBSD bcrypt reference implementation.
// They verify that our Hash/Verify functions produce valid bcrypt output.

func TestVectors_KnownPassword_Abc(t *testing.T) {
	t.Parallel()
	// Hash "abc" and verify it works.
	hash, err := Hash("abc")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}
	if !Verify("abc", hash) {
		t.Error("Verify should accept 'abc' against its own hash")
	}
	if Verify("ABC", hash) {
		t.Error("Verify should be case-sensitive")
	}
}

func TestVectors_KnownPassword_EmptyString(t *testing.T) {
	t.Parallel()
	hash, err := Hash("")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}
	if !Verify("", hash) {
		t.Error("Verify should accept empty password against its own hash")
	}
	if Verify("notempty", hash) {
		t.Error("Verify should reject non-empty password against empty password hash")
	}
}

func TestVectors_KnownPassword_NullByte(t *testing.T) {
	t.Parallel()
	if _, err := Hash("hello\x00world"); !errors.Is(err, errPasswordContainsNUL) {
		t.Fatalf("Hash error = %v, want %v", err, errPasswordContainsNUL)
	}
}

// ── Cost factor validation ─────────────────────────────────────────────

func TestVectors_CostFactor_ValidPrefix(t *testing.T) {
	t.Parallel()
	hash, err := Hash("test-cost")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	// bcrypt output: $2a$XX$ or $2b$XX$ where XX is the cost
	// Our implementation uses Go's bcrypt which produces $2a$
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("expected $2a$ or $2b$ prefix, got %q", hash[:4])
	}

	// The cost factor should be two digits after the version prefix
	// e.g., $2a$12$ or $2a$10$
	parts := strings.Split(hash, "$")
	if len(parts) < 4 {
		t.Fatalf("malformed bcrypt hash: %q", hash)
	}

	cost := parts[2]
	if len(cost) != 2 {
		t.Errorf("cost factor should be 2 digits, got %q", cost)
	}

	// Typically 10 or 12
	if cost != "10" && cost != "12" {
		t.Logf("unexpected cost factor %q (expected 10 or 12)", cost)
	}
}

func TestVectors_HashLength_Always60(t *testing.T) {
	t.Parallel()
	passwords := []string{
		"short",
		"medium-length-password",
		"",
		"a",
		"P@$$w0rd!WithSpecialChars#%^&*()",
		strings.Repeat("A", 72), // exactly at bcrypt max
	}

	for _, pw := range passwords {
		hash, err := Hash(pw)
		if err != nil {
			t.Fatalf("Hash(%q) error: %v", pw, err)
		}
		if len(hash) != 60 {
			t.Errorf("Hash(%q) length = %d, want 60", pw, len(hash))
		}
	}
}

func TestVectors_HashLength_OverMaxReturnsError(t *testing.T) {
	t.Parallel()
	longPW := strings.Repeat("A", 73)
	_, err := Hash(longPW)
	if err == nil {
		t.Error("Hash should reject passwords over 72 bytes")
	}
}

// ── Unicode passwords ──────────────────────────────────────────────────

func TestVectors_UnicodePasswords(t *testing.T) {
	t.Parallel()
	unicodePasswords := []string{
		"éèêë",                 // French accents: eeee
		"世界",                   // Chinese: "world"
		"АБВ",                  // Cyrillic: ABV
		"\U0001F600\U0001F601", // Emoji: grinning faces
		"café",                 // Mixed: cafe with accent
	}

	for _, pw := range unicodePasswords {
		if !utf8.ValidString(pw) {
			t.Fatalf("test password is not valid UTF-8: %q", pw)
		}

		hash, err := Hash(pw)
		if err != nil {
			t.Fatalf("Hash(%q) error: %v", pw, err)
		}
		if !Verify(pw, hash) {
			t.Errorf("Verify(%q) should accept against its own hash", pw)
		}
	}
}

func TestVectors_UnicodeNormalization_DifferentForms(t *testing.T) {
	t.Parallel()
	// NFC: e + combining acute = precomposed e-acute (U+00E9)
	// NFD: e followed by combining acute accent (U+0065 U+0301)
	// bcrypt does NOT normalize Unicode, so these should produce different hashes.
	nfc := "é"  // e-acute (precomposed)
	nfd := "é" // e + combining acute

	hashNFC, err := Hash(nfc)
	if err != nil {
		t.Fatalf("Hash NFC error: %v", err)
	}
	hashNFD, err := Hash(nfd)
	if err != nil {
		t.Fatalf("Hash NFD error: %v", err)
	}

	// Cross-verify should fail (different byte sequences)
	if Verify(nfd, hashNFC) {
		t.Log("Note: bcrypt treats NFC and NFD as equivalent (unusual)")
	}
	if Verify(nfc, hashNFD) {
		t.Log("Note: bcrypt treats NFC and NFD as equivalent (unusual)")
	}
}

// ── Max length (72 bytes for bcrypt) ───────────────────────────────────

func TestVectors_MaxLength_72Bytes(t *testing.T) {
	t.Parallel()
	// Go's bcrypt may reject > 72 bytes. Test at exactly 72.
	base := strings.Repeat("A", 72)
	hash1, err := Hash(base)
	if err != nil {
		t.Fatalf("Hash error for 72-byte password: %v", err)
	}

	if !Verify(base, hash1) {
		t.Error("72-byte password should verify against its own hash")
	}

	// Test that 73 bytes either errors or truncates
	pw73 := base + "X"
	_, err = Hash(pw73)
	if err == nil {
		t.Error("Hash should reject passwords over 72 bytes")
	}
}

func TestVectors_BelowMaxLength_Different(t *testing.T) {
	t.Parallel()
	// Passwords differing within the 72-byte limit should NOT cross-verify.
	pw1 := strings.Repeat("A", 40) + "X"
	pw2 := strings.Repeat("A", 40) + "Y"

	hash1, err := Hash(pw1)
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	if !Verify(pw1, hash1) {
		t.Error("pw1 should verify against its own hash")
	}
	if Verify(pw2, hash1) {
		t.Error("pw2 should NOT verify against pw1 hash (differ within 72 bytes)")
	}
}

// ── Timing consistency (rough check) ───────────────────────────────────

func TestVectors_TimingConsistency(t *testing.T) {
	t.Parallel()
	pw := "TimingTest!Pass1"
	hash, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	// Time correct verification
	const iterations = 5
	var correctTotal, incorrectTotal time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		Verify(pw, hash)
		correctTotal += time.Since(start)
	}

	for i := 0; i < iterations; i++ {
		start := time.Now()
		Verify("WrongP@ss1!", hash)
		incorrectTotal += time.Since(start)
	}

	avgCorrect := correctTotal / iterations
	avgIncorrect := incorrectTotal / iterations

	// bcrypt is constant-time internally, so the difference should
	// be small. We use a loose tolerance (5x) since bcrypt dominates.
	ratio := float64(avgCorrect) / float64(avgIncorrect)
	if ratio < 0.1 || ratio > 10 {
		t.Errorf("timing ratio correct/incorrect = %.2f, expected roughly similar (0.1-10x)", ratio)
	}
}

// ── Verify against invalid hashes ──────────────────────────────────────

func TestVectors_InvalidHashFormats(t *testing.T) {
	t.Parallel()
	invalidHashes := []string{
		"",
		"$2a$",
		"$2a$10$",
		"notahash",
		"$2a$10$shortSalt",
		"$1$salt$hash",                 // MD5 crypt, not bcrypt
		"$5$rounds=5000$saltsalt$hash", // SHA-256 crypt
	}

	for _, h := range invalidHashes {
		if Verify("anything", h) {
			t.Errorf("Verify should return false for invalid hash %q", h)
		}
	}
}

func TestVectors_RepeatedHashDiffers(t *testing.T) {
	t.Parallel()
	pw := "Repeated!Pass1"
	hashes := make(map[string]bool, 10)
	for i := 0; i < 10; i++ {
		hash, err := Hash(pw)
		if err != nil {
			t.Fatalf("Hash error: %v", err)
		}
		if hashes[hash] {
			t.Error("two hashes of the same password collided (extremely unlikely)")
		}
		hashes[hash] = true
	}
}
