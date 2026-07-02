package secretcrypto

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func makeKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypt returned empty string")
	}
	if encrypted == plaintext {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_DifferentKeys_Fails(t *testing.T) {
	key1 := makeKey(t)
	key2 := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	_, err = Decrypt(encrypted, key2)
	if err == nil {
		t.Error("Decrypt should fail with a different key")
	}
}

func TestEncrypt_DifferentCiphertexts(t *testing.T) {
	key := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	ct1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	ct2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	if ct1 == ct2 {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts (nonce uniqueness)")
	}

	d1, _ := Decrypt(ct1, key)
	d2, _ := Decrypt(ct2, key)
	if d1 != plaintext || d2 != plaintext {
		t.Error("both ciphertexts should decrypt to the original plaintext")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key := makeKey(t)
	_, err := Decrypt("not-valid-base64!!!", key)
	if err == nil {
		t.Error("Decrypt should fail for invalid base64")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := makeKey(t)
	// Valid base64 but shorter than a GCM nonce.
	_, err := Decrypt(base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}), key)
	if err == nil {
		t.Error("Decrypt should fail for a ciphertext shorter than the nonce")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	raw, _ := base64.StdEncoding.DecodeString(encrypted)
	if len(raw) > 0 {
		raw[len(raw)-1] ^= 0xFF
	}
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = Decrypt(tampered, key)
	if err == nil {
		t.Error("Decrypt should fail for tampered ciphertext")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := makeKey(t)

	encrypted, err := Encrypt("", key)
	if err != nil {
		t.Fatalf("Encrypt returned error for empty plaintext: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestEncrypt_CiphertextStructure(t *testing.T) {
	key := makeKey(t)
	for _, plaintext := range []string{"short", "JBSWY3DPEHPK3PXP", strings.Repeat("x", 160)} {
		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		raw, err := base64.StdEncoding.DecodeString(encrypted)
		if err != nil {
			t.Fatalf("decoding base64: %v", err)
		}
		// AES-GCM envelope: nonce(12) + ciphertext(len(plaintext)) + tag(16).
		want := 12 + len(plaintext) + 16
		if len(raw) != want {
			t.Errorf("plaintext len %d: raw len = %d, want %d", len(plaintext), len(raw), want)
		}
	}
}

func TestEncrypt_NonceUniquenessOverMany(t *testing.T) {
	key := makeKey(t)
	nonces := make(map[string]bool)
	for i := 0; i < 50; i++ {
		encrypted, err := Encrypt("JBSWY3DPEHPK3PXP", key)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		raw, _ := base64.StdEncoding.DecodeString(encrypted)
		nonce := string(raw[:12])
		if nonces[nonce] {
			t.Error("nonce reuse detected (extremely unlikely)")
		}
		nonces[nonce] = true
	}
}

func TestEncryptDecrypt_LargeAndUnicode(t *testing.T) {
	key := makeKey(t)
	plain := strings.Repeat("Σπρτ-✓-", 32)
	ct, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ct, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plain {
		t.Errorf("round-trip failed: got %q, want %q", got, plain)
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16)
	_, err := Encrypt("test", shortKey)
	if err == nil {
		t.Error("Encrypt should fail for non-32-byte key")
	}

	_, err = Decrypt("dGVzdA==", shortKey)
	if err == nil {
		t.Error("Decrypt should fail for non-32-byte key")
	}
}
