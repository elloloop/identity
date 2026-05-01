package totp

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func makeKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := EncryptSecret(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptSecret returned error: %v", err)
	}
	if encrypted == "" {
		t.Fatal("EncryptSecret returned empty string")
	}
	if encrypted == plaintext {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := DecryptSecret(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptSecret returned error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_DifferentKeys_Fails(t *testing.T) {
	key1 := makeKey(t)
	key2 := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := EncryptSecret(plaintext, key1)
	if err != nil {
		t.Fatalf("EncryptSecret returned error: %v", err)
	}

	_, err = DecryptSecret(encrypted, key2)
	if err == nil {
		t.Error("DecryptSecret should fail with a different key")
	}
}

func TestEncrypt_DifferentCiphertexts(t *testing.T) {
	key := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	ct1, err := EncryptSecret(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptSecret returned error: %v", err)
	}
	ct2, err := EncryptSecret(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptSecret returned error: %v", err)
	}

	if ct1 == ct2 {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts (nonce uniqueness)")
	}

	// Both should decrypt to the same plaintext
	d1, _ := DecryptSecret(ct1, key)
	d2, _ := DecryptSecret(ct2, key)
	if d1 != plaintext || d2 != plaintext {
		t.Error("both ciphertexts should decrypt to the original plaintext")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key := makeKey(t)
	_, err := DecryptSecret("not-valid-base64!!!", key)
	if err == nil {
		t.Error("DecryptSecret should fail for invalid base64")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := makeKey(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := EncryptSecret(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptSecret returned error: %v", err)
	}

	// Decode, flip a byte, re-encode
	raw, _ := base64.StdEncoding.DecodeString(encrypted)
	if len(raw) > 0 {
		raw[len(raw)-1] ^= 0xFF
	}
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = DecryptSecret(tampered, key)
	if err == nil {
		t.Error("DecryptSecret should fail for tampered ciphertext")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := makeKey(t)

	encrypted, err := EncryptSecret("", key)
	if err != nil {
		t.Fatalf("EncryptSecret returned error for empty plaintext: %v", err)
	}

	decrypted, err := DecryptSecret(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptSecret returned error: %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16)
	_, err := EncryptSecret("test", shortKey)
	if err == nil {
		t.Error("EncryptSecret should fail for non-32-byte key")
	}

	_, err = DecryptSecret("dGVzdA==", shortKey)
	if err == nil {
		t.Error("DecryptSecret should fail for non-32-byte key")
	}
}
