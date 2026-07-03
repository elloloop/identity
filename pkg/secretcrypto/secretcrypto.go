// Package secretcrypto is the one place the server encrypts small secrets for
// storage at rest. It is a thin, audited wrapper over AES-256-GCM so every
// caller shares the same construction (random nonce, authenticated ciphertext,
// base64 envelope) rather than reimplementing the primitive per feature.
//
// It is used by TOTP secret storage and per-project OAuth provider secrets
// (client secrets, Apple private keys). The key is a 32-byte AES-256 key the
// operator supplies base64-encoded via the config boundary; this package never
// reads the environment itself.
package secretcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize is the required AES-256 key length in bytes.
const KeySize = 32

// ErrKeySize is returned when a supplied key is not exactly KeySize bytes.
var ErrKeySize = errors.New("secretcrypto: encryption key must be exactly 32 bytes")

// Encrypt encrypts plaintext for at-rest storage using AES-256-GCM. The key
// must be exactly KeySize bytes. It returns a base64-encoded string of the
// nonce prepended to the authenticated ciphertext. Each call uses a fresh
// random nonce, so encrypting the same plaintext twice yields distinct
// ciphertexts.
func Encrypt(plaintext string, key []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretcrypto: generating nonce: %w", err)
	}

	// Seal appends the ciphertext to nonce, so sealed = nonce || ciphertext || tag.
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. The key must be exactly KeySize bytes. It returns
// an error if the ciphertext is malformed, truncated, tampered with, or was
// encrypted under a different key.
func Decrypt(ciphertext string, key []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("secretcrypto: decoding base64: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("secretcrypto: ciphertext too short")
	}

	nonce, sealed := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("secretcrypto: decrypting: %w", err)
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretcrypto: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretcrypto: creating GCM: %w", err)
	}
	return gcm, nil
}
