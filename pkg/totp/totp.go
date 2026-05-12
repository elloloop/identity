// Package totp provides TOTP (RFC 6238) utilities for two-factor authentication.
//
// Features:
//   - 6-digit codes, 30-second window, base32 secrets
//   - Recovery codes in 10-character RFC 4648 base32 format,
//     stored as HMAC-SHA-256(pepper, code) — never as raw or salted hashes
//   - Secret encryption at rest using AES-GCM
//
// Security:
//   - Adjacent window of +/-1 (~30s) absorbs clock drift
//   - Recovery code hashes require a server-side pepper; a leaked DB
//     dump alone is insufficient to brute-force codes offline
//   - All comparisons of recovery hashes use hmac.Equal (constant-time)
//   - No secrets are ever logged
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// RecoveryCodeLength is the number of characters in a recovery code.
// 10 chars of RFC 4648 base32 = 50 bits of entropy, drawn directly
// from crypto/rand.
const RecoveryCodeLength = 10

// MinRecoveryPepperBytes is the minimum length (in raw bytes, post
// base64 decode) accepted for the recovery-code pepper. 32 bytes is
// the natural HMAC-SHA-256 key size.
const MinRecoveryPepperBytes = 32

// GenerateSecret returns a fresh base32 TOTP secret (160-bit / 32-char).
func GenerateSecret() (string, error) {
	// 20 random bytes = 160 bits. Encode as base32 = 32 chars.
	// This matches Google Authenticator's default key strength.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Glassa",
		AccountName: "placeholder",
		SecretSize:  20,
	})
	if err != nil {
		return "", fmt.Errorf("generating TOTP secret: %w", err)
	}
	return key.Secret(), nil
}

// GenerateQRURI builds an otpauth:// provisioning URI suitable for QR codes.
//
// Format (RFC 6238 / Google Authenticator spec):
//
//	otpauth://totp/{issuer}:{email}?secret=...&issuer={issuer}&algorithm=SHA1&digits=6&period=30
func GenerateQRURI(secret, email, issuer string) string {
	label := fmt.Sprintf("%s:%s", issuer, email)
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(label) + "?" + params.Encode()
}

// VerifyCode verifies a 6-digit TOTP code against the secret.
// It checks the current time step plus +/-1 window (for clock drift).
func VerifyCode(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	// Normalize: strip whitespace and non-digit chars, keep digits only
	var stripped strings.Builder
	for _, ch := range code {
		if ch >= '0' && ch <= '9' {
			stripped.WriteRune(ch)
		}
	}
	if stripped.Len() != 6 {
		return false
	}

	valid, err := totp.ValidateCustom(stripped.String(), secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // +/-1 window
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return valid
}

// GenerateRecoveryCodes returns n cryptographically-random recovery codes.
// Each code is RecoveryCodeLength characters drawn from the RFC 4648
// base32 alphabet, giving 50 bits of entropy per code.
func GenerateRecoveryCodes(n int) []string {
	if n <= 0 {
		return nil
	}
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		codes = append(codes, generateRecoveryCode())
	}
	return codes
}

func generateRecoveryCode() string {
	// 10 base32 chars carry 50 bits, so we need at least 7 random
	// bytes (56 bits). Take 8 bytes to leave headroom for the encoder.
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	return enc[:RecoveryCodeLength]
}

// normalizeRecoveryCode canonicalizes a recovery code: uppercase, no
// separators, no whitespace. This makes hashing deterministic
// regardless of how the user pastes the code back.
func normalizeRecoveryCode(code string) string {
	if code == "" {
		return ""
	}
	var b strings.Builder
	for _, ch := range strings.ToUpper(code) {
		if (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// HashRecoveryCode returns hex(HMAC-SHA-256(pepper, canonical(code))).
//
// The pepper is a server-side secret loaded from configuration; an
// attacker who exfiltrates only the database cannot brute-force codes
// offline without it. Empty code or insufficiently-long pepper
// returns the empty string so callers can reject the hash before it
// is stored.
func HashRecoveryCode(code string, pepper []byte) string {
	canonical := normalizeRecoveryCode(code)
	if canonical == "" || len(pepper) < MinRecoveryPepperBytes {
		return ""
	}
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyRecoveryCode checks a recovery code against a stored HMAC-SHA-256
// hash. Comparison uses hmac.Equal, which is constant-time over the
// length of the inputs.
func VerifyRecoveryCode(code, hash string, pepper []byte) bool {
	computed := HashRecoveryCode(code, pepper)
	if computed == "" || hash == "" {
		return false
	}
	return hmac.Equal([]byte(computed), []byte(hash))
}
