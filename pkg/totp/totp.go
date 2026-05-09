// Package totp provides TOTP (RFC 6238) utilities for two-factor authentication.
//
// Features:
//   - 6-digit codes, 30-second window, base32 secrets
//   - Recovery codes in XXXX-XXXX-XXXX format (SHA-256 hashed at rest)
//   - Secret encryption at rest using AES-GCM
//
// Security:
//   - Adjacent window of +/-1 (~30s) absorbs clock drift
//   - Recovery codes use a 32-char alphabet (no 0/O/1/I) for readability
//   - All comparisons of hashes use constant-time comparison
//   - No secrets are ever logged
package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// recoveryAlphabet excludes 0/O/1/I for readability.
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

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

// GenerateRecoveryCodes returns n cryptographically-random recovery codes
// in XXXX-XXXX-XXXX format. Each code uses a 32-char alphabet for 60 bits
// of entropy, matching Google/Microsoft backup-code strength.
func GenerateRecoveryCodes(n int) []string {
	if n <= 0 {
		return nil
	}
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 12)
		if _, err := rand.Read(raw); err != nil {
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		chars := make([]byte, 12)
		for j := 0; j < 12; j++ {
			chars[j] = recoveryAlphabet[int(raw[j])%len(recoveryAlphabet)]
		}
		code := fmt.Sprintf("%s-%s-%s", string(chars[0:4]), string(chars[4:8]), string(chars[8:12]))
		codes = append(codes, code)
	}
	return codes
}

// normalizeRecoveryCode canonicalizes a recovery code: uppercase, no dashes,
// no whitespace. This ensures hashing is deterministic regardless of input format.
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

// HashRecoveryCode returns the SHA-256 hex digest of the canonicalized recovery code.
func HashRecoveryCode(code string) string {
	canonical := normalizeRecoveryCode(code)
	if canonical == "" {
		return ""
	}
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// VerifyRecoveryCode checks a recovery code against a stored SHA-256 hash
// using constant-time comparison to prevent timing attacks.
func VerifyRecoveryCode(code, hash string) bool {
	computed := HashRecoveryCode(code)
	if computed == "" || hash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}
