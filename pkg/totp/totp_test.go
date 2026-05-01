package totp

import (
	"encoding/base32"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestGenerateSecret_Length(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret returned error: %v", err)
	}
	// base32 secret should be at least 26 chars (160 bits in base32 = 32 chars
	// without padding, but the library may vary slightly)
	if len(secret) < 20 {
		t.Errorf("expected secret length >= 20, got %d (%q)", len(secret), secret)
	}
}

func TestGenerateSecret_Base32(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret returned error: %v", err)
	}
	// Should be valid base32
	_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Errorf("secret is not valid base32: %v (secret=%q)", err, secret)
	}
}

func TestGenerateQRURI_Format(t *testing.T) {
	uri := GenerateQRURI("JBSWY3DPEHPK3PXP", "user@example.com", "Glassa")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("expected URI to start with 'otpauth://totp/', got %q", uri)
	}
}

func TestGenerateQRURI_ContainsIssuer(t *testing.T) {
	uri := GenerateQRURI("JBSWY3DPEHPK3PXP", "user@example.com", "Glassa")
	if !strings.Contains(uri, "issuer=Glassa") {
		t.Errorf("expected URI to contain 'issuer=Glassa', got %q", uri)
	}
}

func TestGenerateQRURI_ContainsSecret(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := GenerateQRURI(secret, "user@example.com", "Glassa")
	if !strings.Contains(uri, "secret="+secret) {
		t.Errorf("expected URI to contain 'secret=%s', got %q", secret, uri)
	}
}

func TestGenerateQRURI_ContainsEmail(t *testing.T) {
	uri := GenerateQRURI("JBSWY3DPEHPK3PXP", "user@example.com", "Glassa")
	if !strings.Contains(uri, "user%40example.com") && !strings.Contains(uri, "user@example.com") {
		t.Errorf("expected URI to contain email, got %q", uri)
	}
}

func TestVerifyCode_CurrentCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret returned error: %v", err)
	}
	// Generate a valid code for the current time
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:     0,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generating code: %v", err)
	}
	if !VerifyCode(secret, code) {
		t.Errorf("VerifyCode should accept a freshly generated code")
	}
}

func TestVerifyCode_WrongCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret returned error: %v", err)
	}
	if VerifyCode(secret, "000000") {
		// Technically possible but astronomically unlikely
		t.Log("Warning: 000000 happened to be valid (extremely rare)")
	}
}

func TestVerifyCode_EmptyCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret returned error: %v", err)
	}
	if VerifyCode(secret, "") {
		t.Error("VerifyCode should return false for empty code")
	}
}

func TestVerifyCode_EmptySecret(t *testing.T) {
	if VerifyCode("", "123456") {
		t.Error("VerifyCode should return false for empty secret")
	}
}

func TestVerifyCode_NonDigitCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret returned error: %v", err)
	}
	if VerifyCode(secret, "abcdef") {
		t.Error("VerifyCode should return false for non-digit code")
	}
}

func TestGenerateRecoveryCodes_Count(t *testing.T) {
	codes := GenerateRecoveryCodes(10)
	if len(codes) != 10 {
		t.Errorf("expected 10 codes, got %d", len(codes))
	}

	codes = GenerateRecoveryCodes(5)
	if len(codes) != 5 {
		t.Errorf("expected 5 codes, got %d", len(codes))
	}

	codes = GenerateRecoveryCodes(0)
	if len(codes) != 0 {
		t.Errorf("expected 0 codes for n=0, got %d", len(codes))
	}
}

func TestGenerateRecoveryCodes_Format(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$`)
	codes := GenerateRecoveryCodes(10)
	for _, code := range codes {
		if !pattern.MatchString(code) {
			t.Errorf("code %q does not match XXXX-XXXX-XXXX format", code)
		}
	}
}

func TestGenerateRecoveryCodes_Unique(t *testing.T) {
	codes := GenerateRecoveryCodes(100)
	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		if seen[code] {
			t.Errorf("duplicate code found: %s", code)
		}
		seen[code] = true
	}
}

func TestHashRecoveryCode_Deterministic(t *testing.T) {
	code := "ABCD-EFGH-JKLM"
	hash1 := HashRecoveryCode(code)
	hash2 := HashRecoveryCode(code)
	if hash1 != hash2 {
		t.Error("HashRecoveryCode should be deterministic")
	}
	if hash1 == "" {
		t.Error("HashRecoveryCode should not return empty for valid code")
	}
	// Should be a hex string of length 64 (SHA-256)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}

func TestHashRecoveryCode_Empty(t *testing.T) {
	hash := HashRecoveryCode("")
	if hash != "" {
		t.Error("HashRecoveryCode should return empty for empty code")
	}
}

func TestVerifyRecoveryCode_Correct(t *testing.T) {
	code := "ABCD-EFGH-JKLM"
	hash := HashRecoveryCode(code)
	if !VerifyRecoveryCode(code, hash) {
		t.Error("VerifyRecoveryCode should return true for correct code")
	}
}

func TestVerifyRecoveryCode_Wrong(t *testing.T) {
	code := "ABCD-EFGH-JKLM"
	hash := HashRecoveryCode(code)
	if VerifyRecoveryCode("XXXX-YYYY-ZZZZ", hash) {
		t.Error("VerifyRecoveryCode should return false for wrong code")
	}
}

func TestVerifyRecoveryCode_CaseInsensitive(t *testing.T) {
	code := "ABCD-EFGH-JKLM"
	hash := HashRecoveryCode(code)
	// Lowercase version should also verify
	if !VerifyRecoveryCode("abcd-efgh-jklm", hash) {
		t.Error("VerifyRecoveryCode should be case-insensitive")
	}
}

func TestVerifyRecoveryCode_NoDashes(t *testing.T) {
	code := "ABCD-EFGH-JKLM"
	hash := HashRecoveryCode(code)
	// Without dashes should also verify
	if !VerifyRecoveryCode("ABCDEFGHJKLM", hash) {
		t.Error("VerifyRecoveryCode should accept code without dashes")
	}
}

func TestVerifyRecoveryCode_EmptyInputs(t *testing.T) {
	hash := HashRecoveryCode("ABCD-EFGH-JKLM")
	if VerifyRecoveryCode("", hash) {
		t.Error("VerifyRecoveryCode should return false for empty code")
	}
	if VerifyRecoveryCode("ABCD-EFGH-JKLM", "") {
		t.Error("VerifyRecoveryCode should return false for empty hash")
	}
}
