package jwt

import (
	"testing"
	"time"
)

// newFuzzKeyRing builds a key ring suitable for verifying fuzzed token bytes.
// A single key with a known kid is sufficient — the goal is to exercise the
// parser and verifier paths with arbitrary input, not to test rotation.
func newFuzzKeyRing(tb testing.TB) *KeyRing {
	tb.Helper()
	sk, err := GenerateKey("fuzz-key")
	if err != nil {
		tb.Fatalf("generating key: %v", err)
	}
	kr, err := NewKeyRing([]SigningKey{sk})
	if err != nil {
		tb.Fatalf("building key ring: %v", err)
	}
	return kr
}

// FuzzVerifyAccessToken passes arbitrary byte sequences (interpreted as a
// token string) through VerifyAccessToken. The contract is:
//   - never panic;
//   - return (nil, error) for any input that is not a valid token signed
//     by the active key in the supplied ring.
func FuzzVerifyAccessToken(f *testing.F) {
	kr := newFuzzKeyRing(f)

	// Seed corpus.
	//
	// A valid token signed by the test ring (covers the success path).
	validToken, err := CreateAccessToken(Claims{
		Sub:   "user-123",
		Email: "user@example.com",
		Role:  "admin",
	}, kr, 5*time.Minute)
	if err != nil {
		f.Fatalf("creating seed token: %v", err)
	}
	f.Add(validToken)

	// Representative malformed inputs.
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("aaa.bbb.ccc")
	f.Add("eyJhbGciOiJIUzI1NiJ9.e30.xxx") // valid JWS shape, wrong kid/alg
	f.Add(string([]byte{0x00, 0x01, 0x02, 0xff}))

	f.Fuzz(func(t *testing.T, tokenStr string) {
		claims, err := VerifyAccessToken(tokenStr, kr, "")
		if err != nil {
			// Error path: claims must be nil to honour the (nil, error) contract.
			if claims != nil {
				t.Fatalf("VerifyAccessToken returned non-nil claims with error: claims=%+v err=%v", claims, err)
			}
			return
		}
		// Success path: claims must be non-nil. Only the seed corpus should
		// reach here in practice — the fuzz engine has no way to forge a
		// signature against a freshly-generated 2048-bit RSA key.
		if claims == nil {
			t.Fatalf("VerifyAccessToken returned nil claims with nil error for input %q", tokenStr)
		}
	})
}

// FuzzParseKeyRingFromEnv is intentionally omitted: the JSON parser
// (parseKeyRingFromEnv) lives in cmd/identity/main.go and is unexported,
// so it cannot be reached from this package. See task spec.
