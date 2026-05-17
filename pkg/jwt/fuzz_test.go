package jwt

import (
	"context"
	"testing"
	"time"
)

// FuzzVerifyAccessToken passes arbitrary byte sequences (interpreted as
// a token string) through VerifyAccessToken. The contract is:
//   - never panic;
//   - return (nil, error) for any input that is not a valid token
//     signed by the active key in the supplied signer.
func FuzzVerifyAccessToken(f *testing.F) {
	s := newMemSigner(f, "fuzz-key")

	validToken, err := s.SignAccessToken(context.Background(), Claims{
		Sub:   "user-123",
		Email: "user@example.com",
		Role:  "admin",
	}, 5*time.Minute)
	if err != nil {
		f.Fatalf("creating seed token: %v", err)
	}
	f.Add(validToken)

	f.Add("")
	f.Add("not-a-jwt")
	f.Add("aaa.bbb.ccc")
	f.Add("eyJhbGciOiJIUzI1NiJ9.e30.xxx")
	f.Add(string([]byte{0x00, 0x01, 0x02, 0xff}))

	f.Fuzz(func(t *testing.T, tokenStr string) {
		claims, err := VerifyAccessToken(tokenStr, s, "", "", false)
		if err != nil {
			if claims != nil {
				t.Fatalf("VerifyAccessToken returned non-nil claims with error: claims=%+v err=%v", claims, err)
			}
			return
		}
		if claims == nil {
			t.Fatalf("VerifyAccessToken returned nil claims with nil error for input %q", tokenStr)
		}
	})
}
