package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractKID_MalformedToken exercises the jws.Parse error path inside
// extractKID, which is hit before the kid lookup in VerifyAccessToken.
func TestExtractKID_MalformedToken(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"single segment", "abc"},
		{"two segments", "abc.def"},
		{"non-base64 segments", "!!!.???.***"},
		{"truncated", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0"},
		{"garbage", "this is not a token at all"},
		{"only dots", "...."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := VerifyAccessToken(tc.token, kr, "", "", false)
			require.Error(t, err)
			// Either parse error or missing kid. Both are surfaced via the
			// "parsing token headers" wrapper or the "missing kid" branch.
			ok := strings.Contains(err.Error(), "parsing token headers") ||
				strings.Contains(err.Error(), "missing kid")
			assert.True(t, ok, "unexpected error: %v", err)
		})
	}
}

// TestExtractKID_NoSignatures crafts a JWS-shaped string whose parsed form
// produces zero signatures, hitting the "no signatures in token" branch.
func TestExtractKID_NoSignatures(t *testing.T) {
	t.Parallel()
	// JSON-serialized JWS with empty signatures array.
	bogus := `{"payload":"eyJzdWIiOiJ4In0","signatures":[]}`
	_, err := extractKID([]byte(bogus))
	require.Error(t, err)
}

// TestVerify_OversizedToken ensures gigantic inputs don't panic and return
// an error cleanly.
func TestVerify_OversizedToken(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	huge := strings.Repeat("A", 1<<16) + "." + strings.Repeat("B", 1<<16) + "." + strings.Repeat("C", 1<<16)
	_, err := VerifyAccessToken(huge, kr, "", "", false)
	require.Error(t, err)
}

// TestVerify_AlgNoneRejected ensures tokens signed with alg=none cannot be
// verified against the keyring.
func TestVerify_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)

	// Build an unsecured (alg=none) token by hand.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"test-kid","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","exp":9999999999}`))
	tokenStr := header + "." + payload + "."

	_, err := VerifyAccessToken(tokenStr, kr, "", "", false)
	require.Error(t, err)
}

// TestVerify_HS256Rejected ensures a token signed with HS256 (symmetric) is
// rejected when the verifier expects RS256.
func TestVerify_HS256Rejected(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "x").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(15 * time.Minute)).
		Build()
	require.NoError(t, err)

	hs, err := jwk.FromRaw([]byte("supersecretsymmetrickey-32-bytes"))
	require.NoError(t, err)
	require.NoError(t, hs.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, hs.Set(jwk.AlgorithmKey, jwa.HS256))

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.HS256, hs))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "", "", false)
	require.Error(t, err)
}

// TestVerify_FutureIssued: tokens with iat far in the future are rejected by
// the underlying validator (iat must be in the past).
func TestVerify_FutureIssued(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	active := kr.Active()

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "x").
		Claim("email", "a@b.com").
		IssuedAt(time.Now().Add(48 * time.Hour)).
		Expiration(time.Now().Add(72 * time.Hour)).
		Build()
	require.NoError(t, err)

	key, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, active.KID))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat")
}

// TestNewKeyRing_EmptyKID exercises the "all keys must have a non-empty KID"
// branch by constructing a SigningKey directly without the GenerateKey helper.
func TestNewKeyRing_EmptyKIDInSlice(t *testing.T) {
	t.Parallel()
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	bad := SigningKey{
		KID:        "",
		PrivateKey: k1.PrivateKey,
		PublicKey:  k1.PublicKey,
		Active:     false,
	}

	_, err = NewKeyRing([]SigningKey{k1, bad})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty KID")
}

// TestKeyRing_SingleActiveAfterRotation: simulates a 3-step rotation and
// confirms tokens signed with the previous active key still verify.
func TestKeyRing_RotationChain(t *testing.T) {
	t.Parallel()
	k1, _ := GenerateKey("k1")
	k1.Active = true
	k2, _ := GenerateKey("k2")
	k2.Active = false

	kr1, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)

	claims := Claims{Sub: "u1", Email: "u@x", Name: "U", Role: "member", Tenant: "t1"}
	t1, err := CreateAccessToken(claims, kr1, 15*time.Minute)
	require.NoError(t, err)

	// Promote k2 to active.
	k1.Active = false
	k2.Active = true
	kr2, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)
	require.Equal(t, "k2", kr2.Active().KID)

	// Old token still verifies.
	_, err = VerifyAccessToken(t1, kr2, "", "", false)
	require.NoError(t, err)

	// New token signed with k2 verifies.
	t2, err := CreateAccessToken(claims, kr2, 15*time.Minute)
	require.NoError(t, err)
	_, err = VerifyAccessToken(t2, kr2, "", "", false)
	require.NoError(t, err)

	// Drop k1 from the ring; t1 must no longer verify.
	kr3, err := NewKeyRing([]SigningKey{k2})
	require.NoError(t, err)
	_, err = VerifyAccessToken(t1, kr3, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing key")
}
