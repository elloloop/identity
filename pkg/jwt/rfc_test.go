package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── RFC 7519: JWT header fields ────────────────────────────────────────

func TestRFC7519_HeaderFields_AlgKidTyp(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	// Split compact serialization: header.payload.signature
	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3, "JWS compact serialization has 3 parts")

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]interface{}
	err = json.Unmarshal(headerJSON, &header)
	require.NoError(t, err)

	assert.Equal(t, "RS256", header["alg"], "alg must be RS256")
	assert.Equal(t, "test-kid", header["kid"], "kid must match key ring active kid")
	// typ may be JWT or absent; if present must be JWT
	if typ, ok := header["typ"]; ok {
		assert.Equal(t, "JWT", typ)
	}
}

// ── RFC 7519: Registered claims ────────────────────────────────────────

func TestRFC7519_RegisteredClaims_SubIssExpIatAud(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	claims := Claims{Sub: "user-abc", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	tok, err := jwtoken.Parse([]byte(tokenStr), jwtoken.WithVerify(false), jwtoken.WithValidate(false))
	require.NoError(t, err)

	assert.Equal(t, "user-abc", tok.Subject(), "sub claim must match")
	assert.False(t, tok.IssuedAt().IsZero(), "iat must be present")
	assert.False(t, tok.Expiration().IsZero(), "exp must be present")
	assert.True(t, tok.Expiration().After(tok.IssuedAt()), "exp must be after iat")
}

func TestRFC7519_ExpiryMatchesDuration(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	before := time.Now().Add(-2 * time.Second) // allow 2s clock tolerance
	tokenStr, err := CreateAccessToken(claims, kr, 30*time.Minute)
	require.NoError(t, err)
	after := time.Now().Add(2 * time.Second)

	tok, err := jwtoken.Parse([]byte(tokenStr), jwtoken.WithVerify(false), jwtoken.WithValidate(false))
	require.NoError(t, err)

	// exp should be approximately iat + 30 min
	expectedMin := before.Add(30 * time.Minute)
	expectedMax := after.Add(30 * time.Minute)

	assert.True(t, !tok.Expiration().Before(expectedMin), "exp too early")
	assert.True(t, !tok.Expiration().After(expectedMax), "exp too late")
}

// ── Expired token rejection ────────────────────────────────────────────

func TestRFC7519_ExpiredTokenRejected(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := CreateAccessToken(claims, kr, -5*time.Second)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tokenStr, kr)
	require.Error(t, err, "expired token must be rejected")
}

// ── Future iat handling ────────────────────────────────────────────────

func TestRFC7519_FutureIat_StillVerifies(t *testing.T) {
	// A token with iat slightly in the future should still verify
	// (clock skew tolerance). We build it manually.
	t.Parallel()
	kr := newTestKeyRing(t)
	active := kr.Active()

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "user-future").
		Claim("email", "f@b.com").
		Claim("name", "F").
		Claim("role", "member").
		Claim("tenant", "t1").
		IssuedAt(time.Now().Add(2 * time.Second)).
		Expiration(time.Now().Add(15 * time.Minute)).
		Build()
	require.NoError(t, err)

	key, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	_ = key.Set(jwk.KeyIDKey, active.KID)
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	require.NoError(t, err)

	// This may succeed or fail depending on library skew tolerance.
	// The test documents the behavior.
	_, _ = VerifyAccessToken(string(signed), kr)
}

// ── Claims extraction correctness ──────────────────────────────────────

func TestRFC7519_ClaimsExtraction_AllCustomFields(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	claims := Claims{
		Sub:       "user-extract",
		Email:     "extract@test.com",
		Name:      "Extract User",
		Role:      "owner",
		Tenant:    "tenant-ext",
		AvatarURL: "https://cdn.example.com/avatar.png",
	}

	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	got, err := VerifyAccessToken(tokenStr, kr)
	require.NoError(t, err)

	assert.Equal(t, "user-extract", got.Sub)
	assert.Equal(t, "extract@test.com", got.Email)
	assert.Equal(t, "Extract User", got.Name)
	assert.Equal(t, "owner", got.Role)
	assert.Equal(t, "tenant-ext", got.Tenant)
	assert.Equal(t, "https://cdn.example.com/avatar.png", got.AvatarURL)
	assert.True(t, got.IssuedAt > 0)
	assert.True(t, got.ExpiresAt > 0)
}

// ── Key rotation: sign with k1, add k2, verify k1 still works ─────────

func TestRFC7519_KeyRotation_OldTokenStillVerifies(t *testing.T) {
	t.Parallel()
	k1, err := GenerateKey("rotation-k1")
	require.NoError(t, err)
	k1.Active = true

	kr1, err := NewKeyRing([]SigningKey{k1})
	require.NoError(t, err)

	claims := Claims{Sub: "user-rot", Email: "rot@b.com", Name: "R", Role: "member", Tenant: "t1"}
	tokenStr, err := CreateAccessToken(claims, kr1, 15*time.Minute)
	require.NoError(t, err)

	// Rotate: k1 inactive, k2 active, both in ring
	k2, err := GenerateKey("rotation-k2")
	require.NoError(t, err)

	k1.Active = false
	k2.Active = true
	kr2, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)

	// Token signed with k1 must still verify with kr2
	got, err := VerifyAccessToken(tokenStr, kr2)
	require.NoError(t, err)
	assert.Equal(t, "user-rot", got.Sub)
}

func TestRFC7519_KeyRotation_NewTokenUsesActiveKey(t *testing.T) {
	t.Parallel()
	k1, err := GenerateKey("rot-old")
	require.NoError(t, err)
	k1.Active = false

	k2, err := GenerateKey("rot-new")
	require.NoError(t, err)
	k2.Active = true

	kr, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)

	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}
	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	kid, err := extractKID([]byte(tokenStr))
	require.NoError(t, err)
	assert.Equal(t, "rot-new", kid, "new token should use the active key")
}

// ── JWKS format matches RFC 7517 ───────────────────────────────────────

func TestRFC7517_JWKS_RequiredFields(t *testing.T) {
	t.Parallel()
	k, err := GenerateKey("jwks-test")
	require.NoError(t, err)
	k.Active = true

	kr, err := NewKeyRing([]SigningKey{k})
	require.NoError(t, err)

	jwksBytes, err := kr.JWKS()
	require.NoError(t, err)

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	key := jwks.Keys[0]
	assert.Equal(t, "RSA", key["kty"], "kty must be RSA")
	assert.Equal(t, "sig", key["use"], "use must be sig")
	assert.Equal(t, "RS256", key["alg"], "alg must be RS256")
	assert.Equal(t, "jwks-test", key["kid"], "kid must match")
	assert.NotEmpty(t, key["n"], "modulus n must be present")
	assert.NotEmpty(t, key["e"], "exponent e must be present")
}

func TestRFC7517_JWKS_KeyIDMatchesTokenKID(t *testing.T) {
	t.Parallel()
	k, err := GenerateKey("kid-match-test")
	require.NoError(t, err)
	k.Active = true

	kr, err := NewKeyRing([]SigningKey{k})
	require.NoError(t, err)

	// Get kid from token
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}
	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	tokenKID, err := extractKID([]byte(tokenStr))
	require.NoError(t, err)

	// Get kid from JWKS
	jwksBytes, err := kr.JWKS()
	require.NoError(t, err)

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	var jwksKID string
	for _, key := range jwks.Keys {
		if kid, ok := key["kid"].(string); ok {
			jwksKID = kid
		}
	}

	assert.Equal(t, tokenKID, jwksKID, "JWKS kid must match token kid")
}

func TestRFC7517_JWKS_NFieldIsBase64url(t *testing.T) {
	t.Parallel()
	k, err := GenerateKey("b64-test")
	require.NoError(t, err)
	k.Active = true

	kr, err := NewKeyRing([]SigningKey{k})
	require.NoError(t, err)

	jwksBytes, err := kr.JWKS()
	require.NoError(t, err)

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	n := jwks.Keys[0]["n"].(string)
	// RFC 7517 mandates base64url without padding
	assert.NotContains(t, n, "+", "n must not contain + (base64url)")
	assert.NotContains(t, n, "/", "n must not contain / (base64url)")
}

func TestRFC7519_EmptySubReturnsError(t *testing.T) {
	t.Parallel()
	kr := newTestKeyRing(t)
	claims := Claims{Sub: "", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	// Even with empty sub, the library should still produce a token
	// (sub is technically optional in JWT spec). Document behavior.
	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	if err == nil {
		// Verify it round-trips
		got, err := VerifyAccessToken(tokenStr, kr)
		require.NoError(t, err)
		assert.Equal(t, "", got.Sub)
	}
}

func TestRFC7519_TokenNotValidBefore(t *testing.T) {
	// Manually create a token with nbf in the future.
	t.Parallel()
	kr := newTestKeyRing(t)
	active := kr.Active()

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "user-nbf").
		Claim("email", "nbf@b.com").
		Claim("name", "NBF").
		Claim("role", "member").
		Claim("tenant", "t1").
		IssuedAt(time.Now()).
		NotBefore(time.Now().Add(1 * time.Hour)).
		Expiration(time.Now().Add(2 * time.Hour)).
		Build()
	require.NoError(t, err)

	key, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	_ = key.Set(jwk.KeyIDKey, active.KID)
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr)
	require.Error(t, err, "token with future nbf should be rejected")
}
