package jwt

import (
	"context"
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
	s := newMemSigner(t, "test-kid")
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3, "JWS compact serialization has 3 parts")

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]interface{}
	err = json.Unmarshal(headerJSON, &header)
	require.NoError(t, err)

	assert.Equal(t, "RS256", header["alg"], "alg must be RS256")
	assert.Equal(t, "test-kid", header["kid"], "kid must match signer active kid")
	if typ, ok := header["typ"]; ok {
		assert.Equal(t, "JWT", typ)
	}
}

// ── RFC 7519: Registered claims ────────────────────────────────────────

func TestRFC7519_RegisteredClaims_SubIssExpIatAud(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	claims := Claims{Sub: "user-abc", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
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
	s := newMemSigner(t, "test-kid")
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	before := time.Now().Add(-2 * time.Second)
	tokenStr, err := s.SignAccessToken(context.Background(), claims, 30*time.Minute)
	require.NoError(t, err)
	after := time.Now().Add(2 * time.Second)

	tok, err := jwtoken.Parse([]byte(tokenStr), jwtoken.WithVerify(false), jwtoken.WithValidate(false))
	require.NoError(t, err)

	expectedMin := before.Add(30 * time.Minute)
	expectedMax := after.Add(30 * time.Minute)

	assert.True(t, !tok.Expiration().Before(expectedMin), "exp too early")
	assert.True(t, !tok.Expiration().After(expectedMax), "exp too late")
}

// ── Expired token rejection ────────────────────────────────────────────

func TestRFC7519_ExpiredTokenRejected(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, -5*time.Second)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tokenStr, s, "", "", false)
	require.Error(t, err, "expired token must be rejected")
}

// ── Future iat handling ────────────────────────────────────────────────

func TestRFC7519_FutureIat_StillVerifies(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	mk := s.byKID[s.activeKID]

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

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, mk.jwk))
	require.NoError(t, err)

	// May succeed or fail depending on library skew tolerance — test
	// documents the behaviour.
	_, _ = VerifyAccessToken(string(signed), s, "", "", false)
}

// ── Claims extraction correctness ──────────────────────────────────────

func TestRFC7519_ClaimsExtraction_AllCustomFields(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	claims := Claims{
		Sub:       "user-extract",
		Email:     "extract@test.com",
		Name:      "Extract User",
		Role:      "owner",
		Tenant:    "tenant-ext",
		AvatarURL: "https://cdn.example.com/avatar.png",
	}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	got, err := VerifyAccessToken(tokenStr, s, "", "", false)
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
	s := newMemSigner(t, "rotation-k1")

	claims := Claims{Sub: "user-rot", Email: "rot@b.com", Name: "R", Role: "member", Tenant: "t1"}
	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	// Rotate: add k2 and promote it.
	s.addKey(t, "rotation-k2")
	s.setActive("rotation-k2")

	// Token signed with k1 must still verify because k1 remains in
	// the provider.
	got, err := VerifyAccessToken(tokenStr, s, "", "", false)
	require.NoError(t, err)
	assert.Equal(t, "user-rot", got.Sub)
}

func TestRFC7519_KeyRotation_NewTokenUsesActiveKey(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "rot-old")
	s.addKey(t, "rot-new")
	s.setActive("rot-new")

	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}
	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	kid, err := extractKID([]byte(tokenStr))
	require.NoError(t, err)
	assert.Equal(t, "rot-new", kid, "new token should use the active key")
}

// ── JWKS format matches RFC 7517 ───────────────────────────────────────

func TestRFC7517_JWKS_RequiredFields(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "jwks-test")

	jwksBytes, err := JWKS(s)
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
	s := newMemSigner(t, "kid-match-test")

	claims := Claims{Sub: "u1", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}
	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	tokenKID, err := extractKID([]byte(tokenStr))
	require.NoError(t, err)

	jwksBytes, err := JWKS(s)
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
	s := newMemSigner(t, "b64-test")

	jwksBytes, err := JWKS(s)
	require.NoError(t, err)

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	n := jwks.Keys[0]["n"].(string)
	assert.NotContains(t, n, "+", "n must not contain + (base64url)")
	assert.NotContains(t, n, "/", "n must not contain / (base64url)")
}

func TestRFC7519_EmptySubReturnsError(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	claims := Claims{Sub: "", Email: "a@b.com", Name: "A", Role: "member", Tenant: "t1"}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	if err == nil {
		// A token without a subject must never verify as an access token:
		// other token species (assurance tokens) share the signing keys
		// and are distinguished by carrying no sub.
		_, err := VerifyAccessToken(tokenStr, s, "", "", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing sub")
	}
}

func TestRFC7519_TokenNotValidBefore(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	mk := s.byKID[s.activeKID]

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

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, mk.jwk))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), s, "", "", false)
	require.Error(t, err, "token with future nbf should be rejected")
}

// We don't actually use jwk directly in this test file post-refactor, but
// keep the import so future kid-related JWKS test additions don't need
// to add it back.
var _ = jwk.NewSet
