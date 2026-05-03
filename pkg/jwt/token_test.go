package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKeyRing(t *testing.T) *KeyRing {
	t.Helper()
	k, err := GenerateKey("test-kid")
	require.NoError(t, err)
	k.Active = true
	kr, err := NewKeyRing([]SigningKey{k})
	require.NoError(t, err)
	return kr
}

func TestCreateAndVerify(t *testing.T) {
	kr := newTestKeyRing(t)

	claims := Claims{
		Sub:       "user-123",
		Email:     "alice@example.com",
		Name:      "Alice Smith",
		Role:      "admin",
		Tenant:    "tenant-abc",
		AvatarURL: "https://example.com/avatar.png",
	}

	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	got, err := VerifyAccessToken(tokenStr, kr, "")
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.Sub)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, "Alice Smith", got.Name)
	assert.Equal(t, "admin", got.Role)
	assert.Equal(t, "tenant-abc", got.Tenant)
	assert.Equal(t, "https://example.com/avatar.png", got.AvatarURL)
	assert.True(t, got.IssuedAt > 0)
	assert.True(t, got.ExpiresAt > got.IssuedAt)
}

func TestVerify_ExpiredToken(t *testing.T) {
	kr := newTestKeyRing(t)

	claims := Claims{
		Sub:    "user-123",
		Email:  "alice@example.com",
		Name:   "Alice",
		Role:   "member",
		Tenant: "t1",
	}

	// Create a token that expired 1 second ago.
	tokenStr, err := CreateAccessToken(claims, kr, -1*time.Second)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tokenStr, kr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifying token")
}

func TestVerify_WrongKey(t *testing.T) {
	// Create token with one key ring.
	kr1 := newTestKeyRing(t)

	claims := Claims{
		Sub:    "user-123",
		Email:  "alice@example.com",
		Name:   "Alice",
		Role:   "member",
		Tenant: "t1",
	}
	tokenStr, err := CreateAccessToken(claims, kr1, 15*time.Minute)
	require.NoError(t, err)

	// Try to verify with a different key ring that has the same kid but different key.
	k2, err := GenerateKey("test-kid")
	require.NoError(t, err)
	k2.Active = true
	kr2, err := NewKeyRing([]SigningKey{k2})
	require.NoError(t, err)

	_, err = VerifyAccessToken(tokenStr, kr2, "")
	require.Error(t, err)
}

func TestVerify_MissingKID(t *testing.T) {
	kr := newTestKeyRing(t)
	active := kr.Active()

	// Manually build a token without a kid header.
	tok, err := jwtoken.NewBuilder().
		Claim("sub", "user-123").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(15 * time.Minute)).
		Build()
	require.NoError(t, err)

	// Sign with raw key (no kid set on key).
	key, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	// Deliberately do NOT set KeyIDKey.
	err = key.Set(jwk.AlgorithmKey, jwa.RS256)
	require.NoError(t, err)

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing kid")
}

func TestVerify_UnknownKID(t *testing.T) {
	kr := newTestKeyRing(t)

	// Generate a different key and sign a token with kid="unknown-kid".
	otherKey, err := GenerateKey("unknown-kid")
	require.NoError(t, err)

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "user-123").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(15 * time.Minute)).
		Build()
	require.NoError(t, err)

	key, err := jwk.FromRaw(otherKey.PrivateKey)
	require.NoError(t, err)
	err = key.Set(jwk.KeyIDKey, "unknown-kid")
	require.NoError(t, err)
	err = key.Set(jwk.AlgorithmKey, jwa.RS256)
	require.NoError(t, err)

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing key")
}

func TestCreateToken_HasKIDHeader(t *testing.T) {
	kr := newTestKeyRing(t)

	claims := Claims{
		Sub:    "user-123",
		Email:  "a@b.com",
		Name:   "A",
		Role:   "member",
		Tenant: "t1",
	}
	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	// Parse the raw JWS to inspect the protected header.
	kid, err := extractKID([]byte(tokenStr))
	require.NoError(t, err)
	assert.Equal(t, "test-kid", kid)
}

func TestClaims_AllFieldsPresent(t *testing.T) {
	kr := newTestKeyRing(t)

	claims := Claims{
		Sub:       "user-456",
		Email:     "bob@example.com",
		Name:      "Bob Jones",
		Role:      "owner",
		Tenant:    "tenant-xyz",
		AvatarURL: "https://cdn.example.com/bob.jpg",
	}

	tokenStr, err := CreateAccessToken(claims, kr, 15*time.Minute)
	require.NoError(t, err)

	// Parse without verification to inspect the raw payload.
	tok, err := jwtoken.Parse([]byte(tokenStr), jwtoken.WithVerify(false), jwtoken.WithValidate(false))
	require.NoError(t, err)

	// Serialize to JSON to check all fields are present.
	payload, err := json.Marshal(tok)
	require.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(payload, &m)
	require.NoError(t, err)

	assert.Equal(t, "user-456", m["sub"])
	assert.Equal(t, "bob@example.com", m["email"])
	assert.Equal(t, "Bob Jones", m["name"])
	assert.Equal(t, "owner", m["role"])
	assert.Equal(t, "tenant-xyz", m["tenant"])
	assert.Equal(t, "https://cdn.example.com/bob.jpg", m["avatar_url"])
	assert.NotNil(t, m["iat"])
	assert.NotNil(t, m["exp"])
}
