package jwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	sk, err := GenerateKey("test-key-1")
	require.NoError(t, err)
	assert.Equal(t, "test-key-1", sk.KID)
	assert.NotNil(t, sk.PrivateKey)
	assert.NotNil(t, sk.PublicKey)
	assert.True(t, sk.Active)
	// RSA 2048 bit key should have a modulus of 256 bytes.
	assert.Equal(t, 256, sk.PrivateKey.Size())
}

func TestGenerateKey_EmptyKID(t *testing.T) {
	_, err := GenerateKey("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid is required")
}

func TestNewKeyRing_Empty(t *testing.T) {
	_, err := NewKeyRing(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one key")

	_, err = NewKeyRing([]SigningKey{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one key")
}

func TestNewKeyRing_MultipleActive(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = true

	_, err = NewKeyRing([]SigningKey{k1, k2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple active")
}

func TestNewKeyRing_NoActive(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = false

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = false

	kr, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)
	// Should default to the last key.
	assert.Equal(t, "k2", kr.Active().KID)
}

func TestActive(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = false

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = true

	kr, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)
	assert.Equal(t, "k2", kr.Active().KID)
	assert.True(t, kr.Active().Active)
}

func TestGet(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = false

	kr, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)

	got, ok := kr.Get("k1")
	assert.True(t, ok)
	assert.Equal(t, "k1", got.KID)

	got, ok = kr.Get("k2")
	assert.True(t, ok)
	assert.Equal(t, "k2", got.KID)
}

func TestGet_Unknown(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	kr, err := NewKeyRing([]SigningKey{k1})
	require.NoError(t, err)

	_, ok := kr.Get("nonexistent")
	assert.False(t, ok)
}

func TestAllKIDs(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = false

	kr, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)
	assert.Equal(t, []string{"k1", "k2"}, kr.AllKIDs())
}

func TestJWKS(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	kr, err := NewKeyRing([]SigningKey{k1})
	require.NoError(t, err)

	jwksBytes, err := kr.JWKS()
	require.NoError(t, err)

	// Parse and validate the JWKS structure.
	var jwks map[string]interface{}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	keysArr, ok := jwks["keys"].([]interface{})
	require.True(t, ok, "JWKS must have a 'keys' array")
	require.Len(t, keysArr, 1)

	key := keysArr[0].(map[string]interface{})
	assert.Equal(t, "k1", key["kid"])
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "RS256", key["alg"])
	assert.Equal(t, "sig", key["use"])
	assert.NotEmpty(t, key["n"], "modulus 'n' must be present")
	assert.NotEmpty(t, key["e"], "exponent 'e' must be present")
}

func TestJWKS_MultipleKeys(t *testing.T) {
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = false

	k3, err := GenerateKey("k3")
	require.NoError(t, err)
	k3.Active = false

	kr, err := NewKeyRing([]SigningKey{k1, k2, k3})
	require.NoError(t, err)

	jwksBytes, err := kr.JWKS()
	require.NoError(t, err)

	var jwks map[string]interface{}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	keysArr, ok := jwks["keys"].([]interface{})
	require.True(t, ok)
	assert.Len(t, keysArr, 3)

	kids := make(map[string]bool)
	for _, k := range keysArr {
		km := k.(map[string]interface{})
		kids[km["kid"].(string)] = true
	}
	assert.True(t, kids["k1"])
	assert.True(t, kids["k2"])
	assert.True(t, kids["k3"])
}

func TestNewKeyRing_DuplicateKIDs(t *testing.T) {
	k1, err := GenerateKey("same")
	require.NoError(t, err)
	k1.Active = true

	k2, err := GenerateKey("same")
	require.NoError(t, err)
	k2.Active = false
	k2.KID = "same"

	_, err = NewKeyRing([]SigningKey{k1, k2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate kid")
}

func TestRotation(t *testing.T) {
	// Sign a token with k1, then rotate to k2, and verify the old token
	// still works because k1 is still in the ring.
	k1, err := GenerateKey("k1")
	require.NoError(t, err)
	k1.Active = true

	k2, err := GenerateKey("k2")
	require.NoError(t, err)
	k2.Active = false

	kr, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)

	claims := Claims{
		Sub:    "user-1",
		Email:  "user@example.com",
		Name:   "Test User",
		Role:   "admin",
		Tenant: "tenant-1",
	}

	// Sign with k1 (the active key).
	tokenStr, err := CreateAccessToken(claims, kr, 15*60*1000000000) // 15 min
	require.NoError(t, err)

	// Now create a new ring where k2 is active (simulating rotation).
	k1.Active = false
	k2.Active = true
	kr2, err := NewKeyRing([]SigningKey{k1, k2})
	require.NoError(t, err)
	assert.Equal(t, "k2", kr2.Active().KID)

	// The token signed with k1 should still verify because k1 is in kr2.
	got, err := VerifyAccessToken(tokenStr, kr2, "")
	require.NoError(t, err)
	assert.Equal(t, "user-1", got.Sub)
	assert.Equal(t, "user@example.com", got.Email)
}
