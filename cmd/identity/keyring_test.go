package main

// Tests for parseKeyRingFromEnv. Generates RSA keys at runtime; never embeds
// real keys. Covers each error branch and the happy paths (PKCS1, PKCS8,
// multi-key with explicit active, multi-key defaulting to last).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genRSAKey generates a fresh 2048-bit RSA key for tests.
func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func pemEncodePKCS1(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func pemEncodePKCS8(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// pemEncodePublic encodes a public key in PEM (used to build a non-private PEM
// block, which should fail to parse as a private key).
func pemEncodePublic(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func TestParseKeyRingFromEnv_MalformedJSON(t *testing.T) {
	t.Parallel()
	_, err := parseKeyRingFromEnv("not-json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing JWT keys JSON")
}

func TestParseKeyRingFromEnv_EmptyArray(t *testing.T) {
	t.Parallel()
	_, err := parseKeyRingFromEnv("[]")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParseKeyRingFromEnv_MissingKID(t *testing.T) {
	t.Parallel()
	key := genRSAKey(t)
	payload := []jwtKeyJSON{{
		KID:           "",
		PrivateKeyPEM: pemEncodePKCS1(t, key),
		Active:        true,
	}}
	_, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing kid")
}

func TestParseKeyRingFromEnv_InvalidPEM(t *testing.T) {
	t.Parallel()
	payload := []jwtKeyJSON{{
		KID:           "k1",
		PrivateKeyPEM: "not-a-pem-block",
		Active:        true,
	}}
	_, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key PEM")
}

func TestParseKeyRingFromEnv_PEMNotPrivateKey(t *testing.T) {
	t.Parallel()
	// A valid PEM block, but not a parseable private key (it's a public key).
	key := genRSAKey(t)
	payload := []jwtKeyJSON{{
		KID:           "k1",
		PrivateKeyPEM: pemEncodePublic(t, key),
		Active:        true,
	}}
	_, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid=k1")
}

func TestParseKeyRingFromEnv_NonRSAPKCS8(t *testing.T) {
	t.Parallel()
	// Non-RSA key in PKCS8 (ECDSA) — the PKCS1 parse fails and the PKCS8
	// fallback succeeds but yields a non-RSA type, which must error.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	payload := []jwtKeyJSON{{
		KID:           "ecdsa-1",
		PrivateKeyPEM: pemEncodePKCS8(t, ec),
		Active:        true,
	}}
	_, err = parseKeyRingFromEnv(mustJSON(t, payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not RSA")
}

func TestParseKeyRingFromEnv_PKCS1Happy(t *testing.T) {
	t.Parallel()
	key := genRSAKey(t)
	payload := []jwtKeyJSON{{
		KID:           "k1",
		PrivateKeyPEM: pemEncodePKCS1(t, key),
		Active:        true,
	}}
	kr, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.NoError(t, err)
	require.NotNil(t, kr)
	assert.Equal(t, "k1", kr.Active().KID)
	assert.Equal(t, []string{"k1"}, kr.AllKIDs())
}

func TestParseKeyRingFromEnv_PKCS8Happy(t *testing.T) {
	t.Parallel()
	key := genRSAKey(t)
	payload := []jwtKeyJSON{{
		KID:           "k1",
		PrivateKeyPEM: pemEncodePKCS8(t, key),
		Active:        true,
	}}
	kr, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.NoError(t, err)
	require.NotNil(t, kr)
	assert.Equal(t, "k1", kr.Active().KID)
}

func TestParseKeyRingFromEnv_MultipleKeysExplicitActive(t *testing.T) {
	t.Parallel()
	a, b := genRSAKey(t), genRSAKey(t)
	payload := []jwtKeyJSON{
		{KID: "old", PrivateKeyPEM: pemEncodePKCS1(t, a), Active: false},
		{KID: "new", PrivateKeyPEM: pemEncodePKCS1(t, b), Active: true},
	}
	kr, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.NoError(t, err)
	assert.Equal(t, "new", kr.Active().KID)
	assert.ElementsMatch(t, []string{"old", "new"}, kr.AllKIDs())
}

func TestParseKeyRingFromEnv_MultipleKeysNoActiveDefaultsToLast(t *testing.T) {
	t.Parallel()
	// NewKeyRing defaults to the last key if no Active is set.
	a, b := genRSAKey(t), genRSAKey(t)
	payload := []jwtKeyJSON{
		{KID: "first", PrivateKeyPEM: pemEncodePKCS1(t, a), Active: false},
		{KID: "last", PrivateKeyPEM: pemEncodePKCS1(t, b), Active: false},
	}
	kr, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.NoError(t, err)
	assert.Equal(t, "last", kr.Active().KID)
}

func TestParseKeyRingFromEnv_MultipleActiveErrors(t *testing.T) {
	t.Parallel()
	// Two keys with Active=true is rejected by jwt.NewKeyRing.
	a, b := genRSAKey(t), genRSAKey(t)
	payload := []jwtKeyJSON{
		{KID: "k1", PrivateKeyPEM: pemEncodePKCS1(t, a), Active: true},
		{KID: "k2", PrivateKeyPEM: pemEncodePKCS1(t, b), Active: true},
	}
	_, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "multiple active") ||
		strings.Contains(err.Error(), "active"))
}

func TestParseKeyRingFromEnv_DuplicateKIDsError(t *testing.T) {
	t.Parallel()
	a, b := genRSAKey(t), genRSAKey(t)
	payload := []jwtKeyJSON{
		{KID: "same", PrivateKeyPEM: pemEncodePKCS1(t, a), Active: true},
		{KID: "same", PrivateKeyPEM: pemEncodePKCS1(t, b), Active: false},
	}
	_, err := parseKeyRingFromEnv(mustJSON(t, payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}
