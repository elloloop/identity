package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

func p256PublicKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	require.NoError(t, err)
	return private, der
}

func TestValidTeammatePublicKeyAcceptsOnlyCanonicalP256Keys(t *testing.T) {
	_, p256 := p256PublicKey(t, elliptic.P256())
	_, p384 := p256PublicKey(t, elliptic.P384())
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed, err := x509.MarshalPKIXPublicKey(edPublic)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	require.True(t, validTeammatePublicKey(TeammateKeyECDSAP256, p256))
	for name, c := range map[string]struct {
		algorithm string
		der       []byte
	}{
		"ed25519 key":      {TeammateKeyECDSAP256, ed},
		"ed25519 label":    {"ed25519", ed},
		"p256 as ed25519":  {"ed25519", p256},
		"p384":             {TeammateKeyECDSAP256, p384},
		"rsa":              {TeammateKeyECDSAP256, rsaDER},
		"unknown":          {"", p256},
		"empty":            {TeammateKeyECDSAP256, nil},
		"trailing byte":    {TeammateKeyECDSAP256, append(append([]byte{}, p256...), 0)},
		"not der":          {TeammateKeyECDSAP256, []byte("not a key")},
		"oversized":        {TeammateKeyECDSAP256, make([]byte, maxTeammatePublicKeyBytes+1)},
		"raw ed25519 key":  {TeammateKeyECDSAP256, edPublic},
		"p256 wrong label": {"ECDSA_P256", p256},
	} {
		require.False(t, validTeammatePublicKey(c.algorithm, c.der), name)
	}
}

func TestVerifyTeammateSignatureAcceptsOnlyDERECDSAOverSHA256(t *testing.T) {
	message := []byte(`{"nonce":"n"}`)
	private, p256 := p256PublicKey(t, elliptic.P256())
	digest := sha256.Sum256(message)
	r, sv, err := ecdsa.Sign(rand.Reader, private, digest[:])
	require.NoError(t, err)
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, sv})
	require.NoError(t, err)
	key := &TeammateKey{PublicKey: p256, Algorithm: TeammateKeyECDSAP256}
	require.True(t, verifyTeammateSignature(key, message, signature))
	require.False(t, verifyTeammateSignature(key, []byte("other"), signature))
	require.False(t, verifyTeammateSignature(&TeammateKey{PublicKey: p256, Algorithm: "ed25519"}, message, signature))
	raw := append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...)
	require.False(t, verifyTeammateSignature(key, message, raw), "a raw r and s signature")
	unhashed, err := ecdsa.SignASN1(rand.Reader, private, message)
	require.NoError(t, err)
	require.False(t, verifyTeammateSignature(key, message, unhashed), "a signature over the message, not its digest")

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed, err := x509.MarshalPKIXPublicKey(edPublic)
	require.NoError(t, err)
	edSignature := ed25519.Sign(edPrivate, message)
	require.False(t, verifyTeammateSignature(&TeammateKey{PublicKey: ed, Algorithm: "ed25519"}, message, edSignature), "an Ed25519 key")
	require.False(t, verifyTeammateSignature(&TeammateKey{PublicKey: ed, Algorithm: TeammateKeyECDSAP256}, message, edSignature))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	require.False(t, verifyTeammateSignature(&TeammateKey{PublicKey: rsaDER, Algorithm: TeammateKeyECDSAP256}, message, signature))
	require.False(t, verifyTeammateSignature(&TeammateKey{PublicKey: []byte("garbage"), Algorithm: TeammateKeyECDSAP256}, message, signature))
}

func TestTeammateKeyStopsWorkingAtItsRevocationTime(t *testing.T) {
	require.False(t, (&TeammateKey{}).revokedBy(5000))
	require.False(t, (&TeammateKey{RevokedAtMs: 5001}).revokedBy(5000))
	require.True(t, (&TeammateKey{RevokedAtMs: 5000}).revokedBy(5000))
	require.True(t, (&TeammateKey{RevokedAtMs: 4999}).revokedBy(5000))
}

func TestTeammateKeyRevocationReasonsAndResults(t *testing.T) {
	for _, reason := range []string{TeammateKeyReleased, TeammateKeyReclaimed, TeammateKeyRemoved, TeammateKeyDrifted} {
		require.True(t, validTeammateKeyRevocationReason(reason))
	}
	require.False(t, validTeammateKeyRevocationReason(""))
	require.False(t, validTeammateKeyRevocationReason("RELEASED"))
	require.Equal(t, "denied", registrationResult(errTeammateKeyManager))
	require.Equal(t, "invalid", registrationResult(ErrInvalidArgument))
	require.Equal(t, "error", registrationResult(ErrUnavailable))
}

func TestNewTeammateKeyServiceRefusesWhatCannotServeIt(t *testing.T) {
	enabled := func() *config.Config {
		return &config.Config{TeammateKeysEnabled: true, JWTIssuer: "https://auth.example.test", JWTAudience: "https://api.example.test", DefaultProjectID: "project"}
	}
	signer := testKeyRing(t)
	_, err := NewTeammateKeyService(&config.Config{TeammateKeysEnabled: true}, newFakeControlPlaneStore(), newFakeRepo(), signer, nil, nil)
	require.ErrorContains(t, err, "GATEWAY_JWT_AUDIENCE")
	_, err = NewTeammateKeyService(enabled(), nil, newFakeRepo(), signer, nil, nil)
	require.ErrorContains(t, err, "control plane")
	_, err = NewTeammateKeyService(enabled(), newFakeControlPlaneStore(), newFakeRepo(), signer, nil, nil)
	require.ErrorContains(t, err, "postgres repository")
}

func TestTeammateKeyMetricsRegisterOnce(t *testing.T) {
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(prometheus.NewCounterVec(prometheus.CounterOpts{Name: "identity_teammate_keys_revoked_total", Help: "taken"}, []string{"schedule"})))
	_, err := newTeammateKeyMetrics(reg)
	require.Error(t, err)
	_, err = newTeammateKeyMetrics(nil)
	require.NoError(t, err)
}
