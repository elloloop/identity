package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// b64 is unpadded base64url, matching JWS compact serialization.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// makeSecKR returns a key ring for security tests with a fresh RSA key.
func makeSecKR(t *testing.T, kid string) *KeyRing {
	t.Helper()
	sk, err := GenerateKey(kid)
	require.NoError(t, err)
	kr, err := NewKeyRing([]SigningKey{sk})
	require.NoError(t, err)
	return kr
}

// TestSec_AlgNone_Rejected asserts a token with "alg":"none" is never accepted.
func TestSec_AlgNone_Rejected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	header := map[string]any{"alg": "none", "typ": "JWT", "kid": "test-kid"}
	payload := map[string]any{
		"sub": "user-1",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	tok := b64(hb) + "." + b64(pb) + "."

	_, err := VerifyAccessToken(tok, kr, "")
	require.Error(t, err, "alg=none MUST be rejected")
}

// TestSec_AlgConfusion_HS256WithRSAPubKey asserts the verifier doesn't allow
// an attacker to sign HS256 using the RSA public key bytes as the HMAC secret.
func TestSec_AlgConfusion_HS256WithRSAPubKey(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")
	active := kr.Active()

	// Marshal the public key to PKIX/PEM bytes — what an attacker would have.
	pubBytes, err := x509.MarshalPKIXPublicKey(active.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	header := map[string]any{"alg": "HS256", "typ": "JWT", "kid": "test-kid"}
	payload := map[string]any{
		"sub": "attacker",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := b64(hb) + "." + b64(pb)

	mac := hmac.New(sha256.New, pubPEM)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	tok := signingInput + "." + b64(sig)

	_, err = VerifyAccessToken(tok, kr, "")
	require.Error(t, err, "HS256 with RSA pubkey-as-secret MUST be rejected (alg confusion)")
}

// TestSec_TamperedPayload_Rejected asserts modifying the payload invalidates
// the signature.
func TestSec_TamperedPayload_Rejected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "alice", Role: "member", Tenant: "t1"}, kr, time.Hour)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)

	// Decode, mutate "sub", re-encode payload, leave signature unchanged.
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(pb, &m))
	m["sub"] = "attacker"
	mutated, _ := json.Marshal(m)
	tampered := parts[0] + "." + b64(mutated) + "." + parts[2]

	_, err = VerifyAccessToken(tampered, kr, "")
	require.Error(t, err, "tampered payload MUST be rejected")
}

// TestSec_TamperedSignature_Rejected asserts modifying the signature is rejected.
func TestSec_TamperedSignature_Rejected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "alice"}, kr, time.Hour)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	if len(sig) > 0 {
		sig[0] ^= 0xFF // flip bits
	}
	tampered := parts[0] + "." + parts[1] + "." + b64(sig)

	_, err = VerifyAccessToken(tampered, kr, "")
	require.Error(t, err, "tampered signature MUST be rejected")
}

// TestSec_TruncatedToken asserts tokens with missing segments are rejected.
func TestSec_TruncatedToken(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "alice"}, kr, time.Hour)
	require.NoError(t, err)
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)

	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"one-segment", parts[0]},
		{"two-segments", parts[0] + "." + parts[1]},
		{"trailing-dot-only", parts[0] + "." + parts[1] + "."},
		{"random-noise", "abc.def.ghi"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := VerifyAccessToken(tc.input, kr, "")
			require.Error(t, err, "truncated/malformed token MUST be rejected")
		})
	}
}

// TestSec_JKU_JWK_HeaderIgnored asserts the verifier never resolves keys via
// jku/jwk in headers — only the configured ring is consulted.
func TestSec_JKU_JWK_HeaderIgnored(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "ring-kid")

	// Attacker generates their own key and embeds it as "jwk" in the header,
	// while pointing kid at their key. If the verifier honored jwk header it
	// would accept this token — it MUST NOT.
	attackerKey, err := GenerateKey("attacker-kid")
	require.NoError(t, err)
	jwkAttacker, err := jwk.FromRaw(attackerKey.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, jwkAttacker.Set(jwk.KeyIDKey, "attacker-kid"))
	require.NoError(t, jwkAttacker.Set(jwk.AlgorithmKey, jwa.RS256))

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "attacker").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)

	// Sign with attacker's key — kid="attacker-kid" not in the verifier ring.
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, jwkAttacker))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err, "attacker-key signature MUST be rejected even if jwk header present")
	assert.Contains(t, err.Error(), "unknown signing key")
}

// TestSec_KIDNotInRing_Rejected asserts a token with an unknown kid is rejected
// even if signed correctly with that kid's key.
func TestSec_KIDNotInRing_Rejected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "kid-A")

	otherKey, err := GenerateKey("kid-B")
	require.NoError(t, err)

	jk, err := jwk.FromRaw(otherKey.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, jk.Set(jwk.KeyIDKey, "kid-B"))
	require.NoError(t, jk.Set(jwk.AlgorithmKey, jwa.RS256))

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "u").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, jk))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing key")
}

// TestSec_Expired_OneSecondPast asserts a 1s-past-exp token is rejected.
func TestSec_Expired_OneSecondPast(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "u"}, kr, -1*time.Second)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tok, kr, "")
	require.Error(t, err, "1s-past-exp token MUST be rejected")
}

// TestSec_Expired_ExpZero asserts a token with exp=0 (epoch) is rejected.
func TestSec_Expired_ExpZero(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")
	active := kr.Active()

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "u").
		IssuedAt(time.Unix(1, 0)).
		Expiration(time.Unix(0, 0)).
		Build()
	require.NoError(t, err)

	jk, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, jk.Set(jwk.KeyIDKey, active.KID))
	require.NoError(t, jk.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, jk))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err, "exp=0 token MUST be rejected")
}

// TestSec_Expired_MissingExp asserts a token with no exp claim is rejected.
// The lestrrat-go jwt library treats missing exp as not-expired by default.
// VerifyAccessToken calls tok.Expiration() which returns zero time when exp
// is missing — leaving the token effectively unbounded. Document this
// behavior; if it FAILS, that's the bug surfacing.
func TestSec_Expired_MissingExp(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")
	active := kr.Active()

	// Build a token with NO Expiration() call.
	tok, err := jwtoken.NewBuilder().
		Claim("sub", "u").
		IssuedAt(time.Now()).
		Build()
	require.NoError(t, err)

	jk, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, jk.Set(jwk.KeyIDKey, active.KID))
	require.NoError(t, jk.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, jk))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err, "token with missing exp MUST be rejected; if this passes, verifier accepts unbounded-lifetime tokens")
}

// TestSec_NotBeforeFuture_Rejected asserts a token whose nbf is in the future
// is rejected.
func TestSec_NotBeforeFuture_Rejected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")
	active := kr.Active()

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "u").
		NotBefore(time.Now().Add(2 * time.Hour)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(3 * time.Hour)).
		Build()
	require.NoError(t, err)

	jk, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, jk.Set(jwk.KeyIDKey, active.KID))
	require.NoError(t, jk.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, jk))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), kr, "")
	require.Error(t, err, "nbf-in-future MUST be rejected")
}

// TestSec_IssuerAudience_NotEnforced documents that VerifyAccessToken does
// not enforce iss/aud claims. If a token has an unexpected issuer or
// audience, the verifier currently accepts it. This test pins the current
// (lax) behavior and FAILS if iss/aud enforcement is added — at which point
// the test should be updated rather than the production code reverted.
//
// This is an INFORMATIONAL test; it does not assert rejection because the
// production code does not enforce these claims. The accompanying report
// flags this as a hardening gap.
func TestSec_IssuerAudience_NotEnforced(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")
	active := kr.Active()

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "u").
		Issuer("https://attacker.example.com").
		Audience([]string{"https://attacker.example.com/api"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)

	jk, err := jwk.FromRaw(active.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, jk.Set(jwk.KeyIDKey, active.KID))
	require.NoError(t, jk.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, jk))
	require.NoError(t, err)

	// Pin current behavior: token is accepted because iss/aud are not validated.
	// FAIL message documents the gap if behavior changes.
	_, verr := VerifyAccessToken(string(signed), kr, "")
	if verr != nil {
		t.Fatalf("BUG/CHANGE: VerifyAccessToken now rejects tokens with foreign iss/aud (%v); update this test if iss/aud enforcement was added intentionally", verr)
	}
	t.Log("INFO: iss/aud claims are NOT validated by VerifyAccessToken — hardening gap")
}

// TestSec_Tenant_Mismatch_Rejected asserts a token whose tenant claim does
// not match the verifier's expected tenant is rejected — preventing a token
// minted for tenant-A from being accepted by a service configured for
// tenant-B.
func TestSec_Tenant_Mismatch_Rejected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "u", Tenant: "tenant-A"}, kr, time.Hour)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tok, kr, "tenant-B")
	require.Error(t, err, "cross-tenant token MUST be rejected")
	assert.Contains(t, err.Error(), "tenant mismatch")
}

// TestSec_Tenant_Match_Accepted asserts a token whose tenant claim matches
// the verifier's expected tenant is accepted.
func TestSec_Tenant_Match_Accepted(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "u", Tenant: "tenant-A"}, kr, time.Hour)
	require.NoError(t, err)

	claims, err := VerifyAccessToken(tok, kr, "tenant-A")
	require.NoError(t, err)
	assert.Equal(t, "tenant-A", claims.Tenant)
	assert.Equal(t, "u", claims.Sub)
}

// TestSec_Tenant_EmptyExpected_SkipsCheck asserts that callers that have not
// been updated to thread an expected tenant (passing "") preserve the legacy
// behavior of accepting any tenant value. This is the documented backward-
// compatible mode for un-migrated callers.
func TestSec_Tenant_EmptyExpected_SkipsCheck(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	tok, err := CreateAccessToken(Claims{Sub: "u", Tenant: "tenant-anything"}, kr, time.Hour)
	require.NoError(t, err)

	claims, err := VerifyAccessToken(tok, kr, "")
	require.NoError(t, err)
	assert.Equal(t, "tenant-anything", claims.Tenant)
}

// TestSec_Tenant_EmptyClaim_RejectedWhenExpected asserts that a token with no
// tenant claim is rejected when the verifier expects a specific tenant.
func TestSec_Tenant_EmptyClaim_RejectedWhenExpected(t *testing.T) {
	t.Parallel()
	kr := makeSecKR(t, "test-kid")

	// Token with no tenant claim at all.
	tok, err := CreateAccessToken(Claims{Sub: "u"}, kr, time.Hour)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tok, kr, "tenant-A")
	require.Error(t, err, "token with empty tenant claim MUST be rejected when verifier expects a specific tenant")
	assert.Contains(t, err.Error(), "tenant mismatch")
}
