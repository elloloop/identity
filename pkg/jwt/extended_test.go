package jwt

import (
	"context"
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
	s := newMemSigner(t, "test-kid")

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
			_, err := VerifyAccessToken(tc.token, s, "", "", false)
			require.Error(t, err)
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
	bogus := `{"payload":"eyJzdWIiOiJ4In0","signatures":[]}`
	_, err := extractKID([]byte(bogus))
	require.Error(t, err)
}

// TestVerify_OversizedToken ensures gigantic inputs don't panic and return
// an error cleanly.
func TestVerify_OversizedToken(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")
	huge := strings.Repeat("A", 1<<16) + "." + strings.Repeat("B", 1<<16) + "." + strings.Repeat("C", 1<<16)
	_, err := VerifyAccessToken(huge, s, "", "", false)
	require.Error(t, err)
}

// TestVerify_AlgNoneRejected ensures tokens signed with alg=none cannot be
// verified.
func TestVerify_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"test-kid","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","exp":9999999999}`))
	tokenStr := header + "." + payload + "."

	_, err := VerifyAccessToken(tokenStr, s, "", "", false)
	require.Error(t, err)
}

// TestVerify_HS256Rejected ensures a token signed with HS256 is rejected.
func TestVerify_HS256Rejected(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")

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

	_, err = VerifyAccessToken(string(signed), s, "", "", false)
	require.Error(t, err)
}

// TestVerify_FutureIssued: tokens with iat far in the future are rejected.
func TestVerify_FutureIssued(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "test-kid")

	tok, err := jwtoken.NewBuilder().
		Claim("sub", "x").
		Claim("email", "a@b.com").
		IssuedAt(time.Now().Add(48 * time.Hour)).
		Expiration(time.Now().Add(72 * time.Hour)).
		Build()
	require.NoError(t, err)

	mk := s.byKID[s.activeKID]
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, mk.jwk))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), s, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat")
}

// TestRotationChain exercises the full rotation flow on the abstract Signer:
// add a new key, promote it, drop the old one, and verify token-state
// transitions at each step.
func TestRotationChain(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "k1")
	s.addKey(t, "k2")
	require.Equal(t, "k1", s.ActiveKID())

	claims := Claims{Sub: "u1", Email: "u@x", Name: "U", Role: "member", Tenant: "t1"}
	t1, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	s.setActive("k2")
	require.Equal(t, "k2", s.ActiveKID())

	// Old token still verifies because k1 is still in the provider.
	_, err = VerifyAccessToken(t1, s, "", "", false)
	require.NoError(t, err)

	// New token is signed with k2.
	t2, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)
	_, err = VerifyAccessToken(t2, s, "", "", false)
	require.NoError(t, err)

	// Drop k1 entirely. Now the old token must fail.
	s.dropKey("k1")
	_, err = VerifyAccessToken(t1, s, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing key")
}

// TestAssertJWKSIncludesActiveKIDs panics when the active kid is missing
// from the published JWKS document. This is the startup-assertion the
// service runs before serving any RPCs.
func TestAssertJWKSIncludesActiveKIDs(t *testing.T) {
	t.Parallel()
	s := newMemSigner(t, "primary")
	s.addKey(t, "secondary")

	if err := AssertJWKSIncludesActiveKIDs(s, time.Now()); err != nil {
		t.Fatalf("AssertJWKSIncludesActiveKIDs: %v", err)
	}

	// Force a drift: keep activeKID = "missing" but only publish "primary".
	s.activeKID = "missing"
	err := AssertJWKSIncludesActiveKIDs(s, time.Now())
	if err == nil {
		t.Fatalf("expected error for drifted active kid")
	}
}
