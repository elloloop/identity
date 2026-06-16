package jwt

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAndVerify(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	claims := Claims{
		Sub:       "user-123",
		Email:     "alice@example.com",
		Name:      "Alice Smith",
		Role:      "admin",
		Tenant:    "tenant-abc",
		Project:   "proj-xyz",
		AvatarURL: "https://example.com/avatar.png",
	}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	got, err := VerifyAccessToken(tokenStr, s, "", "", false)
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.Sub)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, "Alice Smith", got.Name)
	assert.Equal(t, "admin", got.Role)
	assert.Equal(t, "tenant-abc", got.Tenant)
	assert.Equal(t, "proj-xyz", got.Project)
	assert.Equal(t, "https://example.com/avatar.png", got.AvatarURL)
	assert.True(t, got.IssuedAt > 0)
	assert.True(t, got.ExpiresAt > got.IssuedAt)
}

// A minor's token carries is_minor=true and round-trips. A token without
// the claim verifies with IsMinor=false (the claim is omitted, not forced).
func TestCreateAndVerify_IsMinorClaim(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	minorTok, err := s.SignAccessToken(context.Background(), Claims{
		Sub: "kid", Email: "kid@b.com", Role: "member", Tenant: "t", IsMinor: true,
	}, 15*time.Minute)
	require.NoError(t, err)
	gotMinor, err := VerifyAccessToken(minorTok, s, "", "", false)
	require.NoError(t, err)
	assert.True(t, gotMinor.IsMinor, "minor token must carry is_minor=true")

	adultTok, err := s.SignAccessToken(context.Background(), Claims{
		Sub: "adult", Email: "a@b.com", Role: "member", Tenant: "t",
	}, 15*time.Minute)
	require.NoError(t, err)
	gotAdult, err := VerifyAccessToken(adultTok, s, "", "", false)
	require.NoError(t, err)
	assert.False(t, gotAdult.IsMinor, "non-minor token verifies with IsMinor=false")
}

// A token minted before the project model (no Project claim) round-trips
// with an empty Project — the claim is omitted, not a forced "".
func TestCreateAndVerify_NoProjectClaim(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	tokenStr, err := s.SignAccessToken(context.Background(), Claims{
		Sub: "u", Email: "a@b.com", Role: "member", Tenant: "t",
	}, 15*time.Minute)
	require.NoError(t, err)

	got, err := VerifyAccessToken(tokenStr, s, "", "", false)
	require.NoError(t, err)
	assert.Empty(t, got.Project, "a token with no project claim verifies with empty Project")
}

func TestVerify_ExpiredToken(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	claims := Claims{
		Sub:    "user-123",
		Email:  "alice@example.com",
		Name:   "Alice",
		Role:   "member",
		Tenant: "t1",
	}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, -1*time.Second)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tokenStr, s, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifying token")
}

func TestVerify_WrongKey(t *testing.T) {
	s1 := newMemSigner(t, "test-kid")

	claims := Claims{
		Sub:    "user-123",
		Email:  "alice@example.com",
		Name:   "Alice",
		Role:   "member",
		Tenant: "t1",
	}
	tokenStr, err := s1.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	// Verify against a different signer with the same kid but different key.
	s2 := newMemSigner(t, "test-kid")

	_, err = VerifyAccessToken(tokenStr, s2, "", "", false)
	require.Error(t, err)
}

func TestVerify_MissingKID(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	// Manually build a token without a kid header.
	tok, err := jwtoken.NewBuilder().
		Claim("sub", "user-123").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(15 * time.Minute)).
		Build()
	require.NoError(t, err)

	// Sign with raw key (no kid set on key).
	mk := s.byKID[s.activeKID]
	key, err := jwk.FromRaw(mk.pub.Key)
	require.NoError(t, err)
	// We need the private key here for signing; reach into the test
	// helper directly since this is a structural negative test.
	priv := mk.jwk
	_ = key
	_ = priv

	// Build a JWK that lacks the kid header.
	stripped, err := priv.Clone()
	require.NoError(t, err)
	require.NoError(t, stripped.Remove(jwk.KeyIDKey))

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, stripped))
	require.NoError(t, err)

	_, err = VerifyAccessToken(string(signed), s, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing kid")
}

func TestVerify_UnknownKID(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	// Build a separate signer whose kid is not known to s.
	other := newMemSigner(t, "unknown-kid")
	tok, err := other.SignAccessToken(context.Background(), Claims{
		Sub:    "user-123",
		Tenant: "t",
	}, 15*time.Minute)
	require.NoError(t, err)

	_, err = VerifyAccessToken(tok, s, "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing key")
}

func TestCreateToken_HasKIDHeader(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	claims := Claims{
		Sub:    "user-123",
		Email:  "a@b.com",
		Name:   "A",
		Role:   "member",
		Tenant: "t1",
	}
	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	kid, err := extractKID([]byte(tokenStr))
	require.NoError(t, err)
	assert.Equal(t, "test-kid", kid)
}

func TestClaims_AllFieldsPresent(t *testing.T) {
	s := newMemSigner(t, "test-kid")

	claims := Claims{
		Sub:       "user-456",
		Email:     "bob@example.com",
		Name:      "Bob Jones",
		Role:      "owner",
		Tenant:    "tenant-xyz",
		AvatarURL: "https://cdn.example.com/bob.jpg",
	}

	tokenStr, err := s.SignAccessToken(context.Background(), claims, 15*time.Minute)
	require.NoError(t, err)

	tok, err := jwtoken.Parse([]byte(tokenStr), jwtoken.WithVerify(false), jwtoken.WithValidate(false))
	require.NoError(t, err)

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
