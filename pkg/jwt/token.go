package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims holds the fields embedded in an access token.
type Claims struct {
	Sub       string `json:"sub"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Tenant    string `json:"tenant"`
	AvatarURL string `json:"avatar_url"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// CreateAccessToken signs a new RS256 access token using the active key in the
// ring. The token always carries a "kid" header so verifiers can pick the
// correct public key.
func CreateAccessToken(claims Claims, kr *KeyRing, expiry time.Duration) (string, error) {
	now := time.Now().Unix()
	exp := now + int64(expiry.Seconds())

	tok, err := jwtoken.NewBuilder().
		Claim("sub", claims.Sub).
		Claim("email", claims.Email).
		Claim("name", claims.Name).
		Claim("role", claims.Role).
		Claim("tenant", claims.Tenant).
		Claim("avatar_url", claims.AvatarURL).
		IssuedAt(time.Unix(now, 0)).
		Expiration(time.Unix(exp, 0)).
		Build()
	if err != nil {
		return "", fmt.Errorf("building token: %w", err)
	}

	active := kr.Active()

	// Build the JWK for signing (includes kid header).
	key, err := jwk.FromRaw(active.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("converting private key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, active.KID); err != nil {
		return "", fmt.Errorf("setting kid on key: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return "", fmt.Errorf("setting alg on key: %w", err)
	}

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return string(signed), nil
}

// VerifyAccessToken verifies an RS256 access token and returns its claims.
// The token must carry a "kid" header that matches a key in the ring.
// Tokens without "kid" or with an unknown "kid" are rejected.
//
// If expectedTenant is non-empty, the token's "tenant" claim must match it
// exactly; otherwise the token is rejected. Passing an empty expectedTenant
// disables the cross-tenant check (backward-compatible mode).
//
// Tokens with a missing or zero "exp" claim are explicitly rejected: the
// underlying lestrrat-go jwt library treats an absent exp as "no expiration",
// which would otherwise produce unbounded-lifetime tokens.
func VerifyAccessToken(tokenStr string, kr *KeyRing, expectedTenant string) (*Claims, error) {
	tokenBytes := []byte(tokenStr)

	// Extract kid from JWS protected header before verification.
	kid, err := extractKID(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing token headers: %w", err)
	}
	if kid == "" {
		return nil, errors.New("token missing kid header")
	}

	// Check that the kid is known.
	sk, ok := kr.Get(kid)
	if !ok {
		return nil, fmt.Errorf("unknown signing key kid=%s", kid)
	}

	// Build a JWK from the matching public key.
	key, err := jwk.FromRaw(sk.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("converting public key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("setting alg: %w", err)
	}

	// Parse and verify.
	tok, err := jwtoken.Parse(
		tokenBytes,
		jwtoken.WithKey(jwa.RS256, key),
		jwtoken.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	// Explicit expiration check: lestrrat-go's WithValidate() treats a missing
	// or zero exp claim as "no expiration set" rather than an expired token,
	// so we enforce it ourselves.
	exp := tok.Expiration()
	if exp.IsZero() {
		return nil, errors.New("token missing or zero expiration")
	}
	if time.Now().UTC().After(exp) {
		return nil, errors.New("token expired")
	}

	claims := &Claims{}
	claims.IssuedAt = tok.IssuedAt().Unix()
	claims.ExpiresAt = exp.Unix()

	if v, ok := tok.Get("sub"); ok {
		claims.Sub, _ = v.(string)
	}
	if v, ok := tok.Get("email"); ok {
		claims.Email, _ = v.(string)
	}
	if v, ok := tok.Get("name"); ok {
		claims.Name, _ = v.(string)
	}
	if v, ok := tok.Get("role"); ok {
		claims.Role, _ = v.(string)
	}
	if v, ok := tok.Get("tenant"); ok {
		claims.Tenant, _ = v.(string)
	}
	if v, ok := tok.Get("avatar_url"); ok {
		claims.AvatarURL, _ = v.(string)
	}

	// Cross-tenant check: when the verifying service knows its expected
	// tenant, reject tokens whose tenant claim does not match.
	if expectedTenant != "" && claims.Tenant != expectedTenant {
		return nil, fmt.Errorf("tenant mismatch: token tenant=%q expected=%q", claims.Tenant, expectedTenant)
	}

	return claims, nil
}

// extractKID parses the JWS compact serialization and returns the "kid"
// from the protected header, or empty string if not present.
func extractKID(tokenBytes []byte) (string, error) {
	msg, err := jws.Parse(tokenBytes)
	if err != nil {
		return "", err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return "", errors.New("no signatures in token")
	}
	headers := sigs[0].ProtectedHeaders()
	return headers.KeyID(), nil
}
