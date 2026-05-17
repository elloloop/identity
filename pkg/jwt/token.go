package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims holds the fields embedded in an access token.
//
// SID is the session id added when the service is running in
// `GATEWAY_REVOCATION_MODE=session`. It is the empty string in
// mode=ttl deployments, in which case the verification middleware
// skips the session lookup entirely (the hot path keeps its zero
// cost). The claim is JSON-named `sid` so it lines up with OAuth /
// OIDC tooling that already understands the `sid` convention.
type Claims struct {
	Sub       string   `json:"sub"`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
	Role      string   `json:"role"`
	Tenant    string   `json:"tenant"`
	AvatarURL string   `json:"avatar_url"`
	SID       string   `json:"sid,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// ClaimsMap converts the access-token claims plus standard iat/exp into
// the generic claim map [Signer.SignClaims] consumes. Used internally by
// concrete signers; exposed so future backends in other repositories
// can reuse the canonical claim layout.
func (c Claims) ClaimsMap(now time.Time, expiry time.Duration) map[string]any {
	iat := now.Unix()
	exp := now.Add(expiry).Unix()
	m := map[string]any{
		"sub":        c.Sub,
		"email":      c.Email,
		"name":       c.Name,
		"role":       c.Role,
		"tenant":     c.Tenant,
		"avatar_url": c.AvatarURL,
		"iat":        iat,
		"exp":        exp,
	}
	if c.SID != "" {
		m["sid"] = c.SID
	}
	if len(c.Audience) > 0 {
		m["aud"] = c.Audience
	}
	return m
}

// VerifyAccessToken verifies an RS256 access token against the supplied
// [KeyProvider] and returns its claims. The token must carry a "kid"
// header that matches a key the provider publishes. Tokens without
// "kid" or with an unknown "kid" are rejected.
//
// If expectedTenant is non-empty, the token's "tenant" claim must match
// it exactly; otherwise the token is rejected. Passing an empty
// expectedTenant disables the cross-tenant check.
//
// Audience handling:
//   - If expectedAudience is empty, the "aud" claim is not inspected.
//   - If expectedAudience is non-empty and the token's "aud" claim is
//     present, it must contain expectedAudience (a token MAY carry
//     multiple audiences — the check passes when any of them matches).
//   - If expectedAudience is non-empty and the token has no "aud"
//     claim, the token is rejected only when requireAudience is true.
//     This gives callers a one-deploy migration window: ship the
//     verifier with requireAudience=false, wait for all minted tokens
//     to carry "aud", then flip requireAudience=true.
//   - A token whose "aud" claim is present but does not contain
//     expectedAudience is ALWAYS rejected, regardless of
//     requireAudience.
//
// Tokens with a missing or zero "exp" claim are explicitly rejected:
// the underlying lestrrat-go jwt library treats an absent exp as
// "no expiration", which would otherwise produce unbounded-lifetime
// tokens.
func VerifyAccessToken(tokenStr string, kp KeyProvider, expectedTenant, expectedAudience string, requireAudience bool) (*Claims, error) {
	tokenBytes := []byte(tokenStr)

	kid, err := extractKID(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing token headers: %w", err)
	}
	if kid == "" {
		return nil, errors.New("token missing kid header")
	}

	pub, ok := kp.Get(kid)
	if !ok {
		return nil, fmt.Errorf("unknown signing key kid=%s", kid)
	}

	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("converting public key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("setting alg: %w", err)
	}

	tok, err := jwtoken.Parse(
		tokenBytes,
		jwtoken.WithKey(jwa.RS256, key),
		jwtoken.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

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
	if v, ok := tok.Get("sid"); ok {
		claims.SID, _ = v.(string)
	}
	claims.Audience = tok.Audience()

	if expectedTenant != "" && claims.Tenant != expectedTenant {
		return nil, fmt.Errorf("tenant mismatch: token tenant=%q expected=%q", claims.Tenant, expectedTenant)
	}

	if expectedAudience != "" {
		if len(claims.Audience) == 0 {
			if requireAudience {
				return nil, fmt.Errorf("audience missing: expected=%q", expectedAudience)
			}
		} else {
			matched := false
			for _, a := range claims.Audience {
				if a == expectedAudience {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("audience mismatch: token aud=%v expected=%q", claims.Audience, expectedAudience)
			}
		}
	}

	return claims, nil
}

// JWKS renders the [KeyProvider]'s public keys as a JWKS document (RFC
// 7517) suitable for serving at /.well-known/jwks.json. Every key the
// provider exposes is included so verifiers can validate tokens minted
// before a rotation completed.
func JWKS(kp KeyProvider) ([]byte, error) {
	set := jwk.NewSet()
	for _, pk := range kp.Keys() {
		key, err := jwk.FromRaw(pk.Key)
		if err != nil {
			return nil, fmt.Errorf("converting public key for kid=%s: %w", pk.KID, err)
		}
		if err := key.Set(jwk.KeyIDKey, pk.KID); err != nil {
			return nil, fmt.Errorf("setting kid: %w", err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
			return nil, fmt.Errorf("setting alg: %w", err)
		}
		if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return nil, fmt.Errorf("setting use: %w", err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("adding key to set: %w", err)
		}
	}
	return json.Marshal(set)
}

// AssertJWKSIncludesActiveKIDs is a startup sanity check: every
// currently-active kid the signer reports must appear in the JWKS
// document the verifier publishes. Drift here means a third-party
// service that fetched JWKS once cannot validate the next token we
// mint.
//
// Returns an error when (a) JWKS rendering fails, or (b) any active
// kid is missing from the rendered JWKS. Pass the rendered JWKS into a
// startup assertion (cmd/identity/main.go panics on error). Inactive
// (expired-but-still-publishable) keys are NOT required to appear.
func AssertJWKSIncludesActiveKIDs(s Signer, now time.Time) error {
	jwksBytes, err := JWKS(s)
	if err != nil {
		return fmt.Errorf("rendering JWKS: %w", err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksBytes, &doc); err != nil {
		return fmt.Errorf("decoding rendered JWKS: %w", err)
	}
	published := make(map[string]bool, len(doc.Keys))
	for _, k := range doc.Keys {
		published[k.Kid] = true
	}

	activeKID := s.ActiveKID()
	if activeKID == "" {
		return errors.New("signer has no active kid")
	}
	if !published[activeKID] {
		return fmt.Errorf("signer active kid %q is not in JWKS", activeKID)
	}

	for _, k := range s.Keys() {
		if !k.IsActive(now) {
			continue
		}
		if !published[k.KID] {
			return fmt.Errorf("active kid %q is missing from JWKS", k.KID)
		}
	}
	return nil
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
