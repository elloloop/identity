package assurance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/elloloop/identity/pkg/jwt"
)

// TokenAudience is the `aud` value that marks a JWT as an assurance
// token. It is what keeps the two token species signed by the same JWKS
// apart: assurance tokens always carry this audience, access tokens
// never do (and access-token verification additionally requires a `sub`,
// which assurance tokens never carry).
const TokenAudience = "assurance"

// HeaderName is the HTTP header clients attach an assurance token to,
// mirroring App Check's own-header transport rather than riding the
// Authorization header the identity token owns.
const HeaderName = "X-Assurance-Token"

// DefaultTokenTTL is the assurance-token lifetime when the deployment
// does not configure one. Kept short: the token freezes a point-in-time
// fact about the client, so its value decays in a way an identity does
// not.
const DefaultTokenTTL = time.Hour

// ErrTokenInvalid indicates an assurance token failed verification
// (bad signature, wrong audience, expired, project mismatch, or
// malformed). One error for every cause: a caller cannot let a client
// distinguish a forged token from an expired one.
var ErrTokenInvalid = errors.New("assurance: token invalid")

// TokenClaims are the facts an assurance token carries. There is
// deliberately no subject: an assurance token says "this request came
// from a client that passed these checks", never who is making it.
type TokenClaims struct {
	// Project scopes the token to the control-plane project it was
	// minted under; empty only for deployments without a project model.
	Project string
	// Providers records which assurance mechanisms passed, in `amr`
	// (RFC 8176-style) form — e.g. ["app_attest"] or ["turnstile"].
	Providers []string
	// DeviceID references the attested device record for tokens minted
	// from a hardware attestation; empty for web-evidence tokens.
	DeviceID string
	// IssuedAt / ExpiresAt are unix seconds, stamped by MintToken.
	IssuedAt  int64
	ExpiresAt int64
}

// MintToken signs an assurance token over claims with the deployment's
// active JWT key. ttl <= 0 uses DefaultTokenTTL.
func MintToken(ctx context.Context, signer jwt.Signer, claims TokenClaims, ttl time.Duration, now time.Time) (string, error) {
	if len(claims.Providers) == 0 {
		return "", errors.New("assurance: minting a token requires at least one passed provider")
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	m := map[string]any{
		"aud": []string{TokenAudience},
		"amr": claims.Providers,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if claims.Project != "" {
		m["project"] = claims.Project
	}
	if claims.DeviceID != "" {
		m["device_id"] = claims.DeviceID
	}
	signed, err := signer.SignClaims(ctx, m)
	if err != nil {
		return "", fmt.Errorf("assurance: signing token: %w", err)
	}
	return signed, nil
}

// VerifyToken verifies an assurance token against the deployment's
// published keys: signature by a known kid, the assurance audience, an
// enforced expiry, and — when expectedProject is non-empty — an exact
// project match (a token minted under one project is rejected on
// requests resolved to another, and a project-scoped deployment rejects
// unscoped tokens). All failures return ErrTokenInvalid.
func VerifyToken(tokenStr string, kp jwt.KeyProvider, expectedProject string, now time.Time) (*TokenClaims, error) {
	tokenBytes := []byte(tokenStr)

	msg, err := jws.Parse(tokenBytes)
	if err != nil || len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("%w: malformed", ErrTokenInvalid)
	}
	kid := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrTokenInvalid)
	}
	pub, ok := kp.Get(kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid", ErrTokenInvalid)
	}
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: converting key", ErrTokenInvalid)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("%w: setting kid", ErrTokenInvalid)
	}

	tok, err := jwtoken.Parse(
		tokenBytes,
		jwtoken.WithKey(jwa.RS256, key),
		jwtoken.WithValidate(true),
		jwtoken.WithClock(jwtoken.ClockFunc(func() time.Time { return now })),
		jwtoken.WithAudience(TokenAudience),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
	// jwx treats an absent exp as "no expiration"; an unbounded
	// assurance token must never verify.
	if tok.Expiration().IsZero() {
		return nil, fmt.Errorf("%w: missing expiration", ErrTokenInvalid)
	}
	// An assurance token asserts a CLIENT, never a subject. Rejecting a
	// sub-bearing token makes the access→assurance direction structural
	// rather than resting on the audience string alone — a deployment that
	// set its JWT audience to "assurance" would otherwise turn every access
	// token into an assurance token.
	if tok.Subject() != "" {
		return nil, fmt.Errorf("%w: assurance tokens carry no subject", ErrTokenInvalid)
	}

	claims := &TokenClaims{ExpiresAt: tok.Expiration().Unix()}
	// An absent iat decodes to the zero time, whose Unix() is a large
	// negative sentinel; report 0 ("unknown") instead, mirroring how the
	// sibling exp case is guarded above.
	if iat := tok.IssuedAt(); !iat.IsZero() {
		claims.IssuedAt = iat.Unix()
	}
	if v, ok := tok.Get("project"); ok {
		claims.Project, _ = v.(string)
	}
	if v, ok := tok.Get("device_id"); ok {
		claims.DeviceID, _ = v.(string)
	}
	if v, ok := tok.Get("amr"); ok {
		claims.Providers = toStringSlice(v)
	}
	if len(claims.Providers) == 0 {
		return nil, fmt.Errorf("%w: no amr", ErrTokenInvalid)
	}
	if expectedProject != "" && claims.Project != expectedProject {
		return nil, fmt.Errorf("%w: project mismatch", ErrTokenInvalid)
	}
	return claims, nil
}

// toStringSlice coerces the decoded JSON forms an `amr` claim can take
// ([]any from generic decoding, []string from our own mint path).
func toStringSlice(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
