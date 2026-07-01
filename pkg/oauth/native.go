package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// googleIssuers are the two issuer strings Google stamps on an ID token. The
// non-https form is historical but still emitted, so both are accepted (this
// matches the hosted Google provider's iss check in google.go).
var googleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

// NativeVerifierConfig configures a NativeVerifier. At least one provider's
// audiences must be non-empty for the verifier to accept that provider; a
// provider with no configured audiences is treated as unsupported.
type NativeVerifierConfig struct {
	// GoogleAudiences is the GLOBAL fallback set of accepted `aud` values for
	// Google ID tokens — the web client id PLUS every per-platform
	// (iOS/Android) OAuth client id the native SDKs present. It is consulted
	// only for a product with no entry in GoogleAudiencesByProduct. Empty
	// disables Google native login for those products.
	GoogleAudiences []string
	// AppleAudiences is the GLOBAL fallback set of accepted `aud` values for
	// Apple ID tokens — the Services ID PLUS every native bundle id. It is
	// consulted only for a product with no entry in AppleAudiencesByProduct.
	// Empty disables Apple native login for those products.
	AppleAudiences []string

	// GoogleAudiencesByProduct scopes the accepted Google `aud` values PER
	// PRODUCT, keyed by the lower-cased product selector. When a product has an
	// entry here, ONLY that entry's audiences are accepted for it — a token
	// whose `aud` is valid for another product (or only globally) is rejected.
	// A product with no entry falls back to GoogleAudiences.
	GoogleAudiencesByProduct map[string][]string
	// AppleAudiencesByProduct scopes the accepted Apple `aud` values PER
	// PRODUCT, keyed by the lower-cased product selector. Same semantics as
	// GoogleAudiencesByProduct: an entry is exclusive for its product, an
	// absent product falls back to AppleAudiences.
	AppleAudiencesByProduct map[string][]string

	// GoogleJWKSURL / AppleJWKSURL override the default provider JWKS
	// endpoints (used by tests to point at a stub). Empty uses the live URL.
	GoogleJWKSURL string
	AppleJWKSURL  string

	// GoogleIssuer / AppleIssuer override the accepted issuer(s) (tests only).
	// Empty uses the live issuer(s).
	GoogleIssuer string
	AppleIssuer  string

	HTTPClient   *http.Client
	JWKSCacheTTL time.Duration
	Now          func() time.Time
}

// NativeVerifier verifies native mobile-SDK ID tokens (Google idToken / Apple
// identityToken) WITHOUT an OAuth code exchange, producing a canonical
// Identity. It reuses the same JWKS cache + JWS verification + claim parsing
// the hosted Exchangers use; the only difference is that `aud` is matched
// against the audience set of the REQUESTED PRODUCT (a per-product set when
// configured, else the global fallback set — never a single web client id) and,
// for Apple, the request nonce is verified against the id_token claim. Scoping
// `aud` per product stops a token minted for product A's client id from being
// redeemed as product B.
type NativeVerifier struct {
	googleAuds          map[string]bool
	appleAuds           map[string]bool
	googleAudsByProduct map[string]map[string]bool
	appleAudsByProduct  map[string]map[string]bool
	googleIssuers       []string
	appleIssuer         string
	googleJWKS          *jwksCache
	appleJWKS           *jwksCache
	now                 func() time.Time
}

// NewNativeVerifier builds a NativeVerifier. JWKS caches are created for both
// providers regardless of whether their audiences are configured; a provider
// with no audiences is rejected at Verify time, so an unconfigured provider's
// cache is never consulted.
func NewNativeVerifier(cfg NativeVerifierConfig) *NativeVerifier {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient()
	}
	if cfg.JWKSCacheTTL == 0 {
		cfg.JWKSCacheTTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// Default to the same JWKS endpoints the hosted google/apple exchangers
	// use (google.go / apple.go); tests override via cfg.
	gJWKSURL := cfg.GoogleJWKSURL
	if gJWKSURL == "" {
		gJWKSURL = googleJWKSURL
	}
	aJWKSURL := cfg.AppleJWKSURL
	if aJWKSURL == "" {
		aJWKSURL = appleJWKSURL
	}
	gIssuers := googleIssuers
	if cfg.GoogleIssuer != "" {
		gIssuers = []string{cfg.GoogleIssuer}
	}
	aIssuer := appleIssuer
	if cfg.AppleIssuer != "" {
		aIssuer = cfg.AppleIssuer
	}
	return &NativeVerifier{
		googleAuds:          toSet(cfg.GoogleAudiences),
		appleAuds:           toSet(cfg.AppleAudiences),
		googleAudsByProduct: toSetByProduct(cfg.GoogleAudiencesByProduct),
		appleAudsByProduct:  toSetByProduct(cfg.AppleAudiencesByProduct),
		googleIssuers:       gIssuers,
		appleIssuer:         aIssuer,
		googleJWKS:          newJWKSCache(gJWKSURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
		appleJWKS:           newJWKSCache(aJWKSURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
		now:                 cfg.Now,
	}
}

// Verify validates a native ID token for the given provider and product, and
// returns a canonical, verified Identity. product selects the audience set the
// token's `aud` is matched against (see audsFor); rawNonce is the un-hashed
// nonce from the native request (Apple only); pass "" for Google. Every failure
// returns an error wrapping ErrIdentityVerification or ErrEmailNotVerified so
// the caller can map it to a single, safe Unauthenticated response — the reason
// (bad aud, wrong product, expired, …) is never leaked to the client.
func (v *NativeVerifier) Verify(ctx context.Context, provider, idToken, rawNonce, product string) (*Identity, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return v.verifyGoogle(ctx, idToken, product)
	case "apple":
		return v.verifyApple(ctx, idToken, rawNonce, product)
	default:
		return nil, fmt.Errorf("%w: unsupported native provider %q", ErrIdentityVerification, provider)
	}
}

func (v *NativeVerifier) verifyGoogle(ctx context.Context, idToken, product string) (*Identity, error) {
	auds := audsFor(product, v.googleAudsByProduct, v.googleAuds)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: google native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.googleJWKS, idToken)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}
	if !containsString(v.googleIssuers, tok.Issuer()) {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, tok.Issuer())
	}
	if !audInSet(tok.Audience(), auds) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	if err := v.checkTimes(tok); err != nil {
		return nil, err
	}

	var claims googleIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}
	if !claims.EmailVerified {
		return nil, fmt.Errorf("%w: email not verified: %s", ErrEmailNotVerified, email)
	}
	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
		Provider:       "google",
	}, nil
}

// nativeAppleClaims extends the hosted appleIDClaims (polymorphic
// email_verified) with the nonce claim the native flow verifies.
type nativeAppleClaims struct {
	appleIDClaims
	Nonce string `json:"nonce"`
}

func (v *NativeVerifier) verifyApple(ctx context.Context, idToken, rawNonce, product string) (*Identity, error) {
	auds := audsFor(product, v.appleAudsByProduct, v.appleAuds)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: apple native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.appleJWKS, idToken)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}
	if tok.Issuer() != v.appleIssuer {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, tok.Issuer())
	}
	if !audInSet(tok.Audience(), auds) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	if err := v.checkTimes(tok); err != nil {
		return nil, err
	}

	var claims nativeAppleClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}

	// Nonce: when the client supplied a raw nonce, the id_token's nonce claim
	// must equal the SHA-256 of that raw value (hex per the sign_in_with_apple
	// / Firebase convention; base64url also accepted). A missing or mismatched
	// claim is a hard reject — it is the native flow's replay protection.
	if strings.TrimSpace(rawNonce) != "" {
		if !nonceMatches(rawNonce, claims.Nonce) {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrIdentityVerification)
		}
	}

	// email_verified is polymorphic (bool OR string "true") — reuse the hosted
	// Apple flow's stance. Relay (Hide My Email) addresses arrive verified and
	// are accepted as-is, exactly like apple.go's Exchange path.
	if !appleEmailVerified(claims.EmailVerified) {
		return nil, fmt.Errorf("%w: email not verified: %s", ErrEmailNotVerified, email)
	}
	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           claims.Name,
		Provider:       "apple",
	}, nil
}

// checkTimes enforces exp (not in the past) and iat (not in the future,
// allowing the same 2-minute clock skew the hosted providers allow).
func (v *NativeVerifier) checkTimes(tok jwt.Token) error {
	now := v.now()
	if exp := tok.Expiration(); !exp.IsZero() && now.After(exp) {
		return fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
	}
	return nil
}

// verifyJWSWithRotation verifies a compact JWS against a JWKS cache, retrying
// once after a cache invalidation if the signing key was not found (handles
// provider key rotation). It mirrors the hosted exchangers' verifyIDToken
// preamble.
func verifyJWSWithRotation(ctx context.Context, cache *jwksCache, raw string) ([]byte, error) {
	set, err := cache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %w", ErrIdentityVerification, err)
	}
	payload, err := verifyJWS(raw, set)
	if err != nil && errors.Is(err, errKeyNotFound) {
		cache.Invalidate()
		set2, fErr := cache.Get(ctx)
		if fErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
		payload, err = verifyJWS(raw, set2)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
	}
	return payload, nil
}

// appleEmailVerified collapses Apple's polymorphic email_verified (bool or the
// string "true") to a boolean, matching apple.go's handling.
func appleEmailVerified(v interface{}) bool {
	switch ev := v.(type) {
	case bool:
		return ev
	case string:
		return ev == "true"
	default:
		return false
	}
}

// nonceMatches reports whether claim equals the hex or base64url (no padding)
// SHA-256 digest of rawNonce.
func nonceMatches(rawNonce, claim string) bool {
	if claim == "" {
		return false
	}
	sum := sha256.Sum256([]byte(rawNonce))
	return claim == hex.EncodeToString(sum[:]) ||
		claim == base64.RawURLEncoding.EncodeToString(sum[:])
}

// audsFor returns the audience set to match a token's `aud` against for the
// given product: the product's per-product set when one is configured (keyed
// case-insensitively), otherwise the global fallback set. A per-product entry
// is EXCLUSIVE — once a product has its own set, the global set is not merged
// in, so a token minted for a different product's client id is rejected even
// if that client id is globally allowed.
func audsFor(product string, byProduct map[string]map[string]bool, global map[string]bool) map[string]bool {
	if len(byProduct) > 0 {
		if set, ok := byProduct[strings.ToLower(strings.TrimSpace(product))]; ok {
			return set
		}
	}
	return global
}

// toSetByProduct converts a product→audiences map into a product→set map,
// lower-casing product keys and dropping products whose audience list is empty
// after trimming. A nil or empty input yields nil.
func toSetByProduct(in map[string][]string) map[string]map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]map[string]bool, len(in))
	for product, auds := range in {
		key := strings.ToLower(strings.TrimSpace(product))
		if key == "" {
			continue
		}
		if set := toSet(auds); len(set) > 0 {
			out[key] = set
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]bool, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" {
			out[it] = true
		}
	}
	return out
}

func audInSet(auds []string, set map[string]bool) bool {
	for _, a := range auds {
		if set[a] {
			return true
		}
	}
	return false
}
