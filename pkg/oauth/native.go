package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	// maxNativeReplayTTL bounds how long a redeemed native token's replay key
	// is retained. Google ID tokens live ~1h; the replay cache never needs to
	// remember a redeemed key past the token's own `exp`, and a mis-issued
	// far-future `exp` must not pin a row indefinitely, so retention is
	// min(exp, now+max).
	maxNativeReplayTTL = time.Hour
	// defaultNativeReplayTTL is the retention used when a token carries no
	// `exp`. Defensive: checkTokenTimes already tolerates a zero `exp`, so the
	// replay row still needs a bounded lifetime.
	defaultNativeReplayTTL = 5 * time.Minute
)

// NativeVerification is the result of verifying a native ID token: the
// canonical Identity plus the material NativeOAuthLogin needs to enforce
// single-use (replay protection). ReplayKey uniquely identifies the one
// issued token — the token's `jti` when the provider stamps one, else a
// stable digest of (provider|iss|sub|iat|aud|nonce). ExpiresAtMs is the
// token's `exp` (epoch ms, bounded to a sane max) so the redeemed-key row
// is retained only as long as the token could still be presented.
type NativeVerification struct {
	Identity    *Identity
	ReplayKey   string
	ExpiresAtMs int64
}

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
func (v *NativeVerifier) Verify(ctx context.Context, provider, idToken, rawNonce, product string) (*NativeVerification, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return v.verifyGoogle(ctx, idToken, product)
	case "apple":
		return v.verifyApple(ctx, idToken, rawNonce, product)
	default:
		return nil, fmt.Errorf("%w: unsupported native provider %q", ErrIdentityVerification, provider)
	}
}

func (v *NativeVerifier) verifyGoogle(ctx context.Context, idToken, product string) (*NativeVerification, error) {
	auds := audsFor(product, v.googleAudsByProduct, v.googleAuds)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: google native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.googleJWKS, idToken, jwa.RS256)
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
	if err := checkTokenTimes(tok, v.now()); err != nil {
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
	return v.buildVerification(&Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
		Provider:       "google",
	}, tok, "google", ""), nil
}

// nativeAppleClaims extends the hosted appleIDClaims (polymorphic
// email_verified) with the nonce claim the native flow verifies.
type nativeAppleClaims struct {
	appleIDClaims
	Nonce string `json:"nonce"`
}

func (v *NativeVerifier) verifyApple(ctx context.Context, idToken, rawNonce, product string) (*NativeVerification, error) {
	auds := audsFor(product, v.appleAudsByProduct, v.appleAuds)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: apple native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.appleJWKS, idToken, jwa.RS256)
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
	if err := checkTokenTimes(tok, v.now()); err != nil {
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
	return v.buildVerification(&Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           claims.Name,
		Provider:       "apple",
	}, tok, "apple", claims.Nonce), nil
}

// buildVerification packages a verified Identity with the replay-cache
// material derived from the same token. Both provider paths funnel through
// it so the replay key and expiry are computed identically.
func (v *NativeVerifier) buildVerification(id *Identity, tok jwt.Token, provider, nonce string) *NativeVerification {
	return &NativeVerification{
		Identity:    id,
		ReplayKey:   nativeReplayKey(tok, provider, nonce),
		ExpiresAtMs: v.replayExpiryMs(tok),
	}
}

// replayExpiryMs is the epoch-ms bound after which the redeemed-key row may
// be swept: the token's own `exp`, capped at now+maxNativeReplayTTL so a
// mis-issued far-future `exp` cannot pin the row indefinitely. A token with
// no `exp` gets defaultNativeReplayTTL.
func (v *NativeVerifier) replayExpiryMs(tok jwt.Token) int64 {
	now := v.now()
	until := tok.Expiration()
	if until.IsZero() {
		until = now.Add(defaultNativeReplayTTL)
	}
	if capAt := now.Add(maxNativeReplayTTL); until.After(capAt) {
		until = capAt
	}
	return until.UnixMilli()
}

// nativeReplayKey derives a stable identifier for a single issued native ID
// token. When the provider stamps a `jti` that alone identifies the token
// (unique per issuer); otherwise a digest over (provider|iss|sub|iat|aud|
// nonce) uniquely names it — a re-issued token for the same subject differs
// in `iat` (and `jti`/`nonce`), so a duplicate key can only be the SAME
// bearer token replayed. Provider prefixes the key so a `jti` collision
// across issuers cannot alias two distinct tokens.
func nativeReplayKey(tok jwt.Token, provider, nonce string) string {
	if jti := strings.TrimSpace(tok.JwtID()); jti != "" {
		return provider + "|jti|" + jti
	}
	auds := append([]string(nil), tok.Audience()...)
	sort.Strings(auds)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		provider,
		tok.Issuer(),
		tok.Subject(),
		strconv.FormatInt(tok.IssuedAt().Unix(), 10),
		strings.Join(auds, ","),
		nonce,
	}, "\x00")))
	return provider + "|d|" + hex.EncodeToString(sum[:])
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
