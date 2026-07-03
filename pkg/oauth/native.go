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

// maxNativeReplayTTL bounds how long a redeemed native token's replay key is
// retained. Google ID tokens live ~1h; the replay cache never needs to
// remember a redeemed key past the token's own `exp`, and a mis-issued
// far-future `exp` must not pin a row indefinitely, so retention is
// min(exp, now+max). Every native token is guaranteed to carry an `exp`
// (requireNativeExp rejects one that does not), so a zero `exp` never reaches
// the replay-expiry computation.
const maxNativeReplayTTL = time.Hour

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

// NativeVerifierConfig configures a NativeVerifier. It holds only the
// project-INDEPENDENT state: the JWKS endpoints (shared across projects — a
// provider's signing keys do not vary per project) and the accepted issuer(s).
// The accepted audience set and (for Microsoft) the issuer/tenant pinning are
// supplied PER REQUEST via NativeVerifyParams, resolved by the caller from the
// request's project scope — so one verifier with shared JWKS caches serves
// every project.
type NativeVerifierConfig struct {
	// GoogleJWKSURL / AppleJWKSURL / MicrosoftJWKSURL override the default
	// provider JWKS endpoints (used by tests to point at a stub). Empty uses the
	// live URL.
	GoogleJWKSURL    string
	AppleJWKSURL     string
	MicrosoftJWKSURL string

	// GoogleIssuer / AppleIssuer override the accepted issuer(s) (tests only).
	// Empty uses the live issuer(s). Microsoft's expected issuer is derived
	// per-request from the token's `tid` and the project's issuer format.
	GoogleIssuer string
	AppleIssuer  string

	HTTPClient   *http.Client
	JWKSCacheTTL time.Duration
	Now          func() time.Time
}

// NativeVerifyParams are the per-request inputs to Verify. The accepted
// audience set (and, for Microsoft, the issuer/tenant pinning) are resolved by
// the caller from the request's project scope — the verifier holds no
// per-project audience state, only the shared JWKS caches.
type NativeVerifyParams struct {
	// Provider is the native provider key: "google", "apple", or "microsoft".
	Provider string
	// IDToken is the JWT a native SDK returned (Google idToken / Apple
	// identityToken / Microsoft id_token).
	IDToken string
	// RawNonce is the client-supplied nonce. Apple stamps the SHA-256 of it on
	// the id_token nonce claim; Microsoft stamps it VERBATIM; Google does not
	// use it. Empty skips the nonce check.
	RawNonce string
	// Audiences is the accepted `aud` allow-list for this request's project +
	// provider. Empty means the provider is not configured for the project, so
	// the token is rejected.
	Audiences []string
	// MicrosoftTenantID, when set to a concrete directory id, pins the accepted
	// tenant: the token's `tid` must equal it. A meta value
	// ("common"/"organizations"/"consumers") or empty keeps the multi-tenant
	// default (issuer derived from the token's own `tid`). Ignored for
	// Google/Apple.
	MicrosoftTenantID string
	// MicrosoftAllowedTenants, when non-empty, restricts the accepted tenant to
	// the listed directory (tenant) GUIDs — the multi-tenant counterpart to the
	// single MicrosoftTenantID pin. A token whose `tid` is not a member (matched
	// case-insensitively) is rejected. Ignored for Google/Apple.
	MicrosoftAllowedTenants []string
	// MicrosoftIssuerFormat overrides the issuer format string interpolated with
	// the tenant id to derive the expected issuer. Empty uses the live Microsoft
	// format. Ignored for Google/Apple.
	MicrosoftIssuerFormat string
}

// NativeVerifier verifies native mobile-SDK ID tokens (Google idToken / Apple
// identityToken / Microsoft id_token) WITHOUT an OAuth code exchange, producing
// a canonical Identity. It reuses the same JWKS cache + JWS verification + claim
// parsing the hosted Exchangers use; the difference is that `aud` is matched
// against the audience set supplied PER REQUEST (resolved from the caller's
// project scope — never a single web client id), and the provider nonce handling
// differs (Apple: SHA-256; Microsoft: verbatim; Google: none). The JWKS caches
// are shared across projects because a provider's signing keys are
// project-independent.
type NativeVerifier struct {
	googleIssuers []string
	appleIssuer   string
	googleJWKS    *jwksCache
	appleJWKS     *jwksCache
	microsoftJWKS *jwksCache
	now           func() time.Time
}

// NewNativeVerifier builds a NativeVerifier. JWKS caches are created for every
// provider regardless of which are configured per project; a provider with no
// audiences for a request is rejected at Verify time, so an unconfigured
// provider's cache is never consulted for that request.
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
	// Default to the same JWKS endpoints the hosted google/apple/microsoft
	// exchangers use (google.go / apple.go / microsoft.go); tests override via cfg.
	gJWKSURL := cfg.GoogleJWKSURL
	if gJWKSURL == "" {
		gJWKSURL = googleJWKSURL
	}
	aJWKSURL := cfg.AppleJWKSURL
	if aJWKSURL == "" {
		aJWKSURL = appleJWKSURL
	}
	mJWKSURL := cfg.MicrosoftJWKSURL
	if mJWKSURL == "" {
		mJWKSURL = microsoftJWKSURL
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
		googleIssuers: gIssuers,
		appleIssuer:   aIssuer,
		googleJWKS:    newJWKSCache(gJWKSURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
		appleJWKS:     newJWKSCache(aJWKSURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
		microsoftJWKS: newJWKSCache(mJWKSURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
		now:           cfg.Now,
	}
}

// Verify validates a native ID token against the per-request params and returns
// a canonical, verified Identity. p.Audiences is the accepted `aud` set for the
// request's project + provider; p.RawNonce is the un-hashed request nonce
// (Apple/Microsoft). Every failure returns an error wrapping
// ErrIdentityVerification or ErrEmailNotVerified so the caller can map it to a
// single, safe Unauthenticated response — the reason (bad aud, wrong project,
// expired, …) is never leaked to the client. Failure errors deliberately omit
// the token's email address: the service logs them with zap.Error at the
// native-login failure site, and the raw email is PII that must not reach logs.
func (v *NativeVerifier) Verify(ctx context.Context, p NativeVerifyParams) (*NativeVerification, error) {
	switch strings.ToLower(strings.TrimSpace(p.Provider)) {
	case "google":
		return v.verifyGoogle(ctx, p)
	case "apple":
		return v.verifyApple(ctx, p)
	case "microsoft":
		return v.verifyMicrosoft(ctx, p)
	default:
		return nil, fmt.Errorf("%w: unsupported native provider %q", ErrIdentityVerification, p.Provider)
	}
}

func (v *NativeVerifier) verifyGoogle(ctx context.Context, p NativeVerifyParams) (*NativeVerification, error) {
	auds := toSet(p.Audiences)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: google native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.googleJWKS, p.IDToken, jwa.RS256)
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
	if err := requireNativeExp(tok); err != nil {
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
		return nil, fmt.Errorf("%w: provider reports email unverified", ErrEmailNotVerified)
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

func (v *NativeVerifier) verifyApple(ctx context.Context, p NativeVerifyParams) (*NativeVerification, error) {
	auds := toSet(p.Audiences)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: apple native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.appleJWKS, p.IDToken, jwa.RS256)
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
	if err := requireNativeExp(tok); err != nil {
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
	// claim is a hard reject — it is the native flow's replay protection. NOTE:
	// Apple HASHES the nonce; Microsoft (verifyMicrosoft) compares it VERBATIM.
	if strings.TrimSpace(p.RawNonce) != "" {
		if !nonceMatches(p.RawNonce, claims.Nonce) {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrIdentityVerification)
		}
	}

	// email_verified is polymorphic (bool OR string "true") — reuse the hosted
	// Apple flow's stance. Relay (Hide My Email) addresses arrive verified and
	// are accepted as-is, exactly like apple.go's Exchange path.
	if !claimIsTrue(claims.EmailVerified) {
		return nil, fmt.Errorf("%w: provider reports email unverified", ErrEmailNotVerified)
	}
	return v.buildVerification(&Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           claims.Name,
		Provider:       "apple",
	}, tok, "apple", claims.Nonce), nil
}

// nativeMicrosoftClaims extends the hosted microsoftIDClaims with the nonce
// claim the native flow verifies. Microsoft stamps the nonce VERBATIM (unlike
// Apple, which hashes it).
type nativeMicrosoftClaims struct {
	microsoftIDClaims
	Nonce string `json:"nonce"`
}

// verifyMicrosoft verifies a native Microsoft (Azure AD) id_token, mirroring the
// hosted verifier's claim handling (microsoft.go verifyIDToken): the expected
// issuer is derived from the token's `tid` and the project's issuer format, the
// email is coalesced from email → preferred_username → upn, and the subject is
// oid then sub. A single-tenant project pins the tenant via p.MicrosoftTenantID;
// the default keeps multi-tenant (issuer from the token's own `tid`).
func (v *NativeVerifier) verifyMicrosoft(ctx context.Context, p NativeVerifyParams) (*NativeVerification, error) {
	auds := toSet(p.Audiences)
	if len(auds) == 0 {
		return nil, fmt.Errorf("%w: microsoft native login not configured", ErrIdentityVerification)
	}
	payload, err := verifyJWSWithRotation(ctx, v.microsoftJWKS, p.IDToken, jwa.RS256)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}

	var claims nativeMicrosoftClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.TID == "" {
		return nil, fmt.Errorf("%w: missing tid", ErrIdentityVerification)
	}
	pin := microsoftTenantPin{TenantID: p.MicrosoftTenantID, AllowedTenants: p.MicrosoftAllowedTenants}
	pinned, err := pin.enforce(claims.TID)
	if err != nil {
		return nil, err
	}
	issuerFormat := p.MicrosoftIssuerFormat
	if issuerFormat == "" {
		issuerFormat = microsoftIssuerFormat
	}
	expectedIss := fmt.Sprintf(issuerFormat, claims.TID)
	if iss := tok.Issuer(); iss != expectedIss {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	if !audInSet(tok.Audience(), auds) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	if err := checkTokenTimes(tok, v.now()); err != nil {
		return nil, err
	}
	if err := requireNativeExp(tok); err != nil {
		return nil, err
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" {
		email = strings.TrimSpace(claims.PreferredUsername)
	}
	if email == "" {
		email = strings.TrimSpace(claims.UPN)
	}
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}
	if claims.VerifiedEmail != nil && !*claims.VerifiedEmail {
		return nil, fmt.Errorf("%w: provider reports email unverified", ErrEmailNotVerified)
	}
	// nOAuth guard (identical to the hosted exchanger): a multi-tenant Microsoft
	// email is trusted only when the tenant is pinned, or xms_edov proves domain
	// ownership. Unproven ⇒ treat as unverified.
	if !microsoftEmailTrusted(pinned, &claims.microsoftIDClaims) {
		return nil, fmt.Errorf("%w: provider reports email unverified", ErrEmailNotVerified)
	}

	subject := claims.OID
	if subject == "" {
		subject = claims.Sub
	}
	if subject == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrIdentityVerification)
	}

	// Nonce: Microsoft echoes the client-supplied nonce VERBATIM (it is not a
	// digest, unlike Apple). When the client supplied one, require an exact
	// match; when it did not, skip the check (like Google).
	if strings.TrimSpace(p.RawNonce) != "" {
		if claims.Nonce != p.RawNonce {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrIdentityVerification)
		}
	}

	return v.buildVerification(&Identity{
		ProviderUserID: subject,
		Email:          strings.ToLower(email),
		EmailVerified:  true,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
		Provider:       "microsoft",
	}, tok, "microsoft", claims.Nonce), nil
}

// requireNativeExp rejects a native ID token that carries no `exp` claim. Real
// Google/Apple native ID tokens always stamp `exp`; the shared checkTokenTimes
// is intentionally tolerant of a missing `exp` for the hosted flows, so a
// native token without one would otherwise pass the time check and be retained
// for only the default replay TTL. This stricter rule is native-only — it does
// not change hosted google/apple/microsoft/oidc behavior.
func requireNativeExp(tok jwt.Token) error {
	if tok.Expiration().IsZero() {
		return fmt.Errorf("%w: native id token missing exp", ErrIdentityVerification)
	}
	return nil
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
// mis-issued far-future `exp` cannot pin the row indefinitely. Callers reach
// this only after requireNativeExp, so `exp` is always present.
func (v *NativeVerifier) replayExpiryMs(tok jwt.Token) int64 {
	now := v.now()
	until := tok.Expiration()
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
