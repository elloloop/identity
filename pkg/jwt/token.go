package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	// ErrTokenMalformed reports a token that is not a structurally valid
	// access token (unparseable JWS/JWT, missing kid, wrong typ profile,
	// or missing required sub/exp claims).
	ErrTokenMalformed = errors.New("token malformed")
	// ErrTokenSignature reports a token whose signing key is unknown or
	// whose cryptographic signature verification failed.
	ErrTokenSignature = errors.New("token signature invalid")
	// ErrTokenExpired reports a token whose exp claim is in the past.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenIssuer reports a token whose iss claim does not match the
	// expected issuer.
	ErrTokenIssuer = errors.New("token issuer mismatch")
	// ErrTokenAudience reports a token whose aud claim is missing or does
	// not match the expected audience.
	ErrTokenAudience = errors.New("token audience mismatch")
	// ErrTokenPurposeRejected reports a single-purpose bearer ticket
	// presented where a session access token is required (or with the
	// wrong purpose).
	ErrTokenPurposeRejected = errors.New("token purpose rejected")
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
	Sub   string `json:"sub"`
	Email string `json:"email"`
	// EmailVerified is the "email_verified" claim: true only when the
	// account's owner has proven control of the mailbox in Email. It is
	// present whenever Email is non-empty, true or false, and absent with
	// Email (ClaimsMap is the canonical serialization, not this json tag),
	// so a verifier gating on proof of the address reads an absent claim (a
	// token minted before the claim existed) as unproven.
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	Tenant        string `json:"tenant"`
	// Project is the control-plane project the token was minted for. It
	// scopes the token to one project so a token minted under project A is
	// rejected on a request resolved to project B (cross-project reuse).
	// Omitted from tokens minted before the project model (empty).
	Project   string `json:"project,omitempty"`
	AvatarURL string `json:"avatar_url"`
	// IsMinor marks the subject as a minor under the deployment's age-gate.
	// It is emitted only when true (omitempty) and only when age-gating is
	// on, so downstream apps can suppress profiling/behavioral features for
	// minors. Existing verifiers that don't know the claim ignore it.
	IsMinor bool `json:"is_minor,omitempty"`
	// Anonymous marks the subject as an anonymous account — a real user with
	// a stable sub but no credential of any kind. Emitted only when true
	// (omitempty), so tokens for identified users are byte-identical to
	// before. Downstream services MUST read it before granting anything that
	// assumes a verified human: an anonymous sub is cheap to mint, and
	// `email` is empty rather than absent-because-unverified. Firebase
	// carries the same signal as sign_in_provider="anonymous".
	Anonymous bool `json:"anonymous,omitempty"`
	// Kind is "agent" on a token whose subject is an agent account (a
	// non-human account a person owns) and empty otherwise, so tokens for
	// people are byte-identical to before: an absent kind means a person.
	// Downstream services MUST read it before granting anything that assumes
	// a human at the keyboard.
	Kind     string   `json:"kind,omitempty"`
	SID      string   `json:"sid,omitempty"`
	Audience []string `json:"aud,omitempty"`
	// Issuer is the "iss" claim: the deployment's configured issuer
	// (GATEWAY_JWT_ISSUER), so a verifier can pin who minted the token.
	// Omitted when unset, so tokens from a deployment without one are
	// byte-identical to before.
	Issuer string `json:"iss,omitempty"`
	// Purpose marks a token as a single-purpose bearer credential rather
	// than a session access token (e.g. "dob_completion" for the
	// required-DOB completion ticket). Empty on every normal access token.
	// Verifiers that authenticate requests MUST reject or ignore any token
	// whose purpose is non-empty — it is proof of one interrupted flow,
	// not of a session.
	Purpose string `json:"purpose,omitempty"`
	// Binding ties a purpose ticket to the state it was minted against (an
	// opaque fingerprint the issuing flow defines), so a change to that state
	// spends the ticket. Empty on access tokens and on unbound tickets.
	Binding string `json:"bnd,omitempty"`
	// AuthTime is when the user authenticated the session (epoch seconds,
	// OIDC's `auth_time`): the sign-in's time, kept unchanged across
	// refreshes, and absent when no sign-in opened the session (a QR handoff,
	// an anonymous account). On a purpose ticket it carries the sign-in of the
	// session the ticket interrupted. An RPC that needs a recent sign-in
	// compares it with now; its presence alone proves nothing recent.
	AuthTime  int64 `json:"auth_time,omitempty"`
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
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
	if c.Email != "" {
		m["email_verified"] = c.EmailVerified
	}
	if c.Project != "" {
		m["project"] = c.Project
	}
	if c.IsMinor {
		m["is_minor"] = true
	}
	if c.Anonymous {
		m["anonymous"] = true
	}
	if c.Kind != "" {
		m["kind"] = c.Kind
	}
	if c.SID != "" {
		m["sid"] = c.SID
	}
	if c.Purpose != "" {
		m["purpose"] = c.Purpose
	}
	if c.Binding != "" {
		m["bnd"] = c.Binding
	}
	if c.AuthTime > 0 {
		m["auth_time"] = c.AuthTime
	}
	if len(c.Audience) > 0 {
		m["aud"] = c.Audience
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
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
//
// A token carrying a non-empty `purpose` claim is REFUSED here: a purpose
// token is proof of one interrupted flow, never of a session. The rule lives
// in the shared verifier rather than in each caller so it holds on every
// transport — the HTTP middlewares, a native-gRPC host's own interceptor
// (see docs/embedding.md), and any downstream service verifying identity's
// tokens through the published JWKS. Use VerifyPurposeToken to verify a
// ticket on the one flow that redeems it.
func VerifyAccessToken(tokenStr string, kp KeyProvider, expectedTenant, expectedAudience string, requireAudience bool) (*Claims, error) {
	claims, err := verifyToken(tokenStr, kp, expectedTenant, expectedAudience, requireAudience)
	if err != nil {
		return nil, err
	}
	if claims.Purpose != "" {
		return nil, fmt.Errorf("%w: token has purpose=%q and authenticates no request", ErrTokenPurposeRejected, claims.Purpose)
	}
	return claims, nil
}

// VerifyPurposeToken verifies a single-purpose bearer ticket and requires its
// `purpose` claim to equal wantPurpose. It is the only way to get a
// purpose-bearing token past verification, so the flow that redeems a ticket
// names the purpose it expects and cannot be handed a ticket minted for a
// different one.
func VerifyPurposeToken(
	tokenStr string, kp KeyProvider, expectedTenant, expectedAudience string, requireAudience bool, wantPurpose string,
) (*Claims, error) {
	if wantPurpose == "" {
		return nil, errors.New("VerifyPurposeToken: wantPurpose is required")
	}
	claims, err := verifyToken(tokenStr, kp, expectedTenant, expectedAudience, requireAudience)
	if err != nil {
		return nil, err
	}
	if claims.Purpose != wantPurpose {
		return nil, fmt.Errorf("%w: token purpose=%q, want %q", ErrTokenPurposeRejected, claims.Purpose, wantPurpose)
	}
	return claims, nil
}

// PeekClaims decodes only the base64url JSON payload segment of a compact JWT
// without touching cryptographic keys or secret material, returning the
// non-secret claims needed for refusal diagnostics (sub, iss, project/pid,
// tenant/tid, sid, purpose, kind, aud, auth_time, iat, exp). It returns
// (nil, false) when tokenStr is not a three-segment compact token or its
// payload segment is not a valid base64url JSON object.
//
// Callers MUST NOT treat the returned claims as verified.
func PeekClaims(tokenStr string) (*Claims, bool) {
	if len(tokenStr) == 0 || len(tokenStr) > maxDelegatedAccessTokenBytes || strings.ContainsAny(tokenStr, " \t\r\n") {
		return nil, false
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	return &Claims{
		Sub:       str("sub"),
		Issuer:    str("iss"),
		Project:   str("project", "pid"),
		Tenant:    str("tenant", "tid"),
		SID:       str("sid"),
		Purpose:   str("purpose"),
		Kind:      str("kind"),
		Audience:  stringSliceClaim(m["aud"]),
		AuthTime:  numericClaim(m["auth_time"]),
		IssuedAt:  numericClaim(m["iat"]),
		ExpiresAt: numericClaim(m["exp"]),
	}, true
}

// verifyToken is the shared signature/claims verification both entry points
// run. It is deliberately unexported: everything outside this file goes
// through one of the two, so no caller can skip the purpose decision.
func verifyToken(tokenStr string, kp KeyProvider, expectedTenant, expectedAudience string, requireAudience bool) (*Claims, error) {
	return verifyTokenProfile(tokenStr, kp, expectedTenant, expectedAudience, requireAudience, "JWT")
}

func verifyTokenProfile(tokenStr string, kp KeyProvider, expectedTenant, expectedAudience string, requireAudience bool, profile string) (*Claims, error) {
	tokenBytes := []byte(tokenStr)
	key, err := verificationKey(tokenBytes, kp, profile)
	if err != nil {
		return nil, err
	}

	tok, err := jwtoken.Parse(
		tokenBytes,
		jwtoken.WithKey(jwa.RS256, key),
		jwtoken.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: verifying token: %w", classifyParseError(tokenBytes, err), err)
	}

	exp := tok.Expiration()
	if exp.IsZero() {
		return nil, fmt.Errorf("%w: token missing or zero expiration", ErrTokenMalformed)
	}
	if time.Now().UTC().After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrTokenExpired)
	}

	claims := &Claims{}
	claims.IssuedAt = tok.IssuedAt().Unix()
	claims.ExpiresAt = exp.Unix()

	if v, ok := tok.Get("sub"); ok {
		claims.Sub, _ = v.(string)
	}
	// A token without a subject is never a valid ACCESS token — every
	// mint path stamps sub. Rejecting here keeps other token species
	// signed by the same keys (e.g. audience-marked assurance tokens)
	// from ever passing as an authenticated user in a deployment that
	// leaves audience checking unconfigured.
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: token missing sub claim", ErrTokenMalformed)
	}
	if v, ok := tok.Get("email"); ok {
		claims.Email, _ = v.(string)
	}
	if v, ok := tok.Get("email_verified"); ok {
		claims.EmailVerified, _ = v.(bool)
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
	if v, ok := tok.Get("project"); ok {
		claims.Project, _ = v.(string)
	}
	if v, ok := tok.Get("avatar_url"); ok {
		claims.AvatarURL, _ = v.(string)
	}
	if v, ok := tok.Get("sid"); ok {
		claims.SID, _ = v.(string)
	}
	if v, ok := tok.Get("purpose"); ok {
		claims.Purpose, _ = v.(string)
	}
	if v, ok := tok.Get("bnd"); ok {
		claims.Binding, _ = v.(string)
	}
	if v, ok := tok.Get("auth_time"); ok {
		claims.AuthTime = numericClaim(v)
	}
	if v, ok := tok.Get("is_minor"); ok {
		claims.IsMinor, _ = v.(bool)
	}
	if v, ok := tok.Get("anonymous"); ok {
		claims.Anonymous, _ = v.(bool)
	}
	if v, ok := tok.Get("kind"); ok {
		claims.Kind, _ = v.(string)
	}
	claims.Audience = tok.Audience()
	claims.Issuer = tok.Issuer()

	if expectedTenant != "" && claims.Tenant != expectedTenant {
		return nil, fmt.Errorf("tenant mismatch: token tenant=%q expected=%q", claims.Tenant, expectedTenant)
	}

	if expectedAudience != "" {
		if len(claims.Audience) == 0 {
			if requireAudience {
				return nil, fmt.Errorf("%w: audience missing: expected=%q", ErrTokenAudience, expectedAudience)
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
				return nil, fmt.Errorf("%w: audience mismatch: token aud=%v expected=%q", ErrTokenAudience, claims.Audience, expectedAudience)
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

// numericClaim reads a JSON number claim, which a JWT library may decode as
// float64, json.Number or an integer type; anything else reads as zero.
func numericClaim(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}

func stringSliceClaim(v any) []string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

func classifyParseError(tokenBytes []byte, err error) error {
	if errors.Is(err, jwtoken.ErrTokenExpired()) {
		return ErrTokenExpired
	}
	if errors.Is(err, jwtoken.ErrInvalidIssuedAt()) || errors.Is(err, jwtoken.ErrTokenNotYetValid()) {
		return ErrTokenMalformed
	}
	if _, parseErr := jwtoken.ParseInsecure(tokenBytes); parseErr != nil {
		return ErrTokenMalformed
	}
	return ErrTokenSignature
}

func verificationKey(tokenBytes []byte, kp KeyProvider, profile string) (jwk.Key, error) {
	typ, err := tokenType(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing token headers: %w", ErrTokenMalformed, err)
	}
	if (profile == DelegatedAccessTokenType && typ != DelegatedAccessTokenType) || (profile == "JWT" && typ != "" && typ != "JWT") {
		return nil, fmt.Errorf("%w: token profile mismatch", ErrTokenMalformed)
	}

	kid, err := extractKID(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing token headers: %w", ErrTokenMalformed, err)
	}
	if kid == "" {
		return nil, fmt.Errorf("%w: token missing kid header", ErrTokenMalformed)
	}

	pub, ok := kp.Get(kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown signing key kid=%s", ErrTokenSignature, kid)
	}

	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: converting public key: %w", ErrTokenSignature, err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("setting alg: %w", err)
	}

	return key, nil
}
