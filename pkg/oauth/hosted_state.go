package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	identityjwt "github.com/elloloop/identity/pkg/jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
)

// HostedStateClaims are the tamper-proof claims the hosted OAuth flow
// binds into the state token it carries through the provider redirect.
// It is a superset of the headless StateClaims with the app's
// return_to added: the provider sends only `state` + `code` back to the
// single callback URL, so everything else (the PKCE verifier, the
// provider name, and where to hand the user back) must round-trip
// inside this signed artifact.
//
// This is a SEPARATE artifact from the headless state token
// (state.go). The headless flow's IssueStateToken / VerifyStateToken
// shape is intentionally left untouched — the SPA still round-trips
// the verifier itself there — so the hosted return_to binding does not
// become a breaking change for native/mobile callers (#126 stop
// condition).
type HostedStateClaims struct {
	Provider     string
	RedirectURI  string
	ReturnTo     string
	State        string
	CodeVerifier string
	CSRFToken    string
	ProjectID    string
	IssuedAt     int64
	ExpiresAt    int64
}

// IssueHostedStateToken signs a hosted-flow state token. redirectURI is
// the identity-owned callback URL registered with the provider;
// returnTo is the validated app URL the callback redirects to.
func IssueHostedStateToken(
	ctx context.Context,
	signer identityjwt.Signer,
	provider, redirectURI, returnTo, state, codeVerifier, csrfToken, projectID string,
	expiry time.Duration,
	now time.Time,
) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	redirectURI = strings.TrimSpace(redirectURI)
	returnTo = strings.TrimSpace(returnTo)
	state = strings.TrimSpace(state)
	codeVerifier = strings.TrimSpace(codeVerifier)
	csrfToken = strings.TrimSpace(csrfToken)
	if provider == "" || redirectURI == "" || returnTo == "" || state == "" || codeVerifier == "" || csrfToken == "" || projectID == "" {
		return "", fmt.Errorf("%w: missing required hosted-state claim", ErrStateValidation)
	}
	if signer == nil {
		return "", fmt.Errorf("%w: missing signer", ErrStateValidation)
	}

	claims := map[string]any{
		"flow":          "hosted",
		"provider":      provider,
		"redirect_uri":  redirectURI,
		"return_to":     returnTo,
		"oauth_state":   state,
		"code_verifier": codeVerifier,
		"csrf_token":    csrfToken,
		"project_id":    projectID,
		"iat":           now.Unix(),
		"exp":           now.Add(expiry).Unix(),
	}

	signed, err := signer.SignClaims(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("%w: sign hosted state token: %w", ErrStateValidation, err)
	}
	return signed, nil
}

// VerifyHostedStateToken validates the signature and expiry of the
// hosted state token (which IS the OAuth `state` parameter the provider
// echoed back), then returns the recovered claims. The provider, return
// target, and PKCE verifier are recovered from the token — the callback
// has no other source for them. The token's signature is the CSRF
// binding: an attacker cannot forge a state the server will accept.
func VerifyHostedStateToken(
	token string,
	kp identityjwt.KeyProvider,
	now time.Time,
) (*HostedStateClaims, error) {
	if kp == nil {
		return nil, fmt.Errorf("%w: missing key provider", ErrStateValidation)
	}
	kid, err := extractStateTokenKID(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateValidation, err)
	}
	if kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrStateValidation)
	}

	pub, ok := kp.Get(kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid", ErrStateValidation)
	}
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: convert public key: %w", ErrStateValidation, err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("%w: set public kid: %w", ErrStateValidation, err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("%w: set public alg: %w", ErrStateValidation, err)
	}

	tok, err := jwtoken.Parse(
		[]byte(token),
		jwtoken.WithKey(jwa.RS256, key),
		jwtoken.WithValidate(false),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: verify hosted state token: %w", ErrStateValidation, err)
	}

	if getStringClaim(tok, "flow") != "hosted" {
		return nil, fmt.Errorf("%w: not a hosted state token", ErrStateValidation)
	}

	claims := &HostedStateClaims{
		Provider:     getStringClaim(tok, "provider"),
		RedirectURI:  getStringClaim(tok, "redirect_uri"),
		ReturnTo:     getStringClaim(tok, "return_to"),
		State:        getStringClaim(tok, "oauth_state"),
		CodeVerifier: getStringClaim(tok, "code_verifier"),
		CSRFToken:    getStringClaim(tok, "csrf_token"),
		ProjectID:    getStringClaim(tok, "project_id"),
		IssuedAt:     tok.IssuedAt().Unix(),
		ExpiresAt:    tok.Expiration().Unix(),
	}
	if claims.Provider == "" || claims.RedirectURI == "" || claims.ReturnTo == "" ||
		claims.State == "" || claims.CodeVerifier == "" || claims.CSRFToken == "" {
		return nil, fmt.Errorf("%w: hosted state token missing required claims", ErrStateValidation)
	}
	if exp := tok.Expiration(); exp.IsZero() || now.After(exp) {
		return nil, fmt.Errorf("%w: hosted state token expired", ErrStateValidation)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: hosted state token iat in the future", ErrStateValidation)
	}
	return claims, nil
}
