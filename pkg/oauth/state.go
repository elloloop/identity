package oauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	identityjwt "github.com/elloloop/identity/pkg/jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
)

type StateClaims struct {
	Provider     string
	RedirectURI  string
	State        string
	CodeVerifier string
	IssuedAt     int64
	ExpiresAt    int64
}

func IssueStateToken(
	kr *identityjwt.KeyRing,
	provider, redirectURI, state, codeVerifier string,
	expiry time.Duration,
	now time.Time,
) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	redirectURI = strings.TrimSpace(redirectURI)
	state = strings.TrimSpace(state)
	codeVerifier = strings.TrimSpace(codeVerifier)
	if provider == "" || redirectURI == "" || state == "" || codeVerifier == "" {
		return "", fmt.Errorf("%w: missing required state-token claim", ErrStateValidation)
	}
	if kr == nil {
		return "", fmt.Errorf("%w: missing signing key ring", ErrStateValidation)
	}

	tok, err := jwtoken.NewBuilder().
		Claim("provider", provider).
		Claim("redirect_uri", redirectURI).
		Claim("oauth_state", state).
		Claim("code_verifier", codeVerifier).
		IssuedAt(now).
		Expiration(now.Add(expiry)).
		Build()
	if err != nil {
		return "", fmt.Errorf("%w: build state token: %w", ErrStateValidation, err)
	}

	active := kr.Active()
	key, err := jwk.FromRaw(active.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("%w: convert signing key: %w", ErrStateValidation, err)
	}
	if err := key.Set(jwk.KeyIDKey, active.KID); err != nil {
		return "", fmt.Errorf("%w: set signing kid: %w", ErrStateValidation, err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return "", fmt.Errorf("%w: set signing alg: %w", ErrStateValidation, err)
	}

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, key))
	if err != nil {
		return "", fmt.Errorf("%w: sign state token: %w", ErrStateValidation, err)
	}
	return string(signed), nil
}

func VerifyStateToken(
	token string,
	kr *identityjwt.KeyRing,
	expectedProvider, expectedRedirectURI, returnedState, explicitCodeVerifier string,
	now time.Time,
) (*StateClaims, error) {
	if kr == nil {
		return nil, fmt.Errorf("%w: missing verification key ring", ErrStateValidation)
	}
	kid, err := extractStateTokenKID(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateValidation, err)
	}
	if kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrStateValidation)
	}

	sk, ok := kr.Get(kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid", ErrStateValidation)
	}
	key, err := jwk.FromRaw(sk.PublicKey)
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
		return nil, fmt.Errorf("%w: verify state token: %w", ErrStateValidation, err)
	}

	claims := &StateClaims{
		Provider:     getStringClaim(tok, "provider"),
		RedirectURI:  getStringClaim(tok, "redirect_uri"),
		State:        getStringClaim(tok, "oauth_state"),
		CodeVerifier: getStringClaim(tok, "code_verifier"),
		IssuedAt:     tok.IssuedAt().Unix(),
		ExpiresAt:    tok.Expiration().Unix(),
	}
	if claims.Provider == "" || claims.RedirectURI == "" || claims.State == "" || claims.CodeVerifier == "" {
		return nil, fmt.Errorf("%w: state token missing required claims", ErrStateValidation)
	}
	if exp := tok.Expiration(); exp.IsZero() || now.After(exp) {
		return nil, fmt.Errorf("%w: state token expired", ErrStateValidation)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: state token iat in the future", ErrStateValidation)
	}

	if want := strings.ToLower(strings.TrimSpace(expectedProvider)); want != "" && claims.Provider != want {
		return nil, fmt.Errorf("%w: provider mismatch", ErrStateValidation)
	}
	if want := strings.TrimSpace(expectedRedirectURI); want != "" && claims.RedirectURI != want {
		return nil, fmt.Errorf("%w: redirect uri mismatch", ErrStateValidation)
	}
	if want := strings.TrimSpace(returnedState); want == "" || claims.State != want {
		return nil, fmt.Errorf("%w: callback state mismatch", ErrStateValidation)
	}
	if verifier := strings.TrimSpace(explicitCodeVerifier); verifier != "" && claims.CodeVerifier != verifier {
		return nil, fmt.Errorf("%w: code verifier mismatch", ErrStateValidation)
	}
	return claims, nil
}

func extractStateTokenKID(token string) (string, error) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return "", err
	}
	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return "", errors.New("no signatures in token")
	}
	return signatures[0].ProtectedHeaders().KeyID(), nil
}

func getStringClaim(tok jwtoken.Token, name string) string {
	value, ok := tok.Get(name)
	if !ok {
		return ""
	}
	str, _ := value.(string)
	return strings.TrimSpace(str)
}
