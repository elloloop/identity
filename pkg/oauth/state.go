package oauth

import (
	"context"
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
	ctx context.Context,
	signer identityjwt.Signer,
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
	if signer == nil {
		return "", fmt.Errorf("%w: missing signer", ErrStateValidation)
	}

	claims := map[string]any{
		"provider":      provider,
		"redirect_uri":  redirectURI,
		"oauth_state":   state,
		"code_verifier": codeVerifier,
		"iat":           now.Unix(),
		"exp":           now.Add(expiry).Unix(),
	}

	signed, err := signer.SignClaims(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("%w: sign state token: %w", ErrStateValidation, err)
	}
	return signed, nil
}

func VerifyStateToken(
	token string,
	kp identityjwt.KeyProvider,
	expectedProvider, expectedRedirectURI, returnedState, explicitCodeVerifier string,
	now time.Time,
) (*StateClaims, error) {
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
