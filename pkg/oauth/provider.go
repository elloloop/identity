package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Identity is the canonical, verified user identity returned by an
// Exchanger after a successful code exchange. Implementations MUST
// only return an Identity for verified users — i.e. the caller can
// rely on Email/ProviderUserID being authoritative.
type Identity struct {
	// ProviderUserID is the stable per-provider user identifier.
	// For OIDC providers this is the "sub" claim. For GitHub this is
	// the numeric user id (rendered as a string).
	ProviderUserID string

	// Email is the user's primary email address. Always lowercased.
	Email string

	// EmailVerified is true if the provider asserts the email is
	// verified. Implementations MUST refuse to return an Identity if
	// the provider says the email is not verified.
	EmailVerified bool

	// Name is the user's display name. May be empty.
	Name string

	// AvatarURL is a URL to the user's profile picture. May be empty.
	AvatarURL string

	// Provider is the provider key — "google", "microsoft", "github".
	Provider string
}

// Exchanger swaps an OAuth authorization code for a verified user
// identity. Implementations are responsible for:
//
//  1. POSTing to the provider's token endpoint with client_id /
//     client_secret / code / redirect_uri.
//  2. Verifying the resulting ID token (OIDC providers) OR fetching
//     userinfo (non-OIDC providers like GitHub).
//  3. Returning a canonical Identity with EmailVerified guaranteed
//     true.
//
// Errors returned to callers are intentionally generic — they do not
// leak provider response bodies. Callers that need provider-specific
// debugging should inspect logs.
type Exchanger interface {
	Exchange(ctx context.Context, code, redirectURI string) (*Identity, error)
}

// Authorizer builds the provider authorization URL for the first half
// of the OAuth authorization-code flow.
type Authorizer interface {
	AuthorizationURL(ctx context.Context, redirectURI, state, codeChallenge string) (string, error)
}

// Common error sentinels. Callers (e.g. the service layer) can
// errors.Is against these to map to RPC error codes.
var (
	// ErrCodeExchangeFailed indicates the provider rejected our
	// token-endpoint POST or returned an unparseable response.
	ErrCodeExchangeFailed = errors.New("oauth: code exchange failed")

	// ErrIdentityVerification indicates the ID token signature, issuer,
	// audience, or expiry could not be validated.
	ErrIdentityVerification = errors.New("oauth: identity verification failed")

	// ErrEmailNotVerified indicates the provider returned an unverified
	// email; we refuse to log such users in.
	ErrEmailNotVerified = errors.New("oauth: provider reported email is not verified")

	// ErrStateValidation indicates the OAuth callback state could not be
	// validated against the server-minted state token.
	ErrStateValidation = errors.New("oauth: state validation failed")
)

// defaultHTTPClient returns an http.Client suitable for talking to
// provider token / JWKS / userinfo endpoints. Conservative timeouts
// ensure a flaky provider can't stall a request indefinitely.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
	}
}
