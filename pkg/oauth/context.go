package oauth

import (
	"context"
	"strings"
)

type codeVerifierContextKey struct{}

// WithCodeVerifier carries the request-scoped PKCE verifier to the
// provider token exchange.
func WithCodeVerifier(ctx context.Context, codeVerifier string) context.Context {
	if strings.TrimSpace(codeVerifier) == "" {
		return ctx
	}
	return context.WithValue(ctx, codeVerifierContextKey{}, codeVerifier)
}

func codeVerifierFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	codeVerifier, _ := ctx.Value(codeVerifierContextKey{}).(string)
	return strings.TrimSpace(codeVerifier)
}
