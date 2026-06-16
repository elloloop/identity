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

type appleNameContextKey struct{}

// WithAppleName carries the request-scoped display name that Apple
// delivers only once, in the form_post `user` field of the first
// authorization callback. The Apple exchanger reads it during Exchange
// so first-login name capture works (Apple never puts the name in the
// id_token). For every other provider this value is unset and ignored.
func WithAppleName(ctx context.Context, name string) context.Context {
	if strings.TrimSpace(name) == "" {
		return ctx
	}
	return context.WithValue(ctx, appleNameContextKey{}, strings.TrimSpace(name))
}

// AppleNameFromContext returns the Apple display name previously stored
// with WithAppleName, or "" when unset. Exported so callers (and tests)
// outside this package can observe what WithAppleName carried.
func AppleNameFromContext(ctx context.Context) string {
	return appleNameFromContext(ctx)
}

func appleNameFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	name, _ := ctx.Value(appleNameContextKey{}).(string)
	return strings.TrimSpace(name)
}
