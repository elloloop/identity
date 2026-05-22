package middleware

import (
	"net/http"
	"strings"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// AuthExemptPaths lists URL paths that do not require a valid JWT.
// Connect-Go uses the proto service/method as the URL path.
var AuthExemptPaths = map[string]bool{
	"/identity.IdentityService/BeginOAuthLogin": true,
	"/identity.IdentityService/OAuthLogin":      true,
	// RedeemOAuthCode trades the hosted-flow one-time code for tokens;
	// the caller is anonymous until the code is redeemed, so it cannot
	// carry a JWT.
	"/identity.IdentityService/RedeemOAuthCode": true,
	"/identity.IdentityService/PasswordLogin":   true,
	"/identity.IdentityService/PasswordSignup":  true,
	// Passwordless email login: the caller is anonymous, proving control
	// of an inbox via an OTP code or a magic-link token rather than a JWT.
	"/identity.IdentityService/RequestEmailLoginCode": true,
	"/identity.IdentityService/VerifyEmailLoginCode":  true,
	"/identity.IdentityService/RequestMagicLink":      true,
	"/identity.IdentityService/RedeemMagicLink":       true,
	"/identity.IdentityService/RefreshToken":          true,
	"/identity.IdentityService/Logout":                true,
	"/identity.IdentityService/GetCurrentUser":        true,
	"/identity.IdentityService/BeginPasskeyLogin":     true,
	"/identity.IdentityService/CompletePasskeyLogin":  true,
	"/identity.IdentityService/InitiateQrLogin":       true,
	"/identity.IdentityService/PollQrLogin":           true,
	"/identity.IdentityService/AcceptInvitation":      true,
	"/identity.IdentityService/RequestAdminHelp":      true,
	"/identity.IdentityService/VerifyTotp":            true,
	// OrganizationSignup is the entry point for B2B multi-tenant
	// deployments (mode=multi). The caller is by definition not yet
	// a member of any tenant, so authentication cannot precede this
	// call. The handler itself enforces the mode guard (returns
	// Unimplemented in mode=single per docs/IDENTITY.md §3).
	"/identity.IdentityService/OrganizationSignup": true,
	// Email + reset flows are unauthenticated by design — the user is
	// either anonymous (forgot password) or proving control of an
	// inbox via a token rather than via a JWT.
	"/identity.IdentityService/RequestPasswordReset": true,
	"/identity.IdentityService/ConfirmPasswordReset": true,
	"/identity.IdentityService/VerifyEmail":          true,
	// ConfirmEmailChange is consumed by clicking a link in the new
	// email's inbox — the user may not be currently signed in.
	"/identity.IdentityService/ConfirmEmailChange": true,
	"/.well-known/jwks.json":                       true,
	"/health":                                      true,
	"/healthz":                                     true,
}

// hostedOAuthPrefix is the path prefix for the browser-facing hosted
// OAuth routes (GET /oauth/start/{provider}, GET /oauth/callback/
// {provider}). These are unauthenticated by design — the user is mid
// sign-in and has no JWT yet — so they are exempt as a prefix rather
// than per-exact-path (the {provider} segment varies).
const hostedOAuthPrefix = "/oauth/"

// isAuthExempt reports whether path bypasses JWT enforcement: either an
// exact-match entry in AuthExemptPaths or any path under the hosted
// OAuth prefix.
func isAuthExempt(path string) bool {
	return AuthExemptPaths[path] || strings.HasPrefix(path, hostedOAuthPrefix)
}

// AuthMiddleware verifies JWT Bearer tokens on non-exempt paths and injects the
// authenticated user ID into the X-Authenticated-User-Id request header so
// downstream Connect handlers can read it.
//
// expectedTenant, when non-empty, is enforced on every verified token: tokens
// whose "tenant" claim does not match are rejected. Pass an empty string to
// disable the cross-tenant check.
//
// expectedAudience and requireAudience are passed through to
// jwtpkg.VerifyAccessToken — see that function for the audience policy.
//
// For auth-exempt paths the middleware still attempts to parse and verify a
// token when one is present (e.g. GetCurrentUser may optionally read the
// caller identity) but never rejects the request.
func AuthMiddleware(kp jwtpkg.KeyProvider, expectedTenant, expectedAudience string, requireAudience bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Strip any client-supplied identity headers so a caller can
			// never spoof the values the middleware injects downstream.
			clearAuthHeaders(r)

			// Skip auth for exempt paths.
			if isAuthExempt(path) {
				// Still try to parse auth if present (for GetCurrentUser).
				if token := extractBearerToken(r); token != "" {
					if claims, err := jwtpkg.VerifyAccessToken(token, kp, expectedTenant, expectedAudience, requireAudience); err == nil {
						setAuthHeaders(r, claims)
					}
				}
				next.ServeHTTP(w, r)
				return
			}

			// Require auth for non-exempt paths.
			token := extractBearerToken(r)
			if token == "" {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"code":"unauthenticated","message":"Missing Authorization header"}`, http.StatusUnauthorized)
				return
			}

			claims, err := jwtpkg.VerifyAccessToken(token, kp, expectedTenant, expectedAudience, requireAudience)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"code":"unauthenticated","message":"Invalid or expired access token"}`, http.StatusUnauthorized)
				return
			}

			setAuthHeaders(r, claims)
			next.ServeHTTP(w, r)
		})
	}
}

// AuthenticatedUserIDHeader carries the verified `sub` claim from the
// auth middleware to the Connect handler layer.
const AuthenticatedUserIDHeader = "X-Authenticated-User-Id"

// AuthenticatedTenantHeader carries the verified `tenant` claim from
// the auth middleware to the tenant-resolution middleware in
// mode=multi. The handler layer never reads it directly; it exists so
// resolution can cross-check the JWT-asserted tenant against the
// host-derived tenant without re-verifying the token.
const AuthenticatedTenantHeader = "X-Authenticated-Tenant"

// setAuthHeaders writes the verified identity headers from claims. Only
// called after VerifyAccessToken succeeds, so the values are trusted.
func setAuthHeaders(r *http.Request, claims *jwtpkg.Claims) {
	r.Header.Set(AuthenticatedUserIDHeader, claims.Sub)
	if claims.Tenant != "" {
		r.Header.Set(AuthenticatedTenantHeader, claims.Tenant)
	}
}

// clearAuthHeaders removes any inbound copies of the identity headers so
// an external client cannot inject them to impersonate a user or tenant.
func clearAuthHeaders(r *http.Request) {
	r.Header.Del(AuthenticatedUserIDHeader)
	r.Header.Del(AuthenticatedTenantHeader)
}

// extractBearerToken returns the token portion of an "Authorization: Bearer <token>"
// header, or an empty string if no such header is present.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}
