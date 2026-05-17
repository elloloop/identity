package middleware

import (
	"net/http"
	"strings"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// AuthExemptPaths lists URL paths that do not require a valid JWT.
// Connect-Go uses the proto service/method as the URL path.
var AuthExemptPaths = map[string]bool{
	"/identity.IdentityService/BeginOAuthLogin":      true,
	"/identity.IdentityService/OAuthLogin":           true,
	"/identity.IdentityService/PasswordLogin":        true,
	"/identity.IdentityService/PasswordSignup":       true,
	"/identity.IdentityService/RefreshToken":         true,
	"/identity.IdentityService/Logout":               true,
	"/identity.IdentityService/GetCurrentUser":       true,
	"/identity.IdentityService/BeginPasskeyLogin":    true,
	"/identity.IdentityService/CompletePasskeyLogin": true,
	"/identity.IdentityService/InitiateQrLogin":      true,
	"/identity.IdentityService/PollQrLogin":          true,
	"/identity.IdentityService/AcceptInvitation":     true,
	"/identity.IdentityService/RequestAdminHelp":     true,
	"/identity.IdentityService/VerifyTotp":           true,
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

			// Skip auth for exempt paths.
			if AuthExemptPaths[path] {
				// Still try to parse auth if present (for GetCurrentUser).
				if token := extractBearerToken(r); token != "" {
					if claims, err := jwtpkg.VerifyAccessToken(token, kp, expectedTenant, expectedAudience, requireAudience); err == nil {
						r.Header.Set("X-Authenticated-User-Id", claims.Sub)
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

			r.Header.Set("X-Authenticated-User-Id", claims.Sub)
			next.ServeHTTP(w, r)
		})
	}
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
