package middleware

import (
	"net/http"
	"strings"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// AuthExemptPaths lists URL paths that do not require a valid JWT.
// Connect-Go uses the proto service/method as the URL path.
var AuthExemptPaths = map[string]bool{
	"/identity.v1.IdentityService/BeginOAuthLogin": true,
	"/identity.v1.IdentityService/OAuthLogin":      true,
	// RedeemOAuthCode trades the hosted-flow one-time code for tokens;
	// the caller is anonymous until the code is redeemed, so it cannot
	// carry a JWT.
	"/identity.v1.IdentityService/RedeemOAuthCode": true,
	"/identity.v1.IdentityService/PasswordLogin":   true,
	"/identity.v1.IdentityService/PasswordSignup":  true,
	// Passwordless email login: the caller is anonymous, proving control
	// of an inbox via an OTP code or a magic-link token rather than a JWT.
	"/identity.v1.IdentityService/RequestEmailLoginCode": true,
	"/identity.v1.IdentityService/VerifyEmailLoginCode":  true,
	"/identity.v1.IdentityService/RequestMagicLink":      true,
	"/identity.v1.IdentityService/RedeemMagicLink":       true,
	"/identity.v1.IdentityService/RefreshToken":          true,
	"/identity.v1.IdentityService/Logout":                true,
	"/identity.v1.IdentityService/GetCurrentUser":        true,
	"/identity.v1.IdentityService/BeginPasskeyLogin":     true,
	"/identity.v1.IdentityService/CompletePasskeyLogin":  true,
	// Passkey-first signup: the caller is anonymous — they are creating a
	// brand-new account from a passkey and have no JWT yet.
	"/identity.v1.IdentityService/BeginPasskeySignup":    true,
	"/identity.v1.IdentityService/CompletePasskeySignup": true,
	"/identity.v1.IdentityService/InitiateQrLogin":       true,
	"/identity.v1.IdentityService/PollQrLogin":           true,
	"/identity.v1.IdentityService/AcceptInvitation":      true,
	"/identity.v1.IdentityService/RequestAdminHelp":      true,
	"/identity.v1.IdentityService/VerifyTotp":            true,
	// Email + reset flows are unauthenticated by design — the user is
	// either anonymous (forgot password) or proving control of an
	// inbox via a token rather than via a JWT.
	"/identity.v1.IdentityService/RequestPasswordReset": true,
	"/identity.v1.IdentityService/ConfirmPasswordReset": true,
	"/identity.v1.IdentityService/VerifyEmail":          true,
	// ConfirmEmailChange is consumed by clicking a link in the new
	// email's inbox — the user may not be currently signed in.
	"/identity.v1.IdentityService/ConfirmEmailChange": true,
	// Control-plane admin RPCs are PLATFORM-operator operations, NOT
	// user-authenticated: there is no user JWT for a platform operator. They
	// are exempt from JWT enforcement, but they are NOT unauthenticated — the
	// admin handler authenticates each call by constant-time-comparing the
	// X-Admin-Secret header against GATEWAY_ADMIN_API_SECRET, and the whole
	// surface is disabled (CodeUnimplemented) when that secret is unset. So
	// the secret check, not the JWT, is their auth.
	"/identity.v1.IdentityService/AdminCreateProject":           true,
	"/identity.v1.IdentityService/AdminCreateProjectCredential": true,
	"/identity.v1.IdentityService/AdminAddProjectAuthDomain":    true,
	"/identity.v1.IdentityService/AddProjectAuthDomain":         true,
	"/identity.v1.IdentityService/VerifyProjectAuthDomain":      true,
	"/identity.v1.IdentityService/ListProjectAuthDomains":       true,
	"/identity.v1.IdentityService/SetPrimaryAuthDomain":         true,
	"/identity.v1.IdentityService/AdminCreateTenant":            true,
	"/identity.v1.IdentityService/AdminAddTenantAdmin":          true,
	"/.well-known/jwks.json":                                    true,
	"/health":                                                   true,
	"/healthz":                                                  true,
}

// hostedOAuthPrefix is the path prefix for the browser-facing hosted
// OAuth routes (GET /oauth/start/{provider}, GET/POST /oauth/callback/
// {provider}). These are unauthenticated by design — the user is mid
// sign-in and has no JWT yet — so they are exempt as a prefix rather
// than per-exact-path (the {provider} segment varies).
const hostedOAuthPrefix = "/oauth/"

// authUIPrefix is the path prefix for the embedded UI static files.
const authUIPrefix = "/auth/"

// isAuthExempt reports whether path bypasses JWT enforcement: either an
// exact-match entry in AuthExemptPaths or any path under the hosted
// OAuth prefix or the auth UI prefix.
func isAuthExempt(path string) bool {
	return AuthExemptPaths[path] || strings.HasPrefix(path, hostedOAuthPrefix) || strings.HasPrefix(path, authUIPrefix)
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

// AuthenticatedProjectHeader carries the verified `project` claim from the
// auth middleware to the project-scope guard. The handler layer never
// reads it directly; it exists so the guard can cross-check the
// JWT-asserted project against the resolved project without re-verifying
// the token.
const AuthenticatedProjectHeader = "X-Authenticated-Project"

// setAuthHeaders writes the verified identity headers from claims. Only
// called after VerifyAccessToken succeeds, so the values are trusted.
func setAuthHeaders(r *http.Request, claims *jwtpkg.Claims) {
	r.Header.Set(AuthenticatedUserIDHeader, claims.Sub)
	if claims.Tenant != "" {
		r.Header.Set(AuthenticatedTenantHeader, claims.Tenant)
	}
	if claims.Project != "" {
		r.Header.Set(AuthenticatedProjectHeader, claims.Project)
	}
}

// clearAuthHeaders removes any inbound copies of the identity headers so
// an external client cannot inject them to impersonate a user, tenant, or
// project.
func clearAuthHeaders(r *http.Request) {
	r.Header.Del(AuthenticatedUserIDHeader)
	r.Header.Del(AuthenticatedTenantHeader)
	r.Header.Del(AuthenticatedProjectHeader)
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
