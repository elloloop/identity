package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// AuthExemptPaths lists URL paths that do not require a valid JWT.
// Connect-Go uses the proto service/method as the URL path.
var AuthExemptPaths = map[string]bool{
	// These verify the durable machine credential themselves; human and agent
	// JWTs are never substitutes for that proof.
	"/identity.v1.IdentityService/ExchangeAgentMachineCredential": true,
	"/identity.v1.IdentityService/CreateAgentMachineChallenge":    true,
	"/identity.v1.IdentityService/RegisterAgentMachineAgentKey":   true,
	// Dedicated configured resource authentication, verified in the handler.
	"/identity.v1.IdentityService/IntrospectAgentMachine": true,
	"/identity.v1.IdentityService/ListAgentMachineAgents": true,
	"/identity.v1.IdentityService/BeginOAuthLogin":        true,
	"/identity.v1.IdentityService/OAuthLogin":             true,
	// NativeOAuthLogin verifies a native mobile-SDK ID token; the caller is
	// anonymous until the token is verified, so no Bearer is required.
	"/identity.v1.IdentityService/NativeOAuthLogin": true,
	// RedeemOAuthCode trades the hosted-flow one-time code for tokens;
	// the caller is anonymous until the code is redeemed, so it cannot
	// carry a JWT.
	"/identity.v1.IdentityService/RedeemOAuthCode": true,
	"/identity.v1.IdentityService/PasswordLogin":   true,
	"/identity.v1.IdentityService/PasswordSignup":  true,
	// UsernameSignup creates an account; the caller has none yet.
	"/identity.v1.IdentityService/UsernameSignup": true,
	// Required-DOB completion: the caller holds the short-lived completion
	// ticket from the dob_required error detail, not a session JWT — no
	// session exists until the DOB is submitted.
	"/identity.v1.IdentityService/SubmitDateOfBirth":              true,
	"/identity.v1.IdentityService/CompleteRequiredPasswordChange": true,
	// Passwordless email login: the caller is anonymous, proving control
	// of an inbox via an OTP code or a magic-link token rather than a JWT.
	"/identity.v1.IdentityService/RequestEmailLoginCode": true,
	"/identity.v1.IdentityService/VerifyEmailLoginCode":  true,
	"/identity.v1.IdentityService/RequestMagicLink":      true,
	"/identity.v1.IdentityService/RedeemMagicLink":       true,
	// Client assurance: a client proves what it IS (genuine app on genuine
	// hardware, or a human-passed web client) before anyone signs in, so
	// none of these can carry a user JWT.
	"/identity.v1.IdentityService/CreateAssuranceChallenge": true,
	"/identity.v1.IdentityService/IssueAssuranceToken":      true,
	"/identity.v1.IdentityService/RefreshAssuranceToken":    true,
	// Anonymous sign-in: the caller has no identity yet — creating one IS
	// the request. UpgradeAnonymousAccount is deliberately NOT here: it
	// promotes the CALLING account, which the access token identifies.
	"/identity.v1.IdentityService/SignInAnonymously":    true,
	"/identity.v1.IdentityService/RefreshToken":         true,
	"/identity.v1.IdentityService/Logout":               true,
	"/identity.v1.IdentityService/GetCurrentUser":       true,
	"/identity.v1.IdentityService/BeginPasskeyLogin":    true,
	"/identity.v1.IdentityService/CompletePasskeyLogin": true,
	// Passkey registration is exempt so a managed child's device can run the
	// ceremony with NO session, presenting its enrolment ticket in the request
	// body. The pair is NOT unauthenticated: the Connect handler requires the
	// session-injected identity header (set here when a session token is
	// present) or a verified `passkey_enrolment` ticket, and refuses both
	// absent. A purpose JWT presented as a Bearer token still never
	// authenticates — the purpose check below rejects it.
	"/identity.v1.IdentityService/BeginPasskeyRegistration":    true,
	"/identity.v1.IdentityService/CompletePasskeyRegistration": true,
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
	"/identity.v1.IdentityService/AdminCreateProject":              true,
	"/identity.v1.IdentityService/AdminCreateProjectCredential":    true,
	"/identity.v1.IdentityService/AdminRevokeProjectCredential":    true,
	"/identity.v1.IdentityService/AdminAddProjectAuthDomain":       true,
	"/identity.v1.IdentityService/AddProjectAuthDomain":            true,
	"/identity.v1.IdentityService/VerifyProjectAuthDomain":         true,
	"/identity.v1.IdentityService/ListProjectAuthDomains":          true,
	"/identity.v1.IdentityService/SetPrimaryAuthDomain":            true,
	"/identity.v1.IdentityService/AdminCreateTenant":               true,
	"/identity.v1.IdentityService/AdminAddTenantAdmin":             true,
	"/identity.v1.IdentityService/UpsertLoginPolicy":               true,
	"/identity.v1.IdentityService/GetLoginPolicy":                  true,
	"/identity.v1.IdentityService/DeleteLoginPolicy":               true,
	"/identity.v1.IdentityService/UpsertProjectConfig":             true,
	"/identity.v1.IdentityService/GetProjectConfig":                true,
	"/identity.v1.IdentityService/AdminSetProjectOAuthProvider":    true,
	"/identity.v1.IdentityService/AdminDeleteProjectOAuthProvider": true,
	"/identity.v1.IdentityService/AdminListProjectOAuthProviders":  true,
	"/identity.v1.IdentityService/AdminSetProjectAssurance":        true,
	"/identity.v1.IdentityService/AdminGetProjectAssurance":        true,
	// CreateFirstPlatformAdmin is the trust-on-first-use bootstrap: a fresh
	// deployer carries NO JWT (no operator user exists yet), so it must be
	// JWT-exempt or the first operator could never be created. It is not
	// unconditionally unauthenticated, though: when GATEWAY_ADMIN_API_SECRET is
	// set the handler requires the X-Admin-Secret header (like the other admin
	// RPCs), and GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP closes it entirely. It
	// also self-secures by closing permanently once any platform admin exists.
	"/identity.v1.IdentityService/CreateFirstPlatformAdmin": true,
	// LookupUsers is called by a service, not a user: it is authenticated by
	// a directory_reader project credential in X-Directory-Key, which the
	// directory service verifies (hash compare, kind, revocation) and which
	// scopes the lookup to that credential's project.
	"/identity.v1.IdentityService/LookupUsers": true,
	"/.well-known/jwks.json":                   true,
	"/health":                                  true,
	"/healthz":                                 true,
	// The SAML IdP metadata is a public document an SP fetches to import the
	// IdP's signing certificate; no caller of it holds a JWT.
	SAMLMetadataPath: true,
}

// SAMLMetadataPath is the well-known path the SAML IdP serves its
// EntityDescriptor XML on. SPs are configured with this URL to import the
// IdP's signing certificate and SSO/SLO endpoints.
const SAMLMetadataPath = "/saml/metadata"

// scimMountPath is the root of the inbound SCIM 2.0 server, and
// SCIMPathPrefix its subtree. A SCIM client authenticates with the
// deployment's SCIM bearer token, which the SCIM handler verifies itself. That
// token is not a JWT, so enforcing JWTs here would refuse every SCIM request
// before the handler could check it. The bare root is exempt too, so a client
// configured with the base URL gets the mux's redirect into the subtree rather
// than a JWT refusal.
const (
	scimMountPath  = "/scim/v2"
	SCIMPathPrefix = scimMountPath + "/"
)

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
// OAuth, auth UI or SCIM prefix.
func isAuthExempt(path string) bool {
	return path == "/.well-known/oauth-authorization-server" || AuthExemptPaths[path] ||
		strings.HasPrefix(path, hostedOAuthPrefix) ||
		strings.HasPrefix(path, authUIPrefix) ||
		path == scimMountPath ||
		strings.HasPrefix(path, SCIMPathPrefix)
}

// TenantLookup reads the status of a tenant of a project; "" when there is
// none. service.TenantStore satisfies it.
type TenantLookup interface {
	GetTenantStatus(ctx context.Context, projectID, tenantID string) (string, error)
}

// TokenTenants is the rule a verified token's "tenant" claim must meet.
//
// A token carries Default unless RefreshToken selected a tenant for it, in
// which case it carries that tenant's id. Such a token is accepted only while
// the tenant is a claimed tenant of the token's project, so suspending a
// tenant ends its tokens at their next request; ending a membership ends
// them at their next refresh, within one access-token lifetime.
type TokenTenants struct {
	// Default is the deployment's storage tenant (DefaultTenantID). Empty
	// disables the check: every tenant claim is accepted.
	Default string
	// Selectable resolves a selected tenant. nil accepts only Default.
	Selectable TenantLookup
	// Logger records a failed read of a selected tenant, which answers the
	// request 503; nil records nothing. The token itself is never logged.
	Logger *zap.Logger
}

var (
	// errTokenTenantRejected is a token whose tenant claim the rule refuses.
	errTokenTenantRejected = errors.New("token tenant not accepted")
	// errTokenTenantLookup is a failed read of a selected tenant: the token
	// may be good, so the request is answered as unavailable, not refused.
	errTokenTenantLookup = errors.New("token tenant lookup failed")
)

// accept applies the rule to verified claims.
func (t TokenTenants) accept(ctx context.Context, claims *jwtpkg.Claims) error {
	if t.Default == "" || claims.Tenant == t.Default {
		return nil
	}
	if t.Selectable == nil || claims.Tenant == "" || claims.Project == "" {
		return errTokenTenantRejected
	}
	status, err := t.Selectable.GetTenantStatus(ctx, claims.Project, claims.Tenant)
	if err != nil {
		if t.Logger != nil {
			t.Logger.Warn("token_tenant_lookup_failed",
				zap.String("project_id", claims.Project),
				zap.String("tenant_id", claims.Tenant),
				zap.Error(err),
			)
		}
		return fmt.Errorf("%w: %w", errTokenTenantLookup, err)
	}
	if status != service.TenantStatusClaimed {
		return errTokenTenantRejected
	}
	return nil
}

// verifyRequestToken verifies an access token and applies the tenant rule.
func verifyRequestToken(ctx context.Context, token string, kp jwtpkg.KeyProvider, tenants TokenTenants, expectedAudience string, requireAudience bool) (*jwtpkg.Claims, error) {
	claims, err := jwtpkg.VerifyAccessToken(token, kp, "", expectedAudience, requireAudience)
	if err != nil {
		return nil, err
	}
	if err := tenants.accept(ctx, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// writeTokenRefusal answers a request whose token verifyRequestToken refused:
// 503 when a selected tenant could not be read, 401 otherwise.
func writeTokenRefusal(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	if errors.Is(err, errTokenTenantLookup) {
		http.Error(w, `{"code":"unavailable","message":"Token tenant lookup failed"}`, http.StatusServiceUnavailable)
		return
	}
	http.Error(w, `{"code":"unauthenticated","message":"Invalid or expired access token"}`, http.StatusUnauthorized)
}

// AuthMiddleware verifies JWT Bearer tokens on non-exempt paths and injects the
// authenticated user ID into the X-Authenticated-User-Id request header so
// downstream Connect handlers can read it.
//
// tenants is the rule every verified token's "tenant" claim must meet; the
// zero value disables the check.
//
// expectedAudience and requireAudience are passed through to
// jwtpkg.VerifyAccessToken — see that function for the audience policy.
//
// For auth-exempt paths the middleware still attempts to parse and verify a
// token when one is present (e.g. GetCurrentUser may optionally read the
// caller identity) but never rejects the request.
func AuthMiddleware(kp jwtpkg.KeyProvider, tenants TokenTenants, expectedAudience string, requireAudience bool) func(http.Handler) http.Handler {
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
					if claims, err := verifyRequestToken(r.Context(), token, kp, tenants, expectedAudience, requireAudience); err == nil {
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

			claims, err := verifyRequestToken(r.Context(), token, kp, tenants, expectedAudience, requireAudience)
			if err != nil {
				writeTokenRefusal(w, err)
				return
			}

			// A purpose token (a dob_completion or passkey_enrolment ticket)
			// never authenticates a request; jwtpkg.VerifyAccessToken refuses
			// one, so it lands in the branch above and is indistinguishable
			// from a bad token. The rule lives in the verifier so it holds on
			// every transport, not only this middleware.

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

// AuthenticatedAuthTimeHeader carries the verified `auth_time` claim (epoch
// seconds of the sign-in that opened the session) to the handlers that need
// a recent sign-in. Absent when the token has none.
const AuthenticatedAuthTimeHeader = "X-Authenticated-Auth-Time"

const AuthenticatedSessionIDHeader = "X-Authenticated-Session-Id"

// setAuthHeaders writes the verified identity headers from claims. Only
// called after VerifyAccessToken succeeds, so the values are trusted.
func setAuthHeaders(r *http.Request, claims *jwtpkg.Claims) {
	r.Header.Set(AuthenticatedUserIDHeader, claims.Sub)
	if claims.SID != "" {
		r.Header.Set(AuthenticatedSessionIDHeader, claims.SID)
	}
	if claims.Tenant != "" {
		r.Header.Set(AuthenticatedTenantHeader, claims.Tenant)
	}
	if claims.Project != "" {
		r.Header.Set(AuthenticatedProjectHeader, claims.Project)
	}
	if claims.AuthTime > 0 {
		r.Header.Set(AuthenticatedAuthTimeHeader, strconv.FormatInt(claims.AuthTime, 10))
	}
}

// clearAuthHeaders removes any inbound copies of the identity headers so
// an external client cannot inject them to impersonate a user, tenant, or
// project.
func clearAuthHeaders(r *http.Request) {
	r.Header.Del(AuthenticatedUserIDHeader)
	r.Header.Del(AuthenticatedTenantHeader)
	r.Header.Del(AuthenticatedProjectHeader)
	r.Header.Del(AuthenticatedAuthTimeHeader)
	r.Header.Del(AuthenticatedSessionIDHeader)
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
