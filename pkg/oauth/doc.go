// Package oauth implements provider-side OAuth code-exchange flows for
// authenticating end users into the identity service.
//
// Identity does OAuth FOR LOGIN ONLY: it accepts an authorization code
// from the frontend, swaps it with the provider for an ID token (or
// userinfo response), verifies the user's identity, and then mints OUR
// own JWT. Provider access/refresh tokens are NEVER stored — that's a
// separate "connections" service concern.
//
// The Exchanger interface decouples the auth flow from any specific
// provider; a Registry holds the per-provider implementations the
// service layer dispatches to via the "provider" string in the RPC.
//
// Currently supported providers:
//
//   - "google":    OIDC. ID token verified via JWKS (RS256).
//   - "microsoft": OIDC via Azure AD common endpoint. ID token verified
//     via JWKS; per-tenant issuer accepted.
//   - "github":    NOT OIDC. We exchange the code, then call /user and
//     /user/emails to discover the canonical (verified, primary) email.
package oauth
