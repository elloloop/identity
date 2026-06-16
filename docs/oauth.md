# OAuth login

identity supports OAuth/OIDC sign-in with Google, Microsoft, GitHub,
Sign in with Apple, and any standards-compliant OIDC provider added
purely via config. It does the authorization-code exchange itself — the frontend is never
trusted to assert the user's identity. There are two flows; a deployer
can use either or both.

- **Hosted flow** (Firebase-style): identity owns the provider callback.
  The browser starts sign-in at identity and identity hands the result
  back to the app via a one-time code. Best DX for web SPAs.
- **Headless flow**: the frontend owns the provider callback and posts
  the code back to identity over RPC. Needed for native/mobile apps
  (custom URL schemes) and callers who want full control.

Both run against the same provider exchangers and token-minting code.

## Enabling providers

A provider is enabled only when **both** its client id and secret are
set. Leave a provider's credentials unset to disable it.

| Provider  | Client ID env                        | Client secret env                        |
|-----------|--------------------------------------|------------------------------------------|
| Google    | `GATEWAY_OAUTH_GOOGLE_CLIENT_ID`     | `GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET`     |
| Microsoft | `GATEWAY_OAUTH_MICROSOFT_CLIENT_ID`  | `GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET`  |
| GitHub    | `GATEWAY_OAUTH_GITHUB_CLIENT_ID`     | `GATEWAY_OAUTH_GITHUB_CLIENT_SECRET`     |

Microsoft also accepts `GATEWAY_MICROSOFT_TENANT_ID` (optional). At
startup identity logs the enabled providers (`oauth_providers_enabled`)
or warns when none are configured.

### Sign in with Apple

Apple does not issue a static client secret; identity mints a
short-lived ES256-signed `client_secret` JWT per exchange. Provide all
four values (the provider is enabled only when all are set):

| Env                          | Meaning                                          |
|------------------------------|--------------------------------------------------|
| `GATEWAY_APPLE_CLIENT_ID`    | Services ID (the OAuth `client_id` / token `aud`)|
| `GATEWAY_APPLE_TEAM_ID`      | Apple Developer team identifier                  |
| `GATEWAY_APPLE_KEY_ID`       | Identifier of the registered private key         |
| `GATEWAY_APPLE_PRIVATE_KEY`  | PEM-encoded PKCS#8 EC private key (the `.p8`)     |

App Store Guideline 4.8 requires Sign in with Apple whenever another
third-party social login is offered in an iOS app. Apple returns the
user's display name only **once**, in the first authorization callback
(`response_mode=form_post`); the hosted callback captures it and threads
it into the exchange so first-login name capture works. The `apple`
provider key flows through the same hosted and headless OAuth paths as
every other provider.

### Generic OIDC providers (config-only)

Any standards-compliant OIDC provider (Okta, Auth0, Slack, an enterprise
IdP) can be added without a code release. List the provider keys in
`GATEWAY_OIDC_PROVIDERS` (comma-separated) and, for each key `KEY`, set:

```
GATEWAY_OIDC_PROVIDERS=okta,acme
GATEWAY_OIDC_OKTA_ISSUER=https://acme.okta.com
GATEWAY_OIDC_OKTA_CLIENT_ID=...
GATEWAY_OIDC_OKTA_CLIENT_SECRET=...
GATEWAY_OIDC_OKTA_SCOPES=openid email profile   # optional, space/comma-separated
```

The exchanger resolves the authorization / token / JWKS / userinfo
endpoints from `<ISSUER>/.well-known/openid-configuration`, verifies the
id_token signature (RS256 or ES256) against the discovered JWKS, and
falls back to the userinfo endpoint for email/name. A provider is enabled
only when its issuer, client id, and client secret are all present.

## Hosted flow

### Configuration

The hosted flow is **off by default**. Enable it by allowlisting the app
URLs identity may redirect users back to:

```
GATEWAY_OAUTH_ALLOWED_RETURN_URLS=https://app.example.com/,https://admin.example.com/auth
```

- Comma-separated list of exact origins or URL prefixes.
- A `return_to` is accepted only if it equals an entry or begins with
  one (prefix match). Validation is **fail-closed**: anything else is
  rejected with `400`.
- **Empty disables the hosted flow** — `GET /oauth/start/*` and
  `GET /oauth/callback/*` return `404`, and only the headless RPCs work.

The active allowlist is logged at startup
(`oauth_hosted_flow_enabled` / `oauth_hosted_flow_disabled`).

### Single redirect URI per provider

identity owns one redirect URI per provider:

```
https://identity.example.com/oauth/callback/{provider}
```

This is the only URL you register with the provider. identity derives it
from the incoming request (honoring `X-Forwarded-Proto` /
`X-Forwarded-Host` from a trusted reverse proxy), so it must resolve to
the same public origin at both `/oauth/start` and `/oauth/callback`.

#### Google Cloud console setup

1. APIs & Services → Credentials → Create credentials → OAuth client ID.
2. Application type: **Web application**.
3. **Authorized redirect URIs**: add exactly one:
   `https://identity.example.com/oauth/callback/google`
   (Google requires an exact match — no trailing slash, no extra path.)
4. Copy the client ID and secret into
   `GATEWAY_OAUTH_GOOGLE_CLIENT_ID` / `GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET`.

Microsoft (Entra ID app registration) and GitHub (OAuth App) are the
same idea: register the single
`https://identity.example.com/oauth/callback/{provider}` redirect URI.

### The flow

```
Browser                 identity                       Provider
  |  GET /oauth/start/google?return_to=<app-url>          |
  |----------------------->|                              |
  |                        |  validate return_to          |
  |                        |  mint state + PKCE + signed  |
  |                        |  hosted state token          |
  |  302 -> provider authorize?...&state=<token>          |
  |<-----------------------|                              |
  |  (user authenticates with provider) ---------------->|
  |  302 -> /oauth/callback/google?state=<token>&code=    |
  |<----------------------------------------------------- |
  |  GET /oauth/callback/google?state=&code=             |
  |----------------------->|                              |
  |                        |  verify state token          |
  |                        |  exchange code (PKCE)        |
  |                        |  upsert user, mint one-time  |
  |                        |  code (60s, single-use)      |
  |  302 -> <return_to>?code=<otc>                        |
  |<-----------------------|                              |
  |  RedeemOAuthCode{code} (RPC) --------------------->   |
  |                        |  consume code, mint tokens   |
  |  {user, access_token, refresh_token, expires_in}     |
  |<-----------------------|                              |
```

1. **`GET /oauth/start/{provider}?return_to=<app-url>`** — validates
   `return_to` against the allowlist, mints state + PKCE, binds
   `return_to` into a signed hosted state token (tamper-proof), and
   302-redirects the browser to the provider.
2. **`GET /oauth/callback/{provider}`** — the single registered redirect
   URI. Recovers the state token, runs the code exchange + token mint,
   mints a single-use one-time code, and 302-redirects to
   `return_to?code=<otc>`. On any failure it returns a generic `400`
   (it cannot trust an unverified `return_to`) and logs server-side.
3. **`RedeemOAuthCode{code}`** (Connect RPC) — the SPA exchanges the
   one-time code for `{user, access_token, refresh_token, expires_in}`.

### The one-time code

- Opaque, single-use, ~60s TTL.
- Only its SHA-256 hash is stored, bound to the user id. **No token
  material is persisted** — the token pair is freshly minted on redeem.
- Redeeming consumes the code atomically (single winner across
  replicas). A replay, an expired code, or an unknown code returns
  `Unauthenticated`.
- Chosen over URL-fragment tokens (leak to history / `Referer`) and
  httpOnly cookies (awkward cross-origin and unusable for native).

## Headless flow

For native/mobile apps, or web apps that want to own the provider
callback page. The state token round-trips the PKCE verifier through the
caller.

1. **`BeginOAuthLogin{provider, redirect_uri}`** — returns
   `{authorization_url, state, state_token, code_verifier, expires_in}`.
   The frontend redirects the user to `authorization_url` (which uses
   the frontend's own `redirect_uri`).
2. The provider redirects back to the frontend's callback page with
   `?code=&state=`.
3. **`OAuthLogin{code, provider, redirect_uri, state, state_token}`** —
   identity verifies the state token, exchanges the code, and returns
   `{user, access_token, refresh_token, expires_in}`.

The headless flow has no `return_to` allowlist: the frontend supplies
and owns its own `redirect_uri`, which it must register with the
provider itself.

## Notes

- Provider access/refresh tokens are discarded after the exchange — only
  identity-issued tokens are returned.
- A returning user is matched by `(provider, provider_user_id)` first, so
  a provider-side email change keeps them on the same local account.
- See `docs/IDENTITY.md` decision log §10 for the rationale behind the
  hosted-flow contract, the one-time-code handover, and the `return_to`
  allowlist.
