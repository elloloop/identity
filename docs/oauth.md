# OAuth login

identity supports OAuth/OIDC sign-in with Google, Microsoft, GitHub, Apple,
and any standards-compliant OIDC provider added purely through config.
It does the authorization-code exchange itself — the frontend is never
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

A provider is enabled when its required credentials are set (client id and secret, or Apple's private key and IDs). Leave a provider's credentials unset to disable it.

| Provider  | Client ID env                        | Client secret env                        |
|-----------|--------------------------------------|------------------------------------------|
| Google    | `GATEWAY_OAUTH_GOOGLE_CLIENT_ID`     | `GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET`     |
| Microsoft | `GATEWAY_OAUTH_MICROSOFT_CLIENT_ID`  | `GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET`  |
| GitHub    | `GATEWAY_OAUTH_GITHUB_CLIENT_ID`     | `GATEWAY_OAUTH_GITHUB_CLIENT_SECRET`     |
| Apple     | `GATEWAY_OAUTH_APPLE_CLIENT_ID`      | `GATEWAY_OAUTH_APPLE_PRIVATE_KEY` (along with TEAM_ID and KEY_ID) |

GitHub issues no ID token, so identity reads the user's addresses from
`/user/emails` (the `user:email` scope, requested by default) and signs the
user in with the verified primary address, else the first verified one. The
profile's public email is never used: GitHub does not verify it. A GitHub
account with no verified address, or a token that cannot read
`/user/emails`, is refused with `Unauthenticated`.

Microsoft also accepts `GATEWAY_MICROSOFT_TENANT_ID` (optional). At
startup identity logs the enabled providers (`oauth_providers_enabled`)
or warns when none are configured.

### Generic OIDC provider (config-only)

Any standards-compliant OIDC provider (Okta, Auth0, Keycloak, a
self-hosted issuer) can be enabled without a code release. Set:

```
GATEWAY_OAUTH_OIDC_ENABLED=true
GATEWAY_OAUTH_OIDC_PROVIDER_KEY=okta            # registry key + reported provider name
GATEWAY_OAUTH_OIDC_ISSUER=https://acme.okta.com
GATEWAY_OAUTH_OIDC_CLIENT_ID=...
GATEWAY_OAUTH_OIDC_CLIENT_SECRET=...
GATEWAY_OAUTH_OIDC_SCOPES=openid email profile  # optional, space-separated ("openid" is always added)
```

The exchanger resolves the authorization / token / JWKS / userinfo
endpoints from `<ISSUER>/.well-known/openid-configuration` (override with
`GATEWAY_OAUTH_OIDC_DISCOVERY_URL`), verifies the id_token signature
against the discovered JWKS, checks the issuer / audience / expiry, and
falls back to the userinfo endpoint for email and name. The user is
rejected unless the provider asserts the email is verified.

The provider registers under `GATEWAY_OAUTH_OIDC_PROVIDER_KEY` and flows
through the same hosted and headless OAuth paths as every built-in
provider. The key may not be `google`, `microsoft`, `github`, or `apple`.

## Hosted flow

### Configuration

The hosted flow is **off by default**. Enable it by allowlisting the app
URLs identity may redirect users back to:

```
GATEWAY_OAUTH_ALLOWED_RETURN_URLS=https://app.example.com/,https://admin.example.com/auth
```

- Comma-separated list of exact origins or origin-bound path prefixes.
- A `return_to` must have the configured origin. A path entry permits that
  path and its descendants, never a lookalike host or path. Validation is
  **fail-closed**: anything else is rejected with `400`.
- An entry may be a one-label wildcard origin for preview deployments,
  `https://*.previews.example.app` (optionally with a path prefix). The `*`
  matches exactly one DNS label; the scheme (`https` only), parent and port
  are fixed, and a malformed pattern fails startup — including one whose
  parent is a public suffix (`*.co.uk`, or a shared host such as
  `*.vercel.app`, `*.netlify.app`, `*.pages.dev`, `*.github.io`). **A pattern
  admits every host under its parent**, and anything published there can
  receive a user's one-time OAuth code — use one only for a parent whose every
  subdomain you control, such as `https://*.<project>.pages.dev`.
  `GATEWAY_ALLOWED_ORIGINS` accepts the same pattern form for CORS.
- A malformed entry without `*` (not an absolute http(s) URL, or with a query
  or fragment) admits nothing and is logged at startup as
  `oauth_allowed_return_url_ignored`.
- **Empty disables the hosted flow** — `GET /oauth/start/*` and
  `GET/POST /oauth/callback/*` return `404`, and only the headless RPCs work.

The active allowlist, patterns included, is logged at startup
(`oauth_hosted_flow_enabled` / `oauth_hosted_flow_disabled`).

### Account chooser (`prompt`)

`GATEWAY_OAUTH_PROMPT` sets the OAuth `prompt` parameter forwarded to
providers that support it (Google, Microsoft) on the hosted authorization
request. It defaults to `select_account`, so a signed-in user is always
offered the provider's account chooser — without it the provider silently
reuses its existing SSO session, and a user who signed out of an app (local
tokens cleared, provider session intact) could not switch accounts.

- Set it to another value the provider accepts (e.g. `consent`) to forward
  that instead.
- Set it **explicitly empty** (`GATEWAY_OAUTH_PROMPT=`) to disable
  forwarding and restore the provider's default behavior.
- Upgrade note: because the default is on, existing deployments show the
  account chooser on Google/Microsoft login after upgrading unless the
  variable is set empty.
- Scope: applies to the env-configured (default-project) Google and
  Microsoft providers. Per-project providers configured via `config_json`
  and the generic OIDC provider are not affected by this variable.

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
  |  GET/POST /oauth/callback/google?state=&code=        |
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
2. **`GET/POST /oauth/callback/{provider}`** — the single registered redirect
   URI. Apple uses `POST`; others use `GET`. Recovers the state token, runs the code exchange + token mint,
   mints a single-use one-time code, and 302-redirects to
   `return_to?code=<otc>`. A refused sign-in is redirected to
   `return_to?error=<code>` instead ([callback errors](#callback-errors)).
3. **`RedeemOAuthCode{code}`** (Connect RPC) — the SPA exchanges the
   one-time code for `{user, access_token, refresh_token, expires_in}`.

An app may also bind the one-time code to itself with its own PKCE pair
(RFC 7636): it sends `code_challenge=<S256 challenge>` and
`code_challenge_method=S256` to `/oauth/start`, and redeems with
`RedeemOAuthCode{code, code_verifier}`. The challenge rides in the signed
state token beside identity's own provider verifier and is stored with the
code. `/oauth/start` answers 400 to any other pair: `plain`, a method without
a challenge, a challenge without `S256`, or a challenge that is not 43
base64url characters. An app that sends no challenge redeems without a
verifier, exactly as before.

### Callback errors

A callback without a trusted `return_to` answers `400` on the identity origin,
since there is nowhere safe to redirect. That is the case when:

- the provider itself redirected back with an `error` (for example the user
  declined consent), since the callback does not trust `return_to` before the
  state token is checked;
- the signed state token or its CSRF cookie does not verify;
- the state token was minted for a different provider than the callback path
  names; or
- the state token was minted for a different project than the callback
  request resolves to.

Once all of these pass, every refused sign-in is 302-redirected to
`return_to?error=<code>`, with no `code` parameter:

| `error` | Meaning |
| --- | --- |
| `email_not_verified` | The account's address is unverified and `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` is on. A verification email has been sent (throttled); the user follows it, then signs in again. |
| `account_disabled` | The account is deactivated or suspended. |
| `account_locked` | The account is temporarily locked after too many failed attempts. |
| `access_denied` | Any other refusal: the exchange failed or the provider did not verify its address, the project or the tenant's login policy does not admit the sign-in, or the provider's address does not prove the account it matches. |
| `temporarily_unavailable` | OAuth is not configured for the project, or a dependency the sign-in needs is briefly unavailable; retry. |
| `server_error` | An unexpected failure; retry. |

The account codes are given only for the account the provider proved, so
they say nothing about any other account. The redirect carries no
description; the reason is logged as `hosted_oauth_callback_failed`.

### Central-hub routing for non-default projects (`GATEWAY_OAUTH_HUB_SHARING`)

By default a non-default project must configure its **own** providers in
`config_json` and originate the hosted flow from its **own** auth-domain
host — strict per-project isolation (ADR-0010). `GATEWAY_OAUTH_HUB_SHARING=true`
opts a deployment into the Firebase/Auth0 model instead: any project may
route the hosted flow through the default project's host (the "central
hub") and, when it has no provider of its own, **borrow the default
project's provider client** — one registered redirect URI and one client
id serve every project (ADR-0011).

```
https://auth.example.com/oauth/start/google?return_to=<app-url>&project_key=<pk>
```

- `project_key` is the project's credential key (the same value the
  `X-Project-Key` header carries; browser redirects cannot set headers).
  The middleware resolves it **before** the handler runs; an unknown key
  is rejected with `401` — it is never silently downgraded to the
  default project.
- The key is prefixed onto the OAuth `state` (`<project_key>:<signed token>`)
  so the callback — arriving on the hub host with no header — re-scopes
  to the same project. The signed token additionally carries a
  `project_id` claim, so the prefix cannot re-route a flow: a mismatch
  between claim and resolved scope fails the callback.
- The user and one-time code are created **in the routed project**, and
  `RedeemOAuthCode` is called with that project's `X-Project-Key` as
  usual.
- A project's own `config_json` providers always win over the hub's;
  borrowing applies only to providers the project did not configure.
- **Trust caveat**: only enable hub sharing when every project belongs to
  the same operator as the hub — the provider consent screen shows the
  shared client's branding for all of them. It is off by default.

### The hosted auth UI (`/auth/`)

The built-in sign-in page is rendered **per request** and mirrors the
options the resolved project enables server-side. (It reflects the
project-wide policy; a tenant's own `LoginPolicy` can restrict further and
is still enforced server-side on every login attempt.)

- The **password form** renders only when the project's `login.allowed_methods`
  (config_json) is empty or includes `password`; the **sign-up toggle**
  additionally requires `GATEWAY_PASSWORD_SIGNUP_ENABLED`.
- **Provider buttons** render for exactly the providers a login attempt
  through that project would resolve — its own `config_json.oauth` providers,
  plus the hub's under `GATEWAY_OAUTH_HUB_SHARING` — and only when the hosted
  flow is enabled and the page was opened with a `return_to`. Each button
  starts the flow on the origin its provider client is registered for: own
  providers on the project's auth-domain, borrowed (hub-shared) providers on
  the hub — a borrowed button therefore also requires the page's
  `project_key` and is hidden without it.
- Served on a project's **own auth-domain**, the Host resolves the project.
  Served on the **central hub**, pass the project explicitly:

  ```
  https://auth.example.com/auth/?project_key=<pk>&return_to=<app-url>
  ```

  The page threads `project_key` and `return_to` into every provider
  button's `/oauth/start` link and scopes its password RPCs with the
  `X-Project-Key` header. An unknown `project_key` is rejected with 401.

### Apps that cannot take the redirect: the code page (`/auth/code`)

A CLI on a remote server cannot receive the callback's redirect: the browser
that signs in runs on the person's own machine, not on the server. Such an
app names identity's own code page as `return_to` and binds the sign-in with
PKCE:

```
https://auth.example.com/oauth/start/google
  ?return_to=https%3A%2F%2Fauth.example.com%2Fauth%2Fcode%3Fstate%3D<app-state>
  &code_challenge=<S256(verifier)>&code_challenge_method=S256
```

1. The app prints that URL. The person opens it in a browser on the machine
   they are typing at, and signs in.
2. The callback lands on `/auth/code?state=<app-state>&code=<otc>`. The page
   shows `<otc>#<app-state>` with a copy button, a warning to paste it only
   into the app where the sign-in started, and how long it lasts. As it loads,
   it removes the code from the address bar and the tab's back/forward
   history.
3. The person pastes the value into the app. The app checks that the part
   after `#` is the state it generated (so a value from an earlier attempt is
   told apart), then redeems with `RedeemOAuthCode{code, code_verifier}`.

The paste has to happen within the one-time code's TTL (a minute), so the
page suits an app the person can paste into from the browser's machine, such
as a terminal with an SSH session to the server. It does not suit a device
with no input to paste into, such as a TV: that needs the device
authorization grant (RFC 8628), which identity does not offer. This is a
copy-and-paste handover, with no polling and no user code to type.

**Start at `/oauth/start/{provider}`.** The app builds the start URL itself,
as above, with `project_key` when the provider is shared from the hub. The
hosted sign-in page (`/auth/`) does not carry a `code_challenge` to its
provider links, so a sign-in started there reaches the code page unbound and
is not shown. Password sign-in issues no one-time code and cannot use the code
page.

**What `/oauth/start` checks.** A `return_to` naming the code page on the host
the request reached is refused with 400, before the person signs in, unless:

- an allowlist entry names the page exactly. An origin, a path prefix such as
  `https://auth.example.com/auth`, or a wildcard that covers the page does not
  enable it;
- the app sent an S256 `code_challenge`;
- any `state` is 16-64 lowercase hex characters.

**What the page shows.** The page shows only a code minted for a sign-in that
sent a `code_challenge`. A code it shows is useless without the app's
verifier, so in a screen share, a proxy log or synced browser history it
grants nothing. A code minted without a challenge is never shown. A refused
sign-in (`?error=`) is shown as a fixed message per
[callback error](#callback-errors). The page echoes nothing else from its URL.
`state` is shown only when it is 16-64 lowercase hex characters, an alphabet
in which no one can write a message on identity's origin. Anything else gets a
fixed explanation and 400. The page answers with `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and a nonce-only
Content-Security-Policy.

**What PKCE does not protect against.** The binding stops anyone who *sees* a
code from using it. It does not stop someone who *started* the sign-in. That
person holds the verifier. If they persuade someone to open their start URL,
sign in, and send them the code from the page, they get that person's
account. This is the same consent-phishing risk as any copy-and-paste or
device-code sign-in. The page's warning (paste it only into the app where you
started signing in, and never give it to anyone who asks) is the only
mitigation. Enable the page only for apps that need it. Do not enable it on a
deployment whose users may be asked for codes by someone else, such as
support staff.

The page is served only while the hosted flow is enabled. To enable it, add
the page to the allowlist exactly, on each public origin an app starts from:

```bash
-e GATEWAY_OAUTH_ALLOWED_RETURN_URLS=https://app.example.com,https://auth.example.com/auth/code
```

The checks at `/oauth/start` apply to the code page on the host the sign-in
starts from. Start each sign-in on the host whose code page it returns to.

A pasted code is consumed by the same one-time-code rules below, so it works
once and within the code's TTL; the app asks the person to sign in again
after that.

### The one-time code

- Opaque, single-use, ~60s TTL.
- Only its SHA-256 hash is stored, bound to the user id and to the app's
  PKCE challenge when it sent one. **No token material is persisted** — the
  token pair is freshly minted on redeem.
- Redeeming consumes the code atomically (single winner across
  replicas). A replay, an expired code, an unknown code, or a
  `code_verifier` that does not match the code's challenge returns
  `Unauthenticated`. A missing verifier for a bound code and a verifier for an
  unbound one are mismatches too (RFC 9700's downgrade check). A mismatch
  spends nothing, so the app holding the verifier can still redeem. A
  `code_verifier` that is not 43-128 characters of `A-Z a-z 0-9 - . _ ~`
  returns `InvalidArgument`.
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
2. The provider redirects back to the frontend's callback page. Most providers
   redirect via GET with `?code=&state=`. Apple redirects via HTTP POST (`form_post`)
   with `code`, `state`, and an optional `user` JSON payload as form data.
3. **`OAuthLogin{code, provider, redirect_uri, state, state_token, apple_user_payload}`** —
   identity supports server-owned authorization-code exchange. It does not consume pre-verified frontend SDK ID tokens. This guarantees you own the user relationship, keeps identity keys off the frontend, and enables robust refresh token flows.

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
