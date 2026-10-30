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

### A client per auth host (`callback_host`)

A provider's consent screen names the application its client is registered
as, so a project served on several auth hosts shows every user the same name.
When one project (one account pool) serves several products, each on its own
auth host, a project can name a different client for a given callback host
(ADR-0019):

```json
"oauth": {
  "google": { "client_id": "base", "client_secret_enc": "<enc>" },
  "hosts": {
    "auth.widgets.example": {
      "google":    { "client_id": "widgets", "client_secret_enc": "<enc>" },
      "microsoft": { "client_id": "widgets-ms", "client_secret_enc": "<enc>" },
      "apple":     { "client_id": "example.widgets.web" }
    }
  }
}
```

- **The key is the host of the flow's callback URL**: the host the hosted
  sign-in page and `/oauth/start` are served on, or the host of the app's
  `redirect_uri` in the headless flow. The callback resolves the client from
  the redirect URI signed into the state, so it completes with the client
  the start used.
- **An override swaps the client and nothing else.** The provider is still
  the one the precedence above selects: the project's own, the env provider
  for the default project, or the hub's under `GATEWAY_OAUTH_HUB_SHARING`.
  Endpoints, Microsoft tenant settings, native audiences and Apple's team id,
  key id and private key come from it. Apple's override is a Services ID of
  the same team; the others are a client id and secret.
- **An override never enables a provider.** Where the precedence yields
  none, the provider stays unavailable on every host.
- **A broken override is unavailable** on its host (a secret that will not
  decrypt, or an env base the server cannot rebuild because the embedder
  supplied its own `OAuthRegistry`). It never falls back to the base client,
  which the provider would reject for that callback.
- **The hosted page starts an overridden provider on its own host**, with no
  `project_key`, since its client is registered there. Other providers start
  where their base client is registered, as before. If the project's primary
  auth domain has an override, the own-provider flows that other hosts start
  there use it too.
- **The default project's overrides** apply to requests that resolve to it by
  an auth domain or a key. A request that names no project falls back to the
  env settings, which carry no overrides.

Register each override's callback, `https://<host>/oauth/callback/<provider>`,
with its client, and configure overrides only once every replica runs a
version that reads them: an older replica ignores `oauth.hosts`, so a flow it
completes would exchange the code with the base client and fail.

Author them with the admin API: `AdminSetProjectOAuthProvider` with
`config.callback_host` set takes only `client_id` and `client_secret` (an
empty secret keeps the stored one; Apple takes none),
`AdminDeleteProjectOAuthProvider` with `callback_host` removes one, and
`AdminListProjectOAuthProviders` returns them, redacted, in `host_clients`.
Setting or deleting the base provider leaves its overrides in place.

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
4. The app shows which account signed in, so a person who pasted someone
   else's code notices.

**The verifier must be random.** A code the page shows is only as safe as
the app's verifier: identity checks its alphabet and length but cannot
check its randomness, and a wrong verifier leaves the code unspent. Generate
a fresh `code_verifier` for every sign-in from at least 32 random octets from
a cryptographically secure generator, base64url-encoded (RFC 7636 §4.1).
Read the pasted value from an interactive prompt or standard input, not a
command-line argument (a shell may treat `#` specially), and split it on the
last `#`.

The paste has to happen within the one-time code's TTL (a minute), so the
page suits an app the person can paste into from the browser's machine, such
as a terminal with an SSH session to the server. It does not suit a device
with no input to paste into, such as a TV: that needs the device
authorization grant (RFC 8628), which identity does not offer. This is a
copy-and-paste handover, with no polling and no user code to type.

**Start at `/oauth/start/{provider}`.** The app builds the start URL itself,
as above, with `project_key` when the provider is shared from the hub. The
hosted sign-in page (`/auth/`) does not carry a `code_challenge` to its
provider links, so it cannot start a sign-in that returns to the code page.
Password sign-in issues no one-time code and cannot use the code page. Treat
the start URL as sensitive: it carries the app's challenge and state.

**The page is opt-in by name, host by host.** On a host whose allowlist entry
does not name it exactly, the page shows no code: it answers 404 with a fixed
message. An origin, a path prefix such as `https://auth.example.com/auth`, or
a wildcard that covers the page does not enable it. The page checks this
itself, against the scheme and host the request reached (as
`X-Forwarded-Proto` and `X-Forwarded-Host` report them, the same values the
provider redirect URI is built from), so it holds whichever host the sign-in
started on and however `return_to` spelled the page's host.

**What `/oauth/start` checks.** So that an app learns of a mistake before the
person signs in, a `return_to` naming the code page on the hostname the
request reached (on any port, after surrounding whitespace is trimmed) is
refused with 400 unless:

- it names the page as exactly `/auth/code`, with no trailing slash or dot
  segments;
- an allowlist entry names the page exactly;
- the app sent an S256 `code_challenge`;
- any `state` is 16-64 lowercase hex characters.

A sign-in that starts on one host this server serves and returns to the code
page on another is not refused at `/oauth/start`. The page there still shows
a code only if its own host's entry names it, the code is bound and the state
is hex.

**What the page shows.** Where it is enabled, the page shows only a code
minted for a sign-in that sent a `code_challenge`. A code it shows is useless
without the app's verifier, so in a screen share, a proxy log or synced
browser history it grants nothing. A code minted without a challenge is never shown. A refused
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
the page to the allowlist exactly, on each public origin it should show codes
on:

```bash
-e GATEWAY_OAUTH_ALLOWED_RETURN_URLS=https://app.example.com,https://auth.example.com/auth/code
```

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
