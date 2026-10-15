# Native agent delegation and a resource server

This example uses a registered public native OAuth client, explicit human
consent, PKCE S256, rotating refresh tokens, and a resource that checks current
Identity authority on every request. It never uses a human token to perform the
agent's work. The native example does not create accounts or approve consent.

## Operator prerequisites

Use a real HTTPS Identity issuer with agents enabled, delegated OAuth enabled,
and session revocation. Register a native public client with both
`authorization_code` and `refresh_token` grants, the literal-loopback redirect
`http://127.0.0.1/callback`, and one resource bound to product `files` and scope
`files:read`. The native callback varies only the loopback port.

Configure the same resource on the issuer with a dedicated introspection
principal and the SHA-256 digest of its secret. Give the resource service only
that principal's secret, injected through the operator's normal secret manager.
Never put human credentials, bearer tokens, or provider keys in these files.

The human must already own an active agent in the resolved Identity project.
The embedded consent page supports the project's normal enabled password or
username login, TOTP/recovery challenge, and configured Turnstile assurance.
It stores the resulting human token only in page memory and calls the normal
human consent RPCs. CAPTCHA verification fails closed if unavailable. A missing
or stale human session returns to this same-origin sign-in flow. A reload
requires sign-in again; no human refresh token is saved.

A project that requires an external-only sign-in, DOB completion, passkeys, or
another step not offered by this embedded page must use its supported accounts
experience before this feature is enabled for that journey. This example does
not add a bearer callback, a token-paste field, or an authentication fallback.
The existing human OAuth provider login is distinct from this delegated agent
OAuth protocol. Do not enable a deployment merely because protocol tests pass.

## Run against your configured test deployment

Supply these non-secret settings to both processes through your environment:

- `DEMO_IDENTITY_ISSUER`: fixed HTTPS Identity origin.
- `DEMO_PROJECT_ID`: exact expected project ID.
- `DEMO_CLIENT_ID`: registered native public client ID.
- `DEMO_RESOURCE`: exact HTTPS resource identifier, also serving this example.

Resource mode additionally needs `DEMO_RESOURCE_ID` and
`DEMO_RESOURCE_SECRET` for its dedicated resource principal. It listens only on
`127.0.0.1:8099`; the operator's normal HTTPS ingress must expose it at the
configured resource origin.

```sh
go run ./examples/agent-delegation -mode resource
go run ./examples/agent-delegation -mode native
```

The native process prints an authorization URL. Open it yourself, sign in,
choose an agent, review the app/resource/scopes/expiry, and explicitly allow or
deny. It validates the exact callback state and issuer, exchanges the one-time
code with its private in-memory verifier, reads `/agent-demo` with the agent
access token, rotates refresh once, and revokes the grant. It saves or displays
no token. The resource authenticates its introspection call to the fixed issuer
and checks active status, agent/actor, issuer, project, one audience, client,
scope, grant, SID, expiry and adult standing. It never caches an active result
until JWT expiry. A local signature check alone would miss current revocation.

## Rebuild and test the consent page

The source is in `consent/src`, built with exact public Refraction UI, Astro,
Tailwind and Microsoft Playwright versions in the frozen lockfile. There are no
runtime CDN assets except the explicitly configured CAPTCHA provider. The
single generated HTML artifact is embedded by Go; Node is not a server runtime
dependency.

```sh
cd examples/agent-delegation/consent
pnpm install --frozen-lockfile
pnpm build
pnpm exec playwright install chromium
pnpm test
```

The browser tests compile a test-only in-memory Identity server and use fake
reserved-domain accounts and a deterministic external CAPTCHA verifier. Normal
password login, assurance token minting, TOTP/recovery, consent RPCs, PKCE token
exchange and authenticated resource introspection run through the actual HTTP
handlers. Only the external CAPTCHA script/provider is replaced. Browser
interception tests separately exercise lost-session UI and malicious display
text. No production account, provider session, application permission or engine
is touched. Tests also cover deny, no eligible agents, missing links, no default
agent selection, keyboard-accessible controls and responsive light/dark views.
The Go example tests check callback replay/state/issuer and per-request resource
revocation admission. The browser job is part of the repository CI aggregate.

The released Refraction Astro 0.22.1 supplies the actual `Button` component.
Its Input/Card/Radio entry points still export nothing, so these controls use
native semantic markup with Refraction's shared tokens/preset pending the
upstream export promotion. No custom replacement component package is added.
System appearance follows `prefers-color-scheme` automatically, including changes
while the page is open. All scripts carry per-response CSP nonces; the page is
uncacheable, cannot be framed, and does not forward a referrer to the app.
