# ADR-0014 — Cross-product SSO (one auth-origin login, per-product sessions)

## Status

Accepted (2026-08-10).

Depends on ADR-0002 (Project is the isolation shard) and builds on the hosted
OAuth flow's one-time-code handover. Related: ADR-0010 / ADR-0011 (per-project
OAuth providers and hub sharing).

## Context

A deployment that serves several products under one project (one user pool)
wants the Firebase/Auth0 shape: the user signs in ONCE at the auth origin,
and each product they open afterwards signs them in without another
credential prompt. The naive implementations are all unsafe:

- **Share a token pair across products.** This server's refresh tokens rotate
  and treat replay as theft (OAuth 2.1 §4.13); a pair handed to two products
  would trip replay detection on its second rotation and nuke every session.
  A product's storage posture also differs — one pair cannot be both an
  httpOnly cookie and an SDK-held token.
- **A long-lived "master token" any product redeems.** A bearer credential
  that mints sessions everywhere is a master key: one leak signs the attacker
  in everywhere, and it must be exempted from the rotation/replay rules that
  make the normal tokens safe.
- **Trust the cookie alone.** A session cookie that mints tokens without
  re-checking authorization would launder a login the deployer has since
  revoked or tightened: suspended accounts, allowlist removals, a tenant
  policy that now requires a second factor, a product's age floor.

## Decision

### One authentication, many independently minted sessions

A successful authentication at the auth origin (the hosted OAuth callback)
additionally establishes a **server-side SSO session**: an opaque token in a
browser cookie, only its SHA-256 hash persisted, with its own absolute TTL
(no sliding renewal) and its own store (`sso_sessions`), revocable
independently of the refresh tokens.

Each product's fast path is a browser navigation to the auth origin:

```
GET /sso/continue?return_to=<allowlisted app url>
```

The endpoint validates the SSO session and then **ends at the existing
single-use `?code=` redeem** (`mintOAuthOneTimeCode` + `RedeemOAuthCode`,
the same handover the hosted callback uses). The product redeems the code
into its OWN fresh token pair. Nothing about refresh rotation, replay
detection, or per-tenant session timeouts is re-implemented, and token
pairs are never shared across products.

### The cookie

`__Host-sso_session`: HttpOnly, Secure, `Path=/`, **no `Domain` attribute**
(the browser pins it to the exact auth origin host), `SameSite=Lax` (the
continue-as link is a top-level navigation; cross-site POSTs carry nothing).
The plaintext exists only in this cookie; the store holds its hash.

### Continue-as re-runs every authorization gate

Each continue-as — a cookie is proof of a PAST authentication, not of
present authorization — re-runs, before minting the code:

1. the return-URL allowlist (`GATEWAY_OAUTH_ALLOWED_RETURN_URLS`,
   fail-closed, the same list the hosted flow uses);
2. the project access mode (`enforceProjectAccessLogin`);
3. account status (`checkAccountStatus`);
4. the tenant login policy with the **original** login method recorded on
   the session — never a synthetic `sso` method — so a policy that now
   disallows that method, or requires a second factor the login never gave,
   refuses (a second-factor requirement falls back to a full interactive
   login rather than minting anything);
5. the product age gate (`enforceProductAgeGate`).

### Never bridges projects

The session record carries the `ProjectID` it was minted under and the
continue-as gate requires it to equal the request's resolved project scope
(mirroring the hosted-state project binding). Data-plane rows are already
project-partitioned (RLS on postgres, sibling stores on memory); the
explicit check is the structural guard on top, tested against a non-default
project.

### Revocation: SSO dies with the credential, logout stays local

One shared `revokeDerivedSessionsForUser` helper (refresh tokens +
mode=session access rows + SSO sessions, all three always attempted) fires
from every credential-kill path: password reset confirm, email change
confirm, planted-credential clearing, account deletion (request, admin
delete, and sweeper purge), and refresh-replay detection. `DeleteUser`'s
cascade drains the rows with the account. `SignOutEverywhere`
(ProfileService) revokes SSO sessions too and works for password-less
OAuth-only accounts — there is no password to confirm with, so the caller's
valid access token is the confirmation. Per-product `Logout` is unchanged
and deliberately leaves the SSO session alive: signing out of one product
is not signing out of the auth origin.

### Configuration

All env, default-off, fail-closed at boot:

- `GATEWAY_SSO_ENABLED` (default false — no routes, no cookie, no rows);
  enabling requires `GATEWAY_OAUTH_ALLOWED_RETURN_URLS` to be set.
- `GATEWAY_SSO_SESSION_TTL_SECONDS` (default 28800, must be > 0).
- `GATEWAY_SSO_CONTINUE_MODE` — `silent` (default: validate and redirect
  with the code immediately) or `one_tap` (render a confirmation page;
  mint only on the confirming POST).

## Consequences

- An expired or revoked SSO session costs the user one interactive login at
  the auth origin; nothing breaks, because continue-as is only ever a fast
  path onto the standard flows.
- `RedeemOAuthCode` now redeems when EITHER hosted OAuth OR SSO is enabled,
  since continue-as mints codes too (an SSO-only deployment has no OAuth
  provider of its own).
- The SSO table is per-project like every other ephemeral-auth table; the
  GC sweeper reaps expired rows.
- Cross-product SSO does not extend to headless/native flows: it is a
  browser-cookie capability at the auth origin by construction.
