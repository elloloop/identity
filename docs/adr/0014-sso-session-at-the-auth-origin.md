# ADR-0014 — Single sign-on: a first-party session at the auth origin

## Status

Accepted (2026-08-09).

Builds on ADR-0002 (the project is the isolation shard) and ADR-0011 (hub
OAuth provider sharing). Changes no existing wire contract: `Logout`,
`RedeemOAuthCode`, `RevokeAllSessions` and `SignOutEverywhere` keep their
current semantics for every existing caller.

## Context

A deployment that hosts several products behind one identity server makes a
user authenticate once per product. Each product redirects to
`/oauth/start/{provider}`, the browser is bounced to Google, and the user
picks the same account they picked ten minutes ago in a different product.
Nothing in the server remembers that this browser already proved who it
belongs to — the only artefact of a successful authentication is a token
pair, and a token pair belongs to exactly one product.

Sharing that token pair between products is not an option, and not merely
by convention:

- Refresh tokens rotate, and a replayed consumed token is treated as theft
  (`ConsumeRefreshTokenByHash` + the replay branch that kills every session
  for the user). Two products rotating one lineage would trip that on each
  other constantly, and correctly.
- A pair handed to product B is a credential B did not authenticate for. A
  compromise of the weakest product would become a compromise of all of
  them.

So the thing to share is the **authentication**, not its product-specific
result.

## Decision

**A successful browser authentication establishes a server-side SSO session,
referenced by a host-locked first-party cookie. Products still get their own
freshly-minted, independently-rotating token pairs — one authentication,
many sessions.**

### 1. The cookie carries no identity

`__Host-sso_session`, set on the auth origin only:
`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, **no `Domain` attribute**.
The `__Host-` prefix makes all three of those browser-enforced rather than
merely intended — a deployment cannot widen the cookie to a parent domain
and start leaking it to product origins, because the browser refuses to
store a `__Host-` cookie that carries `Domain`. It follows the existing
`__Host-oauth_csrf_*` precedent in `internal/app/oauth_hosted_http.go`.

Its value is 32 bytes of `crypto/rand`, base64url-encoded. Only its SHA-256
hash is stored, exactly as refresh tokens and one-time codes are — a
database disclosure yields no usable session.

The three dormant `GATEWAY_COOKIE_DOMAIN` / `GATEWAY_COOKIE_SECURE` /
`GATEWAY_COOKIE_SAMESITE` config fields, which no code path has ever read,
are **deleted** rather than adopted. `GATEWAY_COOKIE_DOMAIN` in particular
is a footgun under this design: its only function would be to defeat the
host-locking the design depends on.

### 2. The session is a project-scoped row, not a JWT

`sso_sessions` — `token_hash`, `user_id`, `login_method`, `created_at_ms`,
`last_used_at_ms`, `expires_at_ms`, `revoked_at_ms`, `ip_address`,
`user_agent` — stored through `service.Repository` like every other durable
auth artefact, on all three drivers, held identical by the conformance
suite.

Server-side, not a self-contained signed token, because the whole point is
revocability: "sign out everywhere" must be able to *end* it, and a signed
JWT cannot be un-signed. The `HostedStateClaims` idiom is right for a value
that round-trips through a provider and dies in 15 minutes; it is wrong for
one that must be killable for 90 days.

Rows are project-scoped like everything else (ADR-0002), and the fast path
verifies the row's project against the request's resolved scope. A session
established under project A cannot fast-path into project B even on a
hub-shared deployment where both resolve at the same host — the same
cross-check `CompleteHostedOAuth` already performs on `claims.ProjectID`.

**Rolling lifetime.** `expires_at_ms` is re-anchored at `now + TTL` on each
successful use (`GATEWAY_SSO_SESSION_TTL_SECONDS`, default 90 days). There
is deliberately no second "absolute cap" knob: one lifetime setting, and an
abandoned session dies on schedule.

### 3. The fast path re-mints; it never re-uses

When `/oauth/start` (or the hosted sign-in page) sees a valid SSO session it
renders **"Continue as \<email\>"** with **"Use a different account"** beside
it. Continuing does *not* produce tokens directly. It ends exactly where
`CompleteHostedOAuth` ends: by minting the existing single-use `?code=` and
redirecting to `return_to`. The product redeems it with the unchanged
`RedeemOAuthCode` RPC, which mints the pair.

That is the load-bearing structural choice in this ADR. Because the fast
path terminates at the one-time code, **every property of token issuance is
inherited rather than re-implemented**: per-product pairs, rotation lineage,
`SessionRecord` creation under `mode=session`, and the product age gate
inside `issueTokensWithSessionStart` all happen on the normal path, in the
normal order, with no SSO-specific branch anywhere near them. There is no
second token-minting code path to keep in sync, and no way for a future
change to token issuance to miss the SSO case.

### 4. Authentication is not authorization — the gates re-run

Skipping the provider round trip must not skip anything else. Before a code
is minted the fast path runs, in this order:

1. `allowlist.Allows(return_to)` — unchanged, at `/oauth/start` as always.
2. the SSO session lookup, including the project cross-check above.
3. `checkAccountStatus` — lockout, account status, IDV.
4. `enforceProjectAccessLogin` — the project's access mode. An allowlisted
   admin project still refuses an account that is not on its list, one tap
   after that same account signed into a consumer product.
5. `enforceLoginPolicy`, replayed with **the login method that established
   the SSO session** (stored on the row), not with a fabricated "sso"
   method. The cookie is evidence of a past authentication, and must not
   launder a password login into something the tenant's policy treats as
   stronger.
6. and then, on redemption, `RedeemOAuthCode`'s own
   `checkAccountStatus` + `enforceLoginPolicy` + the age gate, unchanged.

**Second factors are not fast-pathed.** When the policy decision or the
account requires a second factor, the continue-as card is not offered and
the browser takes the full sign-in flow. A challenge/response cannot be
completed inside a 302 handler, and treating a months-old cookie as
standing proof of a second factor would defeat the reason a deployment
turned 2FA on.

### 5. Sign-out: per-product logout does not touch it

| Surface | Effect |
|---|---|
| `Logout` (per product) | That product's refresh token, and its access session under `mode=session`. **The SSO session is untouched.** Unchanged behaviour for every existing caller. |
| `RevokeAllSessions` / `SignOutEverywhere` | Every refresh token and session for the user **and every SSO session for the user**, and the cookie is cleared on the response when the call arrives with one. |
| `ChangePassword` | Already revoked every session; now revokes SSO sessions too, via the same shared helper. |

Per-product sign-out leaving SSO alive is the deliberate, familiar model:
signing out of one app is not signing out of the account, and exactly one
surface does the latter.

**Not built, deliberately:** a provenance column linking each refresh token
to the SSO session that begat it. It would let a caller revoke one browser's
descendants specifically. The approved sign-out model has no use for it —
revocation is user-scoped, which is a strict superset — and it would cost a
new column on three drivers plus threading the id through the one-time code
into `issueTokens`. `ListMySessions` already enumerates what would be
revoked. When a "sign out this browser's other apps" feature is actually
wanted, that is the change to make.

### 6. Silent vs. one tap is configuration

`GATEWAY_SSO_CONTINUE_MODE` — `tap` (default) or `silent`. In `silent` mode
a valid session forwards without an interstitial; in `tap` mode the user
sees which account is about to be used and can reject it.

`tap` is the default because the failure mode is asymmetric. Silent SSO on a
shared or family device signs a second person into a product as the first
person, invisibly, and the products downstream have no way to tell that
happened. One tap costs a fraction of a second and makes the account
visible before anything is minted. A deployment whose devices are all
single-user can set `silent`.

## Consequences

- **Positive.** Products get SSO with no client change: any surface that
  already redirects to `/oauth/start` benefits, including native apps whose
  hub round trip runs in the system browser's (non-ephemeral) cookie jar.
- **Positive.** No new token-minting path. The blast radius of this feature
  stops at "which code path decides to mint a one-time code"; everything
  downstream of the code is the pre-existing, already-tested flow.
- **Negative / accepted.** The auth origin now sets a long-lived cookie, so
  it becomes a tracking-relevant surface and a target. Mitigations: hashed
  at rest, host-locked, `HttpOnly`, opaque, revocable, and never sent to a
  product origin.
- **Negative / accepted.** Accounts requiring a second factor see no
  benefit (§4).
- **Neutral.** `GATEWAY_SSO_ENABLED` defaults to **false**: a server that
  operators run for their own deployments does not silently start setting a
  new cookie on upgrade.
