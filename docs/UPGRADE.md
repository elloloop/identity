# Upgrade guide

## v4.0 → v4.1 — anonymous identity (additive)

v4.1 adds anonymous sign-in: credential-less accounts with a stable id that
can later gain a credential without changing it (see
[ADR-0013](./adr/0013-anonymous-identity.md) and the
[docs-site page](../docs-site/src/pages/docs/auth/anonymous.astro)).

**Nothing changes unless you turn it on.** The feature defaults off, the
new RPCs return `UNIMPLEMENTED` until a project enables it, the wire
additions are additive (`User.is_anonymous` field 26; two new RPCs), and
the `anonymous` JWT claim is emitted only for anonymous accounts, so
tokens for identified users are byte-identical to v4.0.

**Migrations** (postgres 0028, sqlite 0013), applied with
`identity migrate`, add `users.is_anonymous` and **rebuild the per-project
email unique index as a partial index** over non-empty addresses — every
anonymous account carries an empty email, so a total index would make the
second one a duplicate-key error. Uniqueness still binds, case-insensitively,
for every user that has an address.

> On a large `users` table the rebuild takes a brief SHARE lock (blocks
> writes, allows reads) for the duration of the build. Pre-build the
> replacement with `CREATE INDEX CONCURRENTLY` outside a transaction before
> deploying the binary, and the migration's `IF NOT EXISTS` clauses will
> no-op:
>
> ```sql
> CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_project_email_partial_uidx
>     ON users (project_id, lower(email)) WHERE email <> '';
> ```
>
> Only that one. The sweep index (`users_project_anonymous_last_login_idx`)
> cannot be pre-built — its `WHERE is_anonymous` predicate is parsed even
> under `IF NOT EXISTS`, and the column does not exist until the migration
> adds it. It needs no pre-build anyway: the predicate is false for every
> pre-existing row, so it builds empty in constant time.

**To enable it**, per deployment (default project) or per project in
`config_json`:

| Variable | Default | Notes |
| --- | --- | --- |
| `GATEWAY_ANONYMOUS_ENABLED` | `false` | turns on `SignInAnonymously` |
| `GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE` | `false` | gates it on the assurance layer; **boot fails** if set while `GATEWAY_ASSURANCE_ENABLED=false` |
| `GATEWAY_ANONYMOUS_RETENTION_DAYS` | `30` | days of inactivity before reaping; **must exceed `GATEWAY_REFRESH_EXPIRY_SECONDS`**; `0` disables the sweep. Deployment-wide, and the sweep reaches the **boot-default project only** — see below |

Two things to know before enabling:

1. **Sign-in is independent of `access.mode`; upgrading is not.** A project
   running `mode: closed` still hands out anonymous sessions — but
   `UpgradeAnonymousAccount` is enforced with signup semantics and returns
   `PERMISSION_DENIED` under `closed` (the default),
   `invite`, or an off-list `allowlist`. Setting only the
   `GATEWAY_ANONYMOUS_*` variables therefore gives you working sign-in and an
   upgrade path that always fails; open the project for the upgrade half to
   work. Control anonymous traffic with assurance and rate limits, not the
   access mode.
2. **Downstream services must check the `anonymous` claim** before granting
   anything that assumes a verified human. An anonymous `sub` is cheap to
   mint, and `email` is empty rather than absent-because-unverified, so code
   that only tests "is there a sub?" will treat a farmed account as a user.

**The retention sweep covers the boot-default project only.** A
control-plane deployment that enables anonymous sign-in on other projects
must reap those rows itself; otherwise they accumulate indefinitely from an
unauthenticated endpoint.

**Rollback** (`0028.down` / `0013.down`) **deletes anonymous users.** They
cannot be represented in the pre-0028 schema and hold no credential to sign
back in with, so the deletion is the honest outcome rather than a
half-applied rollback.

## v3.x → v4.0 — CAPTCHA becomes the client-assurance layer (breaking)

v4.0 replaces the inline-CAPTCHA design with the client-assurance layer
(App Attest / Play Integrity / Turnstile / reCAPTCHA behind one short-lived
assurance token — see
[ADR-0012](./adr/0012-client-assurance-layer.md) and the
[docs-site page](../docs-site/src/pages/docs/auth/assurance.astro)).
The new surface defaults off, so a deployment that never enabled CAPTCHA
gains no behaviour — **but read the environment section below before
pulling the image.** Every removed `GATEWAY_CAPTCHA_*` variable must be
DELETED from your environment, not merely set to `false`: the server
refuses to boot while any of them is *present*, whatever its value.

That check is deliberate. The rename would otherwise fail OPEN — a v3
operator who set `GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN=true` and pulled
v4 would boot clean with zero enforcement on six auth endpoints and no
signal. Failing closed is the only safe direction, but it means a
forgotten `GATEWAY_CAPTCHA_ENABLED=false` left in a compose file, a Helm
values template, or an ECS task definition will crash-loop the v4 image.
The error names every offending variable and its replacement.

**Wire (clients):** the `captcha_token` request field is removed from
`PasswordSignup`, `PasswordLogin`, `RequestPasswordReset`,
`RequestEmailLoginCode`, `RequestMagicLink`, and `BeginPasskeySignup`
(field numbers reserved). A web client now exchanges its captcha solution
first — `IssueAssuranceToken {platform:"web", webToken:…}` — and attaches
the returned token as the `X-Assurance-Token` header on the gated call.
The storage migrations (postgres 0027, sqlite 0012) are ordinary additive
migrations applied with `identity migrate`.

**Environment:** rename / replace. **Unset the left-hand column** — the
server refuses to boot while any of these is present, even set to `false`
or the empty string:

| v3.x — must be UNSET | v4.0 |
| --- | --- |
| `GATEWAY_CAPTCHA_ENABLED` | `GATEWAY_ASSURANCE_ENABLED` |
| `GATEWAY_CAPTCHA_PROVIDER` | `GATEWAY_ASSURANCE_WEB_PROVIDER` |
| `GATEWAY_CAPTCHA_TURNSTILE_SECRET` / `_SITE_KEY` | `GATEWAY_ASSURANCE_TURNSTILE_SECRET` / `_SITE_KEY` |
| `GATEWAY_CAPTCHA_RECAPTCHA_SECRET` / `_SCORE_THRESHOLD` | `GATEWAY_ASSURANCE_RECAPTCHA_SECRET` / `_SCORE_THRESHOLD` |
| `GATEWAY_CAPTCHA_ENFORCE_*` (6 toggles) | `GATEWAY_ASSURANCE_ENFORCE_*` (same six, same defaults) |

New (all optional): `GATEWAY_ASSURANCE_IOS_TEAM_ID` / `_IOS_BUNDLE_ID` /
`_IOS_ENV`, `GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME` /
`_ANDROID_CERT_SHA256_DIGESTS` / `_ANDROID_SA_KEY_JSON`,
`GATEWAY_ASSURANCE_TOKEN_TTL_SECONDS`,
`GATEWAY_ASSURANCE_CHALLENGE_TTL_SECONDS`,
`GATEWAY_ASSURANCE_DEVICE_RETENTION_DAYS` (default 90 — how long an
attested device survives after its last refresh; 0 keeps them forever),
`GATEWAY_ASSURANCE_WEB_TOKEN_TTL_SECONDS` (default 300 — the web arm's
own, shorter token lifetime), `GATEWAY_RATE_LIMIT_ASSURANCE_PER_IP`;
plus `GATEWAY_ASSURANCE_ALLOW_PROJECT_ONLY` — optional in general, but
**required** when you enable assurance with no env-level arm (every app
identity in per-project `config_json`), since the server otherwise
refuses to boot; per-project app identities go
in `config_json` `assurance`, authored with the operator RPC
`AdminSetProjectAssurance` (it takes the Play service-account key in
plaintext and encrypts it server-side under `GATEWAY_PROJECT_SECRETS_KEY`,
mirroring `AdminSetProjectOAuthProvider`), and read back with
`AdminGetProjectAssurance` — the only way to confirm an encrypted key
survived a rotation.

**Native gRPC embedders:** the three assurance RPCs are bridged onto
`RegisterGRPC` alongside the existing ones, so a host that enables any
`GATEWAY_ASSURANCE_ENFORCE_*` toggle can still obtain a token from the
same surface (the v3 CAPTCHA solution used to ride inside the request
message; it is now the `X-Assurance-Token` metadata key).

**Embedders:** `Options.CaptchaVerifier` is now
`Options.AssuranceWebVerifier`; the handler constructor no longer takes a
verifier (it is wired into the auth service). The public `pkg/captcha`
package is gone — it moved to `pkg/assurance` with a shape-identical
`Verifier` interface, so a custom verifier only needs its import swapped.

**Token verifiers:** `pkg/jwt.VerifyAccessToken` now rejects a token with
no `sub` claim. Every access token this server has ever minted carries
one, so this affects only callers that hand it non-access tokens; it is
what keeps an assurance token (deliberately subject-less) from ever
authenticating as a user.

---

## TL;DR

Upgrading from any **pre-v1.0** release to **v1.0** is a **breaking schema
reset**. All pre-v1.0 releases are deprecated. There is no in-place data
migration in this release.

- **Greenfield / no data you must keep:** do a **fresh install** of v1.0
  against an empty database. This is the supported and recommended path.
- **You ran a pre-v1.0 build with data you must keep:** there is **no
  first-party automated data migration**. No production deployment ran the
  legacy model, so no backfill is built or maintained. If you genuinely have
  pre-v1.0 data with rows, you must migrate it manually against a backup or
  copy; you are on your own.

Within the v1.x line, upgrades are ordinary additive migrations applied with
`identity migrate`; this guide is specifically about the pre-v1.0 → v1.0 jump.

## Why it is a reset

v1.0 is the Project / Tenant / Domain redesign. It inverts the storage
cardinality of the datastore, so the leading key of every data-plane table
changes. See [ADR-0002 — Project is the isolation shard](./adr/0002-project-is-the-isolation-shard.md)
for the decision, and [`docs/IDENTITY.md`](./IDENTITY.md) plus the other ADRs
under [`docs/adr/`](./adr/) for the full model.

### What changed in the model

| Pre-v1.0 | v1.0 |
|---|---|
| `tenant_id` is the physical shard **and** the leading key of every data-plane table. | **`project_id`** is the leading key. The **Project** is the isolation shard; it references a control-plane `projects` row. |
| `mode = single \| multi` boot flag forks the deployment; in `multi` each org-shard is its own `tenant_id`. | **`mode` removed.** One code path resolves the **Project** per request (from an `X-Project-Key` credential or the `Host` header), then the **Tenant** from the user's email domain. |
| **Organization** / **OrganizationMembership** model `OrganizationSignup`. | **Organizations removed.** Multitenancy is modelled by **Projects** (the shard) containing **Tenants** auto-formed from verified email domains. |
| A tenant string is both the company and the shard (1:1, same string). | Three distinct concepts: **storage scope** (physical shard), **Project** (control-plane isolation entity, 1 per storage scope), **Tenant** (data-plane company, many per Project). |

### What changed in config

The `mode` knob and its companions are gone. Remove these env vars if you set
them:

- `GATEWAY_IDENTITY_MODE`
- `GATEWAY_TENANT_HOST_BASE_DOMAIN`
- `GATEWAY_TENANT_RESOLUTION_SOURCES`

v1.0 adds the control-plane default project. In a clean install these default
to distinct values — the project **id** (`GATEWAY_DEFAULT_PROJECT_ID`, default
`default`) is intentionally **not** equal to the storage scope
(`GATEWAY_DEFAULT_TENANT_ID`, default `local`), per ADR-0002:

- `GATEWAY_DEFAULT_PROJECT_ID` — id of the default control-plane Project.
- `GATEWAY_DEFAULT_TENANT_ID` — the physical storage scope (shard) the default
  Project maps onto.

### New required config: `GATEWAY_PROJECT_SECRETS_KEY` (postgres)

Per-project OAuth providers (each Project configures its own Google/Microsoft/
Apple/OIDC providers, Firebase-style) store provider secrets **encrypted at
rest**. The encryption key is supplied via `GATEWAY_PROJECT_SECRETS_KEY`, a
**base64-encoded 32-byte** key.

**This is a breaking change for postgres deployments:** when
`GATEWAY_REPO_DRIVER=postgres` (the default), boot now **fails fast** unless
`GATEWAY_PROJECT_SECRETS_KEY` is set. Generate one and set it **before**
upgrading:

```sh
openssl rand -base64 32
```

Drivers without a control plane (`sqlite`, `memory`) pin every request to the
default project and draw OAuth providers from the `GATEWAY_OAUTH_*` env vars, so
they do **not** require the key. Rotating or losing the key invalidates every
per-project provider secret already stored (they must be re-encrypted).

### Removed: `GATEWAY_NATIVE_OAUTH_*_AUDIENCES_BY_PRODUCT`

Native mobile sign-in accepted-audience configuration is now **per-project**,
carried in a project's `config_json` under
`oauth.<provider>.native_audiences` (an array of accepted `aud` values). This
replaces the per-product stopgap env vars shipped the prior week:

- `GATEWAY_NATIVE_OAUTH_GOOGLE_AUDIENCES_BY_PRODUCT` — **removed**
- `GATEWAY_NATIVE_OAUTH_APPLE_AUDIENCES_BY_PRODUCT` — **removed**

**Migrate:** move each `product=aud1 aud2` entry to the corresponding project's
`config_json` (`oauth.google.native_audiences` / `oauth.apple.native_audiences`
/ the new `oauth.microsoft.native_audiences`). The plain
`GATEWAY_NATIVE_OAUTH_{GOOGLE,APPLE,MICROSOFT}_AUDIENCES` env vars are **kept**
as the **default project's** seed (a non-default project never inherits them),
and `GATEWAY_NATIVE_OAUTH_PRODUCT_PROJECTS` (product → project resolution) is
**kept**. This release also adds **native Microsoft** login (mirrors the hosted
verifier: issuer derived from the token's `tid`, `email → preferred_username →
upn` coalescing, and a **verbatim** nonce — unlike Apple's hashed nonce). It is
breaking, but the `*_BY_PRODUCT` vars shipped only the prior week.

> **⚠️ Do not silently disable native login.** `GATEWAY_NATIVE_OAUTH_ENABLED`
> auto-defaults to `true` only when at least one of the **plain**
> `GATEWAY_NATIVE_OAUTH_{GOOGLE,APPLE,MICROSOFT}_AUDIENCES` env vars is set — it
> no longer considers the removed `*_BY_PRODUCT` vars. If you migrate by moving
> audiences into `config_json` **and** clearing the plain env vars, the flag
> auto-defaults to **`false`** and `NativeOAuthLogin` returns
> `FailedPrecondition`. Such deployments **must set
> `GATEWAY_NATIVE_OAUTH_ENABLED=true` explicitly.**

> **🔒 Security — Microsoft nOAuth hardening (behavior change, hosted + native).**
> Microsoft sign-in defaults to **multi-tenant**: the expected issuer is derived
> from the token's own `tid`, so **any** Azure AD tenant — including an
> attacker-controlled one — can mint a valid token bearing an arbitrary `email`.
> Combined with email-based account federation this is an
> [nOAuth](https://www.descope.com/blog/post/noauth)-class account-takeover
> vector: an attacker presents a token carrying a **victim's email** and takes
> over the victim's account.
>
> This release **closes the vector by default** — hosted (`pkg/oauth/microsoft.go`)
> and native (`pkg/oauth/native.go`) alike. A Microsoft email is now trusted as
> verified (the precondition for federation) **only** when **one** of:
>
> - the issuing tenant is **pinned** — a single-tenant `tenant_id`
>   (`GATEWAY_MICROSOFT_TENANT_ID` for the default project, or
>   `oauth.microsoft.tenant_id` per project), OR the token's `tid` matches a new
>   **tenant allow-list** (`GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS`,
>   comma-separated, for the default project; `oauth.microsoft.allowed_tenants`
>   per project); OR
> - the token carries **`xms_edov == true`** (Microsoft's email-domain-owner-verified
>   claim, accepted as a JSON bool or the string `"true"`).
>
> A non-standard `verified_email == true` is **not** trusted on its own (an
> attacker tenant can set it as easily as the email), though an explicit
> `verified_email == false` is still rejected. Otherwise the email is treated as
> unverified and the login is **rejected** with `ErrEmailNotVerified` (surfaced as
> `Unauthenticated`) — matching the existing Google/Apple unverified-email
> handling, so **no** silent merge into an existing account is possible. Pinning a
> tenant also now **enforces** `tid` equality during verification (previously
> `tenant_id` only chose the authorize endpoint), so a single-tenant deployment
> rejects other tenants' tokens.
>
> **Tenant identifiers must be directory GUIDs.** Azure always stamps the token's
> `tid` as a directory (tenant) GUID, and the runtime pin compares against it
> (case-insensitively), so a value that can never equal a `tid` is **rejected by
> config validation** rather than silently failing every login. Where that
> rejection surfaces depends on where the value lives:
>
> - **env** (`GATEWAY_MICROSOFT_TENANT_ID` / `GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS`)
>   — fails fast at **boot** (`Config.Validate`);
> - **per-project `config_json`** (`oauth.microsoft.*`) — rejected at **admin
>   write time** for new values, but a value **already stored** from before this
>   release is validated on the **per-request project-resolution path**, so it
>   fails at request time and (until re-pinned) takes down that project's whole
>   resolution — not just Microsoft. There is no boot scan, so audit stored
>   configs before upgrading. The fields:
>
> - `allowed_tenants` (env `GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS` /
>   `oauth.microsoft.allowed_tenants`) — every entry must be a **GUID**;
> - `tenant_id` (env `GATEWAY_MICROSOFT_TENANT_ID` / `oauth.microsoft.tenant_id`) —
>   a **GUID**, a **meta** value (`common`/`organizations`/`consumers`, meaning "no
>   pin — multi-tenant"), or empty.
>
> When both `tenant_id` and `allowed_tenants` are set they form a **union**: a
> `tid` is accepted if it equals `tenant_id` OR is a member of `allowed_tenants`.
> A verified-domain string (e.g. `contoso.onmicrosoft.com`) is invalid in either.
> (Note the pre-existing env-var prefix divergence: `GATEWAY_MICROSOFT_TENANT_ID`
> vs `GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS`; the former is kept as-is to avoid a
> breaking rename.)
>
> **`xms_edov` is opt-in on the Azure side.** Azure does not emit it by default —
> add it as an optional ID-token claim on the app registration (Token
> configuration → optional claim → `xms_edov`) if you want to rely on it instead
> of pinning a tenant.
>
> **Action required:**
> - _Multi-tenant deployments that relied on blindly-trusted email_ — pin your
>   tenant(s) via `tenant_id` / `allowed_tenants` (GUIDs), or enable `xms_edov`,
>   or those logins are now rejected.
> - _Single-tenant deployments pinned by a **verified domain**_ — this is a
>   **breaking change**: re-pin `tenant_id` (or `GATEWAY_MICROSOFT_TENANT_ID`) to
>   your directory **GUID** before upgrading. An env domain-form value fails fast
>   at boot; a domain-form value **already stored** in a project's `config_json`
>   fails at request-time project resolution (no boot signal) and disables that
>   whole project until corrected — so audit and re-pin stored per-project
>   Microsoft configs first. Previously a domain-form pin silently rejected every
>   Microsoft login at runtime.

### Schema migrations involved

The model change lands across three Postgres migrations
(`internal/repo/postgres/migrations/`):

- **0013** — additive: creates the control-plane tables (`projects`,
  `project_credentials`, `project_auth_domains`, `platform_admins`) and the new
  data-plane governance tables (`tenants`, `domains`, `login_policies`,
  `tenant_memberships`, `tenant_invitations`).
- **0014** — drops the legacy `organizations` / `organization_members` tables.
- **0015** — renames each kept data-plane table's leading `tenant_id` column to
  `project_id`, re-scopes its indexes, and adds a `FOREIGN KEY` to
  `projects(id)`.

v1.0 then adds one more migration:

- **0016** — enables Postgres row-level security on the data-plane tables as
  defense-in-depth, scoped to `project_id` (`0016_enable_rls_data_plane`).

## Recommended path: fresh install

For a greenfield deployment, or any deployment without legacy data you must
keep:

1. Point v1.0 at an **empty** database.
2. Apply the schema:

   ```sh
   identity migrate          # applies all pending migrations (0001..0016)
   ```

   (Or run `migrate ... up` against `internal/repo/postgres/migrations` from
   your deploy pipeline; the binary does not auto-migrate on boot by default.)
3. Set v1.0 config (drop the removed `mode` vars; the default project id and
   storage scope default to `default` / `local`).
4. Start the service.
5. **Before opening the service to public traffic, bootstrap the first platform
   admin.** `CreateFirstPlatformAdmin` is a one-time, trust-on-first-use RPC
   that stays open only while `platform_admins` is empty, so a fresh,
   internet-exposed deployment has a window in which an anonymous caller could
   win the first-admin race. Create the first admin over a private network
   first, and/or set `GATEWAY_ADMIN_API_SECRET` (which then also gates the
   bootstrap on the `X-Admin-Secret` header) or
   `GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP=true` (to close the RPC entirely — the
   first admin is then created by a direct `platform_admins` insert, or by
   toggling the flag off just long enough to bootstrap and back on; no
   first-party seed CLI or migration ships for this).

SQLite backends are likewise a fresh start — the SQLite schema is the v1.0
Project-keyed shape; there is no legacy data to carry forward.

## Legacy Postgres data

There is **no first-party automated data migration** from the pre-v1.0 model to
v1.0. No production deployment ran the legacy model, so no backfill is built,
shipped, or maintained.

If you genuinely have a pre-v1.0 Postgres database with rows you must keep,
migrating it is your responsibility. Work against a backup or a copy, never the
live database. The migration is not trivial: migration 0015 renames each
data-plane table's leading `tenant_id` column to `project_id` **in place** and
attaches a `project_id → projects(id)` foreign key, so before 0015 runs you
must have created a control-plane `projects` row for **every** distinct legacy
`tenant_id` present in **any** of the ~30 FK'd data-plane tables — otherwise
0015's foreign key aborts the migration. There is no supported script for this,
and you are on your own.
