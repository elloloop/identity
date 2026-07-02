# Upgrade guide

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
