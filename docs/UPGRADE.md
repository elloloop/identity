# Upgrade guide

## TL;DR

Upgrading from any **pre-v1.0** release to **v1.0** is a **breaking schema
reset**. All pre-v1.0 releases are deprecated. There is no in-place data
migration in this release.

- **Greenfield / no data you must keep:** do a **fresh install** of v1.0
  against an empty database. This is the supported and recommended path.
- **You ran a pre-v1.0 build with data you must keep:** there is no production
  data on the legacy model, so no backfill is maintained. A rare developer or
  early adopter in this situation can try the
  **unsupported, best-effort** bridge in
  [`scripts/upgrade/pre-v1-to-v1.sql`](../scripts/upgrade/pre-v1-to-v1.sql) —
  on a copy, verified by hand.

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

### Schema migrations involved

The reset lands across three Postgres migrations
(`internal/repo/postgres/migrations/`):

- **0013** — additive: creates the control-plane tables (`projects`,
  `project_credentials`, `project_auth_domains`, `platform_admins`) and the new
  data-plane governance tables (`tenants`, `domains`, `login_policies`,
  `tenant_memberships`, `tenant_invitations`).
- **0014** — drops the legacy `organizations` / `organization_members` tables.
- **0015** — renames each kept data-plane table's leading `tenant_id` column to
  `project_id`, re-scopes its indexes, and adds a `FOREIGN KEY` to
  `projects(id)`.

## Recommended path: fresh install

For a greenfield deployment, or any deployment without legacy data you must
keep:

1. Point v1.0 at an **empty** database.
2. Apply the schema:

   ```sh
   identity migrate          # applies all pending migrations (0001..0015)
   ```

   (Or run `migrate ... up` against `internal/repo/postgres/migrations` from
   your deploy pipeline; the binary does not auto-migrate on boot by default.)
3. Set v1.0 config (drop the removed `mode` vars; the default project id and
   storage scope default to `default` / `local`).
4. Start the service.

EntDB backends are likewise a fresh start — the EntDB schema is the v1.0
Project-keyed shape; there is no legacy EntDB data to carry forward.

## Unsupported path: bridging legacy Postgres data

> **This is best-effort and unsupported.** It is not wired into the boot path
> or golang-migrate, is not exercised by CI, and carries no compatibility
> guarantee. Run it manually, on a copy, and verify before trusting it. If in
> doubt, do a fresh install instead.

If you genuinely ran a pre-v1.0 build against Postgres and want to keep that
data, the bridge in
[`scripts/upgrade/pre-v1-to-v1.sql`](../scripts/upgrade/pre-v1-to-v1.sql)
materializes one control-plane `projects` row per distinct legacy `tenant_id`
so that migration 0015's `project_id → projects(id)` foreign key is satisfied.
Each project's `id` and `storage_scope_id` are set to the legacy shard string,
because 0015 renames `tenant_id → project_id` **in place** without rewriting
values.

Sequence (the bridge runs *between* migrations 0014 and 0015):

```sh
# 1. stage the schema to 0014 (creates `projects`, drops `organizations`)
migrate -path internal/repo/postgres/migrations -database "$DSN" goto 14

# 2. materialize a Project per legacy tenant_id (this script)
psql "$DSN" -v ON_ERROR_STOP=1 -f scripts/upgrade/pre-v1-to-v1.sql

# 3. finish: rename tenant_id -> project_id and attach the projects FK
migrate -path internal/repo/postgres/migrations -database "$DSN" up
```

For a single-deployment legacy database (one shard string, your old
`GATEWAY_DEFAULT_TENANT_ID`), set v1.0 config so the default project id matches
the bridged shard:

```sh
GATEWAY_DEFAULT_PROJECT_ID=<your legacy GATEWAY_DEFAULT_TENANT_ID>
GATEWAY_DEFAULT_TENANT_ID=<unchanged>
```

A legacy `mode=multi` database has several shard strings; the bridge creates
one Project per shard automatically. Review the resulting `projects` rows and
choose the one to use as your default project.

The script's own header documents its guards (it refuses to run if `projects`
is missing or if 0015 has already been applied) and the exact post-conditions.
Read it before running.
