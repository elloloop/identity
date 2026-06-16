# Identity Redesign — Database Schema (Postgres)

> Single source of truth for the redesigned identity datastore. Postgres is
> the datastore. This document is grounded in the current proto schema
> (`proto/identity/schema/schema.proto`) and migrations `0001..0012`
> (`internal/repo/postgres/migrations/`). The next migration is **0013**.

## 0. Scope and the two-service split

**identity** owns: AuthN, User, Projects, Tenants, Domains, Login policies,
and tenant-level membership/admin. **Workspaces**, workspace membership, and
fine-grained / ReBAC authorization are a **separate service** and are NOT
modelled here. The two services meet only at token issuance. Identity never
models "workspace".

The redesign drops `Organization`, `OrganizationMembership`, `WorkingGroup`,
and the `MEMBER_OF` edge entirely (relocated to the workspace service).
`UserInvitation` is retired in favour of `TenantInvitation` (M8).

### Three tenant-like concepts (kept distinct — never conflated)

| Concept | Plane | What it is | Cardinality |
|---|---|---|---|
| **Storage scope** | physical | A physical tenant-shard. In single mode it equals `DefaultTenantID`. The shard a project's data physically lives on. | 1 per Project |
| **Project** | control plane | A *logical* control-plane isolation entity (= a Firebase project). Maps onto exactly one storage scope. The default project maps onto `DefaultTenantID` but is **NOT equal** to it. | 1 per storage scope |
| **Tenant** | data plane | A *logical* data-plane company entity, auto-formed per verified non-public email domain. | many per Project |

The "auth domain" in `ProjectAuthDomain` (a **hostname** identity is served on,
e.g. `auth.easyloops.app`) is a DIFFERENT concept from the Tenant email
**Domain** (e.g. `acme.com`). Never conflate them.

---

## 1. Control plane vs data plane overview

### Control plane (platform-global — the registry of projects)

Platform-global tables. They are NOT scoped by `project_id` (they *define* or
*reference* projects). Rows here describe which projects exist, how requests
resolve to a project, and who the platform operators are.

- **`projects`** — the registry. One row per project; `storage_scope_id` is
  UNIQUE and names the shard the project maps onto.
- **`project_credentials`** — publishable / secret / mTLS keys used to resolve
  the project on a request, by `public_id`.
- **`project_auth_domains`** — per-project serving hostnames. One host → one
  project (UNIQUE across the whole deployment). Lets one deployment serve
  product-branded domains; a request resolves its project by key OR by the
  `Host` header → `project_auth_domains.hostname`.
- **`platform_admins`** — platform operators (global email). Their auth
  sessions reuse `refresh_tokens` / `sessions` in a reserved platform scope.

### Per-project data plane (every row carries `project_id`)

Every data-plane row carries `project_id`. One storage scope per project; the
storage layer physically partitions by the project's `storage_scope_id`, while
`project_id` is the **leading column of every unique and secondary index** and
the mandatory `WHERE project_id = $1` predicate injected once at the repo
boundary.

New data-plane tables:

- **`tenants`** — logical company entity, auto-forms `latent` from the first
  user of a non-public email domain; becomes `claimed` once a domain is
  verified.
- **`domains`** — a tenant's email domain (`acme.com`); UNIQUE per
  `(project_id, domain)` — one tenant per domain.
- **`login_policies`** — 1:1 with a Tenant; controls HOW domain users
  authenticate, never WHETHER.
- **`tenant_memberships`** — materialized membership for explicit members and
  ALL role grants; pure domain membership is derivable.
- **`tenant_invitations`** — replaces `UserInvitation` (M8).

Kept auth/data tables (each gains `project_id`, uniqueness re-scoped to
`(project_id, ...)`): `users`, `refresh_tokens`, `sessions`,
`password_reset_tokens`, `email_verification_tokens`, `email_change_tokens`,
`email_login_codes`, `magic_link_tokens`, `login_challenges`, `passkeys`,
`passkey_challenges`, `totp_secrets`, `recovery_codes`, `qr_login_sessions`,
`oauth_identities`, `oauth_one_time_codes`, `phone_verification_codes`,
`identity_verifications`, `audit_events`.

> **Migration sequencing.** This slice (0013) creates ONLY the new tables
> (`projects`, `project_credentials`, `project_auth_domains`, `platform_admins`,
> `tenants`, `domains`, `login_policies`, `tenant_memberships`,
> `tenant_invitations`). New tables reference the existing `users` table where
> needed. It does NOT alter existing tables — the `project_id` backfill on
> `users` and the kept auth tables (rename `tenant_id` → `project_id`, re-scope
> uniqueness, add FKs to `projects`) is a **later slice**. The field lists in
> §2.2 (and the keep/modify table in §3) document that *target* shape;
> only §5 DDL is applied now.

### Conventions (inherited from `0001_init`, kept verbatim)

- **IDs.** Every table uses a `TEXT` primary key, not UUID. Populated with
  `gen_random_uuid()::text` (core on PG 13+; no extension on `postgres:16`).
- **Timestamps.** `bigint` epoch **milliseconds** (`*_at_ms`), never
  `timestamptz`. `0` means "never / unset".
- **Single-use / soft state.** `*_at_ms` columns that gate single-use default
  to `0` (= unconsumed/active), not `NULL`.
- **Enums.** `TEXT` + `CHECK (... IN (...))`, never PG `ENUM` types (adding a
  value is a one-line migration vs non-transactional `ALTER TYPE`).
- **JSON.** `JSONB NOT NULL DEFAULT '{}'::jsonb` for arbitrary payloads.
- **CSV columns.** `allowed_methods` etc. are plain `TEXT` CSV (matches the
  proto `transports`/`enum_values` CSV convention).
- **Email canonicalization (H2).** The canonical form is kept IN `email`
  (matches today's `canonicalizeEmail`); there is NO separate
  `canonical_email` column. Uniqueness uses `lower(email)` exactly as today.

---

## 2. Entity field lists

Legend — **Null**: N = `NOT NULL`, Y = nullable. **PK**: primary key. **U**:
participates in a unique index (scope noted). **Idx**: participates in a
secondary index. **FK**: foreign key.

### 2.1 Control-plane entities

#### `projects` (Project)

The control-plane registry. One row per project. Platform-global (NOT
`project_id`-scoped — it *is* the project).

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. The `project_id` every data-plane row carries. |
| `storage_scope_id` | TEXT | N | **U (global)**. The physical shard this project maps onto. The default project's value = `DefaultTenantID`, but `id != storage_scope_id`. |
| `name` | TEXT | N | Display name. Not unique. |
| `status` | TEXT | N | `CHECK IN ('active','suspended')`. Default `active`. Indexed. |
| `config_json` | JSONB | N | Default `'{}'`. Per-project settings, decoded by `service.ParseProjectConfig`. Currently: `cors.allowed_origins` (array of bare scheme+host origins layered on the global `GATEWAY_ALLOWED_ORIGINS` floor). Reserved for enabled login methods, OAuth providers, email templates, TTLs. |
| `created_at_ms` | BIGINT | N | |
| `updated_at_ms` | BIGINT | N | |

- **PK:** `id`.
- **Unique:** `projects_storage_scope_uidx (storage_scope_id)` — one project
  per storage scope, enforced globally.
- **Indexes:** `projects_status_idx (status)`.
- **FKs:** none (root of the control plane).

#### `project_credentials` (ProjectCredential)

Lookup keys used to resolve a project on a request.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Indexed. |
| `kind` | TEXT | N | `CHECK IN ('publishable','secret','mtls')`. |
| `public_id` | TEXT | N | **U (global)**. The lookup handle presented on the request. |
| `secret_hash` | TEXT | N | Default `''`. sha256 of the secret; empty for `publishable`/`mtls`. |
| `status` | TEXT | N | `CHECK IN ('active','revoked')`. Default `active`. |
| `created_at_ms` | BIGINT | N | |
| `last_used_at_ms` | BIGINT | N | Default `0`. |
| `revoked_at_ms` | BIGINT | N | Default `0` (= not revoked). |

- **PK:** `id`.
- **Unique:** `project_credentials_public_id_uidx (public_id)` — the key handle
  is globally unique so a single lookup resolves the project.
- **Indexes:** `project_credentials_project_idx (project_id)`,
  `project_credentials_project_status_idx (project_id, status)`.
- **FKs:** `project_id` → `projects(id)` ON DELETE CASCADE.

#### `project_auth_domains` (ProjectAuthDomain — NEW)

Per-project serving hostname. One host → one project, so the `Host` header
alone resolves a project. This is the HOSTNAME identity is served on
(`auth.easyloops.app`), NOT a tenant email domain.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Indexed. |
| `hostname` | TEXT | N | **U (global, deployment-wide)** on `lower(hostname)` — one host → one project. |
| `is_primary` | BOOLEAN | N | Default `FALSE`. The hostname used to build email/oauth links. At most one primary per project (partial unique). |
| `verified_at_ms` | BIGINT | N | Default `0` (= unverified) until DNS/ownership is proven. |
| `created_at_ms` | BIGINT | N | |

- **PK:** `id`.
- **Unique:** `project_auth_domains_hostname_uidx (lower(hostname))` (global);
  `project_auth_domains_primary_uidx (project_id) WHERE is_primary` — at most
  one primary hostname per project.
- **Indexes:** `project_auth_domains_project_idx (project_id)`.
- **FKs:** `project_id` → `projects(id)` ON DELETE CASCADE.

##### Customer custom auth-domains (ownership verification)

A project can register a **customer-owned** serving hostname and must prove
control of it before it resolves. The flow is gated by the admin secret (the
same `X-Admin-Secret` the other control-plane admin RPCs use):

1. **`AddProjectAuthDomain(project_id, hostname)`** inserts the row with
   `verified_at_ms = 0` and returns a DNS **TXT challenge**. The challenge is
   deterministic — `identity-auth-domain-verify=` + `hex(sha256(project_id + ":"
   + lower(hostname)))` — so no per-domain token is stored and re-issuing returns
   the same value (mirrors the tenant email-domain pattern in `domain.go`).
2. The customer publishes that TXT value on the hostname.
3. **`VerifyProjectAuthDomain(project_id, hostname)`** looks up the TXT record
   via the injected `service.DNSResolver`; on a match it stamps
   `verified_at_ms`. A missing/mismatched record is a retryable
   `PermissionDenied`; the domain stays unverified.
4. **`ListProjectAuthDomains(project_id)`** returns all of a project's domains
   (verified and pending).

**Resolution invariant:** the Host→project resolver
(`GetProjectByAuthHostname` / `ResolveByHostname`) matches **only verified**
domains (`verified_at_ms > 0`). An unverified custom hostname does NOT resolve
to its project, so an attacker cannot point an unproven hostname at someone
else's project. Deployer-seeded domains
(`GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS`) and operator-vouched
`AdminAddProjectAuthDomain` domains are seeded pre-verified.

**Per-domain TLS is operational, out of scope for the server.** Once a custom
hostname is verified, the operator is responsible for serving a valid TLS
certificate for it (e.g. an ACME/Let's-Encrypt-fronting load balancer or a
wildcard cert). identity stores the hostname and gates resolution on ownership;
it does not provision or terminate TLS.

#### `platform_admins` (PlatformAdmin)

Platform operators. Their auth sessions reuse `refresh_tokens`/`sessions` in a
reserved platform scope (no separate session table).

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `email` | TEXT | N | **U (global)** on `lower(email)`. |
| `password_hash` | TEXT | N | Default `''`. bcrypt; never exposed via RPC. |
| `totp_required` | BOOLEAN | N | Default `FALSE`. |
| `status` | TEXT | N | `CHECK IN ('active','suspended')`. Default `active`. Indexed. |
| `created_at_ms` | BIGINT | N | |
| `last_login_at_ms` | BIGINT | N | Default `0`. |

- **PK:** `id`.
- **Unique:** `platform_admins_email_uidx (lower(email))` — global.
- **Indexes:** `platform_admins_status_idx (status)`.
- **FKs:** none (platform-global).

### 2.2 Per-project data-plane entities

> For the KEPT auth tables the field lists below show the **target** shape
> (`project_id` leading, uniqueness re-scoped). Today's tables carry
> `tenant_id` as that column; the rename + re-scope is the later backfill
> slice, NOT this migration.

#### `users` (User) — MODIFIED

Existing auth/profile fields PLUS `project_id`. One identity per person per
project; canonical email kept in `email` (H2). Organization linkage dropped.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)`. Leading column of every index. |
| `email` | TEXT | N | Canonical form (H2). **U** per `(project_id, lower(email))`. |
| `name` | TEXT | N | Default `''`. |
| `role` | TEXT | N | `CHECK IN ('admin','member','guest')`. Default `member`. |
| `avatar_url` | TEXT | N | Default `''`. |
| `status` | TEXT | N | `CHECK IN ('active','invited','deactivated','suspended')`. Default `active`. Indexed. |
| `recovery_email` | TEXT | N | Default `''`. |
| `password_hash` | TEXT | N | Default `''`. |
| `quota_bytes` | BIGINT | N | Default `0`. |
| `totp_required` | BOOLEAN | N | Default `FALSE`. |
| `failed_login_count` | BIGINT | N | Default `0`. |
| `locked_until_ms` | BIGINT | N | Default `0`. |
| `email_verified` | BOOLEAN | N | Default `FALSE`. |
| `email_verified_at_ms` | BIGINT | N | Default `0`. |
| `idv_verified` | BOOLEAN | N | Default `FALSE`. |
| `idv_verified_at_ms` | BIGINT | N | Default `0`. |
| `phone_number` | TEXT | N | Default `''`. |
| `phone_verified` | BOOLEAN | N | Default `FALSE`. |
| `phone_verified_at_ms` | BIGINT | N | Default `0`. |
| `invited_by` | TEXT | N | Default `''`. |
| `invited_at_ms` | BIGINT | N | Default `0`. |
| `last_login_at_ms` | BIGINT | N | Default `0`. |
| `deactivated_at_ms` | BIGINT | N | Default `0`. |
| `created_at_ms` | BIGINT | N | |
| `updated_at_ms` | BIGINT | N | |

- **PK:** `id`. **Unique:** `users_project_email_uidx (project_id, lower(email))`.
- **Indexes:** `users_project_status_idx (project_id, status)`.
- **FKs:** `project_id` → `projects(id)`.

#### `tenants` (Tenant) — NEW

Logical company entity. Auto-forms `latent` from the first user of a non-public
email domain; `claimed` once a domain is verified.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Leading column. |
| `name` | TEXT | N | Display name. |
| `primary_domain` | TEXT | N | Default `''`. Plain indexed convenience — **NOT unique** (H: dropped uniqueness). |
| `status` | TEXT | N | `CHECK IN ('latent','claimed','suspended')`. Default `latent`. |
| `created_at_ms` | BIGINT | N | |
| `updated_at_ms` | BIGINT | N | |

- **PK:** `id`.
- **Unique:** none beyond PK (no domain uniqueness on tenant).
- **Indexes:** `tenants_project_idx (project_id)`,
  `tenants_project_primary_domain_idx (project_id, lower(primary_domain))`,
  `tenants_project_status_idx (project_id, status)`.
- **FKs:** `project_id` → `projects(id)` ON DELETE CASCADE.

#### `domains` (Domain — tenant email domain) — NEW

A tenant's verified email domain. One tenant per domain. PUBLIC providers
(`gmail.com`, `outlook.com`, `yahoo.com`, …) are blocklisted at THREE gates
(signup tenant-formation, domain verify, derived-membership) on the canonical
punycode domain (H3) — enforced in application code on `lower(domain)`.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Leading column. |
| `tenant_id` | TEXT | N | **FK** → `tenants(id)` ON DELETE CASCADE. Indexed. |
| `domain` | TEXT | N | Canonical punycode form. **U** per `(project_id, lower(domain))` — one tenant per domain. |
| `verification_method` | TEXT | N | `CHECK IN ('dns_txt','email')`. |
| `status` | TEXT | N | `CHECK IN ('pending','verified','failed')`. Default `pending`. |
| `verified_at_ms` | BIGINT | N | Default `0` (= unverified). |
| `created_at_ms` | BIGINT | N | |
| `updated_at_ms` | BIGINT | N | |

- **PK:** `id`. **Unique:** `domains_project_domain_uidx (project_id, lower(domain))`.
- **Indexes:** `domains_project_tenant_idx (project_id, tenant_id)`,
  `domains_project_status_idx (project_id, status)`.
- **FKs:** `project_id` → `projects(id)` ON DELETE CASCADE;
  `tenant_id` → `tenants(id)` ON DELETE CASCADE.

#### `login_policies` (LoginPolicy) — NEW

1:1 with a Tenant. Controls HOW domain users authenticate, never WHETHER.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Leading column. |
| `tenant_id` | TEXT | N | **FK** → `tenants(id)` ON DELETE CASCADE. **U** per `(project_id, tenant_id)` — 1:1. |
| `allowed_methods` | TEXT | N | Default `''`. CSV; empty fails safe to `email_otp` in app code. |
| `sso_required` | BOOLEAN | N | Default `FALSE`. |
| `sso_connection_json` | JSONB | N | Default `'{}'`. |
| `require_2fa` | BOOLEAN | N | Default `FALSE`. |
| `password_min_length` | INTEGER | N | Default `0`. Min password length for this tenant; `0` = global default. Tenants tighten, never loosen. (migration 0263) |
| `password_require_classes` | BOOLEAN | N | Default `FALSE`. Demands all four char classes; global classes always enforced. (migration 0263) |
| `session_idle_timeout_seconds` | BIGINT | N | Default `0`. Invalidate a session unused for this long; `0` = no idle timeout. (migration 0263) |
| `session_absolute_timeout_seconds` | BIGINT | N | Default `0`. Invalidate a session older than this; `0` = no absolute timeout. (migration 0263) |
| `created_at_ms` | BIGINT | N | |
| `updated_at_ms` | BIGINT | N | |

- **PK:** `id`. **Unique:** `login_policies_project_tenant_uidx (project_id, tenant_id)`.
- **Indexes:** covered by the unique index.
- **FKs:** `project_id` → `projects(id)` ON DELETE CASCADE;
  `tenant_id` → `tenants(id)` ON DELETE CASCADE.

#### `tenant_memberships` (TenantMembership) — NEW

Materialized for explicit members and ALL role grants. Pure domain membership
is derivable and NOT stored. **Precedence (H6):** a materialized row's `status`
is authoritative whenever a row exists; derived domain-membership applies only
when no row exists, and only against a VERIFIED domain of a CLAIMED tenant.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Leading column. |
| `tenant_id` | TEXT | N | **FK** → `tenants(id)` ON DELETE CASCADE. |
| `user_id` | TEXT | N | **FK** → `users(id)` ON DELETE CASCADE. |
| `source` | TEXT | N | `CHECK IN ('domain','invited','added')`. |
| `role` | TEXT | N | `CHECK IN ('member','admin','owner')`. Default `member`. |
| `status` | TEXT | N | `CHECK IN ('active','pending','inactive')`. Default `active`. |
| `created_at_ms` | BIGINT | N | |
| `updated_at_ms` | BIGINT | N | |

- **PK:** `id`. **Unique:** `tenant_memberships_project_tenant_user_uidx (project_id, tenant_id, user_id)`.
- **Indexes:** `tenant_memberships_project_user_idx (project_id, user_id)`
  (answer "which tenants does this user belong to?");
  `tenant_memberships_project_tenant_idx (project_id, tenant_id)`.
- **FKs:** `project_id` → `projects(id)` CASCADE; `tenant_id` → `tenants(id)`
  CASCADE; `user_id` → `users(id)` CASCADE.

#### `tenant_invitations` (TenantInvitation) — NEW (replaces UserInvitation, M8)

One open invite per `(project, tenant, email)`, enforced via an atomic
revoke-then-insert at the repo boundary (entdb/memory cannot do partial-unique;
Postgres uses a partial unique index on the open status as defense-in-depth).

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | TEXT | N | **PK**. |
| `project_id` | TEXT | N | **FK** → `projects(id)` ON DELETE CASCADE. Leading column. |
| `tenant_id` | TEXT | N | **FK** → `tenants(id)` ON DELETE CASCADE. |
| `token_hash` | TEXT | N | **U** per `(project_id, token_hash)`. sha256 of the invite token. |
| `email` | TEXT | N | Invitee email (canonical/lowercased). |
| `invited_by` | TEXT | N | Default `''`. Free-text provenance — the inviting user's id. NOT an FK (matches `users.invited_by` in `0001_init`), so deleting the inviter never blocks or rewrites the audit trail. |
| `role` | TEXT | N | `CHECK IN ('member','admin','owner')`. Default `member`. |
| `status` | TEXT | N | `CHECK IN ('pending','accepted','revoked','expired')`. Default `pending`. |
| `expires_at_ms` | BIGINT | N | |
| `accepted_at_ms` | BIGINT | N | Default `0`. |
| `created_at_ms` | BIGINT | N | |

- **PK:** `id`. **Unique:** `tenant_invitations_project_token_uidx (project_id, token_hash)`;
  `tenant_invitations_open_email_uidx (project_id, tenant_id, lower(email)) WHERE status = 'pending'`
  — one open invite per (project, tenant, email).
- **Indexes:** `tenant_invitations_project_tenant_idx (project_id, tenant_id)`,
  `tenant_invitations_project_expires_idx (project_id, expires_at_ms)` (GC sweeper).
- **FKs:** `project_id` → `projects(id)` CASCADE; `tenant_id` → `tenants(id)`
  CASCADE. `invited_by` is NOT an FK (free-text provenance, matching
  `users.invited_by` in `0001_init`).

### 2.3 Kept auth/data tables (target shape — `tenant_id` → `project_id`)

Each kept table replaces its leading `tenant_id` column with `project_id`
(FK → `projects(id)`), and re-scopes every unique/secondary index to lead with
`project_id`. No other columns change. The per-table target shape:

| Table | PK | Unique (re-scoped to `project_id`) | Secondary indexes | FK to `users` |
|---|---|---|---|---|
| `refresh_tokens` | `id` | `(project_id, token_hash)` | `(project_id, user_id)` | `user_id` CASCADE |
| `sessions` | `id` | `(project_id, sid)` | `(project_id, user_id)` | `user_id` CASCADE |
| `password_reset_tokens` | `id` | `(project_id, token_hash)` | `(project_id, user_id)`, `(project_id, expires_at_ms)` | `user_id` CASCADE |
| `email_verification_tokens` | `id` | `(project_id, token_hash)` | `(project_id, user_id)`, `(project_id, expires_at_ms)` | none (user_id default `''`) |
| `email_change_tokens` | `id` | `(project_id, token_hash)` | `(project_id, expires_at_ms)` | `user_id` CASCADE |
| `email_login_codes` | `id` | `(project_id, email)` | `(project_id, expires_at_ms)` | none (keyed by email) |
| `magic_link_tokens` | `id` | `(project_id, token_hash)` | `(project_id, expires_at_ms)` | none (keyed by email) |
| `login_challenges` | `id` | `(project_id, challenge_id)` | `(project_id, expires_at_ms)` | `user_id` CASCADE |
| `passkeys` | `id` | `(project_id, credential_id)` | `(project_id, user_id)` | `user_id` CASCADE |
| `passkey_challenges` | `id` | — | `(project_id)`, `(project_id, expires_at_ms)` | none (user_id default `''`) |
| `totp_secrets` | `id` | — | `(project_id, user_id)` | `user_id` CASCADE |
| `recovery_codes` | `id` | `(project_id, user_id, code_hash)` | — | `user_id` CASCADE |
| `qr_login_sessions` | `id` | `(project_id, session_id)` | `(project_id, expires_at_ms)` | none (user_id default `''`) |
| `oauth_identities` | `id` | `(project_id, provider, provider_user_id)` | `(project_id, user_id)` | `user_id` CASCADE |
| `oauth_one_time_codes` | `id` | `(project_id, code_hash)` | `(project_id, expires_at_ms)` | `user_id` CASCADE |
| `phone_verification_codes` | `id` | `(project_id, user_id)` | `(project_id, expires_at_ms)` | `user_id` CASCADE |
| `identity_verifications` | `id` | `(project_id, verification_id)` | `(project_id, user_id, created_at_ms DESC)` | `user_id` CASCADE |
| `audit_events` | `id` | — | `(project_id, actor, occurred_at_ms DESC)`, `(project_id, event_type, occurred_at_ms DESC)` | none (actor/target are free text refs) |

All other columns (timestamps, hashes, device fields, CHECK enums) are
unchanged from `0001..0012`. Platform-admin sessions reuse `refresh_tokens` /
`sessions` in a reserved platform scope — i.e. with `project_id` set to the
reserved platform-scope project id (the default/platform project), never to a
tenant.

---

## 3. Keep / modify / add / drop vs today's schema

| Today (entity / table) | Action | Target | Rationale |
|---|---|---|---|
| `users` | **MODIFY** | add `project_id`; uniqueness → `(project_id, lower(email))`; drop org linkage | One identity per person per project; canonical email stays in `email` (H2). |
| `refresh_tokens` | **MODIFY** | `tenant_id`→`project_id`; re-scope uniqueness | Per-project isolation. |
| `sessions` | **MODIFY** | `tenant_id`→`project_id`; re-scope uniqueness | Platform-admin sessions reuse this in the reserved platform scope. |
| `password_reset_tokens` | **MODIFY** | `tenant_id`→`project_id` | |
| `email_verification_tokens` | **MODIFY** | `tenant_id`→`project_id` | |
| `email_change_tokens` | **MODIFY** | `tenant_id`→`project_id` | |
| `email_login_codes` | **MODIFY** | `tenant_id`→`project_id` | |
| `magic_link_tokens` | **MODIFY** | `tenant_id`→`project_id` | |
| `login_challenges` | **MODIFY** | `tenant_id`→`project_id` | |
| `passkeys` | **MODIFY** | `tenant_id`→`project_id` | |
| `passkey_challenges` | **MODIFY** | `tenant_id`→`project_id` | |
| `totp_secrets` | **MODIFY** | `tenant_id`→`project_id` | |
| `recovery_codes` | **MODIFY** | `tenant_id`→`project_id` | |
| `qr_login_sessions` | **MODIFY** | `tenant_id`→`project_id` | |
| `oauth_identities` | **MODIFY** | `tenant_id`→`project_id`; uniqueness → `(project_id, provider, provider_user_id)` | |
| `oauth_one_time_codes` | **MODIFY** | `tenant_id`→`project_id` | |
| `phone_verification_codes` | **MODIFY** | `tenant_id`→`project_id` | |
| `identity_verifications` | **MODIFY** | `tenant_id`→`project_id` | |
| `audit_events` | **MODIFY** | `tenant_id`→`project_id` | |
| `admin_help_requests` | **MODIFY** | `tenant_id`→`project_id` | Kept; re-scoped like the rest (out of the new-table slice; backfill slice). |
| — | **ADD** | `projects` | Control-plane registry. |
| — | **ADD** | `project_credentials` | Key-based project resolution. |
| — | **ADD** | `project_auth_domains` | Host-header project resolution (NEW). |
| — | **ADD** | `platform_admins` | Platform operators. |
| — | **ADD** | `tenants` | Logical data-plane company. |
| — | **ADD** | `domains` | Tenant email domains. |
| — | **ADD** | `login_policies` | Per-tenant auth policy. |
| — | **ADD** | `tenant_memberships` | Materialized membership + role grants. |
| — | **ADD** | `tenant_invitations` | Tenant invites (replaces `user_invitations`). |
| `user_invitations` | **DROP** | replaced by `tenant_invitations` (M8) | Retire `UserInvitation`. |
| `organizations` | **DROP** | relocate to workspace service | B1: org-shards become Projects. |
| `organization_members` | **DROP** | relocate to workspace service | |
| `groups` | **DROP** | relocate to workspace service | `WorkingGroup` leaves identity. |
| `group_memberships` (`MEMBER_OF`) | **DROP** | relocate to workspace service | Remove dead `MEMBER_OF` code (H). |

> The DROP/MODIFY rows above are the *target*. The DDL in §5 is **additive
> only** — it creates the nine new tables and does not touch `users` or any
> existing table. The renames, drops, and backfills land in subsequent slices.

---

## 4. Per-project isolation rules

1. **Storage cardinality inverts (B1).** PROJECT = shard (not tenant = shard).
   `RepositoryForTenant` → `RepositoryForProject`. Per-request resolution
   resolves the **PROJECT** (shard) first — by credential `public_id`
   (publishable/secret/mtls) OR by `Host` header →
   `project_auth_domains.hostname` — then resolves the **TENANT** (logical)
   from the user's email domain / membership. `mode=multi` is removed; each
   existing `mode=multi` org-shard becomes its own Project; greenfield uses the
   default project.

2. **`project_id` is the leading column** of every unique and secondary index
   on every data-plane table. No data-plane unique constraint is global except
   where stated for control-plane tables (`storage_scope_id`, `public_id`,
   `hostname`, platform-admin `email`).

3. **Mandatory predicate.** Every data-plane query carries a mandatory
   `WHERE project_id = $1` injected once at the repo boundary (the
   `RepositoryForProject` wrapper), so no call site can omit it.

4. **Postgres RLS as defense-in-depth.** Row-level security policies keyed on a
   per-connection `app.project_id` setting back the repo-boundary predicate;
   schema-/db-per-project is reserved for physical-isolation customers only.

5. **Default project seeded on boot.** A logical Project entity is seeded with
   `storage_scope_id = DefaultTenantID`; the Project `id` is NOT equal to the
   storage id. The default/platform project also serves as the reserved
   platform scope for platform-admin sessions.

6. **Public-provider blocklist (H3).** Enforced in application code at three
   gates — signup tenant-formation, domain verify, derived-membership — on the
   canonical **punycode** `lower(domain)`. The DB stores domains in that
   canonical form; the blocklist is a typed config list, never DB rows.

7. **Derived membership (H6).** Pure domain membership is computed only against
   a VERIFIED `domains` row of a `claimed` `tenants` row, and only when NO
   `tenant_memberships` row exists for `(project_id, tenant_id, user_id)`. A
   materialized row always overrides the derived result.

---

## 5. Postgres DDL — new tables only (migration 0013, additive)

The following is the complete, ready-to-apply DDL for migration **0013**. It
creates ONLY the nine new tables, additively. New tables reference the existing
`users` table where needed (`tenant_memberships.user_id`,
`tenant_invitations.invited_by`). It does NOT alter `users` or any existing
table — the `project_id` backfill on existing tables is a later slice. FKs from
the new tables to `projects` are created here; the eventual FKs from existing
tables to `projects` land with that later backfill slice.

> Ordering matters: `projects` first (referenced by all others), then
> `tenants` (referenced by `domains`, `login_policies`, `tenant_memberships`,
> `tenant_invitations`).

```sql
-- 0013_add_projects_tenants_domains.up.sql
--
-- Identity redesign — control-plane (projects, project_credentials,
-- project_auth_domains, platform_admins) and per-project data-plane
-- (tenants, domains, login_policies, tenant_memberships,
-- tenant_invitations) tables.
--
-- Additive only: creates the nine new tables. New tables reference the
-- existing users table where needed; existing tables are NOT altered here
-- (the tenant_id -> project_id rename + project_id backfill on users and
-- the kept auth tables is a later slice). Conventions inherited from
-- 0001_init: TEXT PKs (gen_random_uuid()::text), bigint epoch-ms
-- timestamps (*_at_ms; 0 = never), TEXT+CHECK enums, JSONB payloads,
-- project_id as the leading column of every data-plane index.

-- ── Control plane ──────────────────────────────────────────────────────

CREATE TABLE projects (
    id                TEXT PRIMARY KEY,
    storage_scope_id  TEXT NOT NULL,
    name              TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','suspended')),
    config_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at_ms     BIGINT NOT NULL,
    updated_at_ms     BIGINT NOT NULL
);
CREATE UNIQUE INDEX projects_storage_scope_uidx
    ON projects (storage_scope_id);
CREATE INDEX projects_status_idx
    ON projects (status);

CREATE TABLE project_credentials (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL
                       CHECK (kind IN ('publishable','secret','mtls')),
    public_id       TEXT NOT NULL,
    secret_hash     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','revoked')),
    created_at_ms   BIGINT NOT NULL,
    last_used_at_ms BIGINT NOT NULL DEFAULT 0,
    revoked_at_ms   BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX project_credentials_public_id_uidx
    ON project_credentials (public_id);
CREATE INDEX project_credentials_project_idx
    ON project_credentials (project_id);
CREATE INDEX project_credentials_project_status_idx
    ON project_credentials (project_id, status);

CREATE TABLE project_auth_domains (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hostname        TEXT NOT NULL,
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at_ms  BIGINT NOT NULL DEFAULT 0,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX project_auth_domains_hostname_uidx
    ON project_auth_domains (lower(hostname));
CREATE UNIQUE INDEX project_auth_domains_primary_uidx
    ON project_auth_domains (project_id) WHERE is_primary;
CREATE INDEX project_auth_domains_project_idx
    ON project_auth_domains (project_id);

CREATE TABLE platform_admins (
    id               TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    password_hash    TEXT NOT NULL DEFAULT '',
    totp_required    BOOLEAN NOT NULL DEFAULT FALSE,
    status           TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','suspended')),
    created_at_ms    BIGINT NOT NULL,
    last_login_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX platform_admins_email_uidx
    ON platform_admins (lower(email));
CREATE INDEX platform_admins_status_idx
    ON platform_admins (status);

-- ── Per-project data plane ─────────────────────────────────────────────

CREATE TABLE tenants (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL DEFAULT '',
    primary_domain  TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'latent'
                       CHECK (status IN ('latent','claimed','suspended')),
    created_at_ms   BIGINT NOT NULL,
    updated_at_ms   BIGINT NOT NULL
);
CREATE INDEX tenants_project_idx
    ON tenants (project_id);
CREATE INDEX tenants_project_primary_domain_idx
    ON tenants (project_id, lower(primary_domain));
CREATE INDEX tenants_project_status_idx
    ON tenants (project_id, status);

CREATE TABLE domains (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain               TEXT NOT NULL,
    verification_method  TEXT NOT NULL
                            CHECK (verification_method IN ('dns_txt','email')),
    status               TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','verified','failed')),
    verified_at_ms       BIGINT NOT NULL DEFAULT 0,
    created_at_ms        BIGINT NOT NULL,
    updated_at_ms        BIGINT NOT NULL
);
CREATE UNIQUE INDEX domains_project_domain_uidx
    ON domains (project_id, lower(domain));
CREATE INDEX domains_project_tenant_idx
    ON domains (project_id, tenant_id);
CREATE INDEX domains_project_status_idx
    ON domains (project_id, status);

CREATE TABLE login_policies (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    allowed_methods      TEXT NOT NULL DEFAULT '',
    sso_required         BOOLEAN NOT NULL DEFAULT FALSE,
    sso_connection_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    require_2fa          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms        BIGINT NOT NULL,
    updated_at_ms        BIGINT NOT NULL
);
CREATE UNIQUE INDEX login_policies_project_tenant_uidx
    ON login_policies (project_id, tenant_id);

CREATE TABLE tenant_memberships (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source          TEXT NOT NULL
                       CHECK (source IN ('domain','invited','added')),
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('member','admin','owner')),
    status          TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','pending','inactive')),
    created_at_ms   BIGINT NOT NULL,
    updated_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX tenant_memberships_project_tenant_user_uidx
    ON tenant_memberships (project_id, tenant_id, user_id);
CREATE INDEX tenant_memberships_project_user_idx
    ON tenant_memberships (project_id, user_id);
CREATE INDEX tenant_memberships_project_tenant_idx
    ON tenant_memberships (project_id, tenant_id);

CREATE TABLE tenant_invitations (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    email           TEXT NOT NULL,
    invited_by      TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('member','admin','owner')),
    status          TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','accepted','revoked','expired')),
    expires_at_ms   BIGINT NOT NULL,
    accepted_at_ms  BIGINT NOT NULL DEFAULT 0,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX tenant_invitations_project_token_uidx
    ON tenant_invitations (project_id, token_hash);
CREATE UNIQUE INDEX tenant_invitations_open_email_uidx
    ON tenant_invitations (project_id, tenant_id, lower(email))
    WHERE status = 'pending';
CREATE INDEX tenant_invitations_project_tenant_idx
    ON tenant_invitations (project_id, tenant_id);
CREATE INDEX tenant_invitations_project_expires_idx
    ON tenant_invitations (project_id, expires_at_ms);
```

### Down migration (`0013_add_projects_tenants_domains.down.sql`)

Drop in reverse dependency order so FK children go before their parents:

```sql
-- 0013_add_projects_tenants_domains.down.sql
DROP TABLE IF EXISTS tenant_invitations;
DROP TABLE IF EXISTS tenant_memberships;
DROP TABLE IF EXISTS login_policies;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS tenants;
DROP TABLE IF EXISTS platform_admins;
DROP TABLE IF EXISTS project_auth_domains;
DROP TABLE IF EXISTS project_credentials;
DROP TABLE IF EXISTS projects;
```

> **`invited_by` is intentionally not an FK.** It mirrors `users.invited_by`
> from `0001_init` (also a plain `TEXT DEFAULT ''`, not an FK). Keeping it
> free-text provenance means deleting the inviting user neither blocks the
> delete (as an `ON DELETE RESTRICT` FK would) nor silently rewrites the
> invitation's audit trail (as `SET NULL`/`SET DEFAULT` would, and `SET DEFAULT
> ''` would in fact fail the FK check because no `users` row has id `''`). The
> `tenant_invitations_open_email_uidx` partial unique index is
> defense-in-depth for the "one open invite per (project, tenant, email)"
> rule; the authoritative enforcement is the atomic revoke-then-insert at the
> repo boundary, because entdb/memory drivers cannot express partial-unique
> constraints and must match Postgres semantics in the conformance suite.
