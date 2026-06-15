# Identity service: what it is, what it isn't

This document is the **charter** for the identity service. It exists so
that future contributors (human or agent) don't have to re-derive what
the service is *for* every time they touch the code. If you find
yourself making an architectural decision and you can't tell which
shape the answer should take, read this first — most of those decisions
are already made here.

The companion engineering rules ([AGENTS.md](../AGENTS.md)) say *how*
to write code in this repo. This document says *what* the code is.

---

## v1.0 breaking changes (read first if you upgraded)

v1.0 is the Project/Tenant/Domain redesign (ADR-0001..0009). It removed
several pre-v1.0 features that older copies of this document still
described as live. Upgrading from a pre-v1.0 deployment is a **breaking
schema reset — there is no in-place data migration in this release** (a
legacy-data migration script and Postgres row-level-security hardening
are tracked v1.1 follow-ups). What changed:

- **`OrganizationSignup` removed**, along with the `Organization` /
  `OrganizationMembership` storage. Multitenancy is now modelled by
  **Projects** (the isolation shard) with **Tenants** auto-formed from
  verified email domains inside a project (ADR-0002, ADR-0004).
- **`mode=single | multi` removed**, together with its env vars
  (`GATEWAY_IDENTITY_MODE`, `GATEWAY_TENANT_HOST_BASE_DOMAIN`,
  `GATEWAY_TENANT_RESOLUTION_SOURCES`). There is one code path now: every
  request resolves a **Project** first, then a **Tenant**.
- **Data-plane storage re-keyed `tenant_id` → `project_id`** (ADR-0002);
  `project_id` is the leading column of every data-plane index.
- **`TenantAdmin` / `RepositoryForTenant` embedding options removed**;
  the per-project repository is resolved internally from the request's
  project scope (`RepositoryForProject`).

The decision log at the end of this document still records the pre-v1.0
rationale where it remains useful as history; the ADRs under
[`docs/adr/`](./adr/) supersede the entries they reference.

---

## One-line summary

Identity is a **reusable, Firebase-style authentication and account
service**. One codebase, deployed per product; multitenancy is resolved
per request as **Project → Tenant**, not chosen by a boot-time mode flag.

## What identity is for

Identity is **not** specific to any one product. It is a shared service
that other products at the company depend on for:

- Account creation (password signup, OAuth, passkeys, invitation,
  admin-provisioned)
- Login (password, TOTP, recovery code, passkey, QR cross-device, OAuth
  IdP)
- Session and refresh-token issuance, rotation, and revocation
- Identity verification (IDV) gating for tenants that require it
- Account-level role/status (admin/member/guest, active/locked/
  deactivated/suspended)
- Audit of every state-changing identity event

It is **not**:

- A general-purpose authorisation engine (RBAC for product features
  lives in the consuming product).
- A user-profile / preferences / settings store (the consuming product
  owns its own user-attached data).
- A multi-product "single sign-on across products" service (each
  product deployment is independent).

## The products it's designed for

Two concrete shapes today, both pre-launch. The Project/Tenant model is
designed so any new product fits into one of these shapes. Both run the
**same** code path — the difference is how many tenants form inside a
project, not a boot-time mode.

### Shape 1 — B2C, one project, consumer signups

**Example:** [easyloops.app](https://easyloops.app) (coursera-/
pluralsight-style learning product).

- The product is **one Project.** Every end-user signing up joins that
  project's global user pool, keyed by email (ADR-0003).
- Consumer signups (gmail/outlook/…) do **not** form a tenant — public
  email domains never imply a company. If the product has groups,
  classes, teams etc., those are application-level concepts owned by the
  product (or the separate workspace service), not by identity.
- Signup is self-serve; scale is millions of end-users.

### Shape 2 — B2B, tenants auto-form from email domains

**Example:** [glassa.work](https://glassa.work) (Microsoft-Workspace /
Google-Workspace-style productivity suite — email, productivity tools).

- The product is **one Project per customer-shard** (or a single project
  serving many companies). **Tenants** form automatically: the first user
  of a non-public email domain (`acme.com`) auto-creates a `latent`
  tenant; it becomes `claimed` once that domain is verified (ADR-0004).
- Membership is derived from a verified domain or materialised by an
  explicit invite / admin grant (`tenant_memberships`). There is no
  "organisation" object — a Tenant IS the company entity.
- Onboarding:
  1. **Domain self-service** — a user with a company email signs up; the
     tenant auto-forms; once a domain owner verifies the domain, other
     domain users are members by derivation.
  2. **Invitation** — a tenant admin invites someone by email
     (`InviteUser` / `AcceptInvitation`, backed by `tenant_invitations`).
- Per-request resolution is **Project first, then Tenant**: the project
  is resolved from an `X-Project-Key` credential or the `Host` header (a
  project auth-domain), and the tenant from the authenticated user's
  email domain / membership.

## Tenancy model: Project, Tenant, storage scope

The redesign keeps three "tenant-like" concepts strictly distinct
(ADR-0002; full table in [`docs/redesign/schema.md`](./redesign/schema.md)):

| Concept | Plane | What it is | Cardinality |
|---|---|---|---|
| **Storage scope** | physical | The physical shard the data lives on (a tenant-shard-db tenant, or a Postgres scope). Equals `GATEWAY_DEFAULT_TENANT_ID` for the default project. | 1 per Project |
| **Project** | control plane | A *logical* control-plane isolation entity (a Firebase project). Maps onto exactly one storage scope, but `Project.id != storage_scope_id`. | 1 per storage scope |
| **Tenant** | data plane | A *logical* company entity, auto-formed per verified non-public email domain. | many per Project |

The **Project is the isolation shard** (ADR-0002 inverted the old
"tenant = shard" model). Every data-plane row carries `project_id` as the
leading column of every unique and secondary index; a mandatory
`WHERE project_id = $1` predicate is injected once at the repository
boundary (`RepositoryForProject`). The old `tenant_id`-keyed storage and
the `mode=single | multi` boot flag are gone.

**Resolution is Project-then-Tenant, per request.** The project-resolution
middleware (`internal/middleware/project.go`) resolves the project in this
precedence:

1. the **`X-Project-Key`** credential header (a publishable/secret/mTLS
   key's `public_id`); an explicit key that does not resolve is rejected
   (`Unauthenticated`), never silently downgraded;
2. the request **`Host`**, matched against a `project_auth_domains`
   hostname (a serving hostname like `auth.easyloops.app` — NOT a tenant
   email domain);
3. the **default project** (the zero-config pin: `GATEWAY_DEFAULT_PROJECT_ID`,
   default `"default"`, mapped onto the `GATEWAY_DEFAULT_TENANT_ID`
   storage scope).

Only the **postgres** driver has a control plane (the `projects` /
`project_credentials` / `project_auth_domains` registry); the entdb and
memory drivers run with a nil resolver, so every request pins to the
default project (steps 1–2 are skipped). The resolved project scope rides
the request context; services read it to pick the per-project repository.

Once the project is fixed, the **Tenant** is the user's company entity
inside that project, derived from their verified email domain or from a
materialised `tenant_memberships` row. A user with a `gmail.com`/`outlook.com`
address forms no tenant — public providers are blocklisted at signup,
domain-verify, and derived-membership (`GATEWAY_PUBLIC_EMAIL_DOMAINS`
extends the built-in set).

**The storage layer** (Postgres or tenant-shard-db/EntDB) stores the data.
For EntDB the proto schema in `proto/identity/schema/schema.proto` is
auto-attached by the SDK (ADR-031) on the first `ExecuteAtomic` per shard,
and the server enforces field types, unique constraints, and required
fields atomically. See decision log §15 for that migration.

## Configuration: Project resolution, not a mode flag

There is no boot-time tenancy mode. The relevant knobs:

```
GATEWAY_REPO_DRIVER                 = postgres | entdb | memory  # postgres has the control plane
GATEWAY_DEFAULT_PROJECT_ID          = <string>   # default "default"; the seeded control-plane Project id
GATEWAY_DEFAULT_TENANT_ID           = <string>   # the storage scope the default project maps onto
GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS= <csv>      # serving hostnames seeded (verified) on the default project; first is primary
GATEWAY_ADMIN_API_SECRET            = <secret>   # authenticates control-plane admin RPCs; empty disables them
GATEWAY_PUBLIC_EMAIL_DOMAINS        = <csv>      # extra public domains that never auto-form a tenant
```

On boot, the postgres driver seeds the default `Project` (mapped onto the
`DefaultTenantID` storage scope) and any `DefaultProjectAuthDomains`
(seeded verified, since they are deployer-owned). Additional projects,
credentials, and tenants are provisioned out-of-band by a platform
operator through the control-plane admin RPCs (`AdminCreateProject`,
`AdminCreateProjectCredential`, `AdminCreateTenant`, `AdminAddTenantAdmin`),
which authenticate via the `GATEWAY_ADMIN_API_SECRET` shared secret rather
than a user token. With the secret empty (the default) those RPCs return
`CodeUnimplemented`, so a deployer who never sets it cannot reach them.

### Why one code path, not a mode flag

Same code, same tests, same release. A single-project B2C deployment and a
many-tenant B2B deployment run the identical Project-then-Tenant
resolution; the difference is data (how many tenants auto-form), not a
boot flag. The pre-v1.0 `mode=single | multi` fork is gone (ADR-0002).

## Onboarding flows

Every signup creates a `User` inside the resolved project's data plane,
keyed by email (one identity per person per project — ADR-0003). The repo
layer writes the user under the project scope; there is no separate
storage-layer "tenant member" registration step in the redesigned model.

A **Tenant** forms as a side effect, not via a dedicated signup RPC:

1. A user signs up with a non-public email domain (`acme.com`).
2. If no tenant exists for that domain in the project, a `latent` tenant
   plus a `pending` `domains` row are created.
3. When a domain owner verifies the domain, the tenant becomes `claimed`
   and other users of that domain are members by derivation.

Explicit membership is added by **invitation** (`InviteUser` /
`AcceptInvitation`, backed by `tenant_invitations`) or by a platform
operator's `AdminAddTenantAdmin` grant — both write a `tenant_memberships`
row whose materialised `status` is authoritative over derived membership.

## Identity's role model vs tenant-shard-db's role model

These are different axes that are easy to conflate:

| Layer | What "role" means | Allowed values today |
|---|---|---|
| Identity (`User.Role`) | What can this user *do in the product*? Gate on this when serving identity RPCs (e.g., "only admin can invite users"). | `admin`, `member`, `guest` |
| tenant-shard-db (`TenantMember.Role`) | Is this actor *allowed to write to this tenant at all*? Gate on this at the storage layer only. | `owner`, `admin`, `member` (upstream's enum) |

Every identity user that exists in a tenant is at minimum a
`"member"` at the storage layer. Identity's own admin-promotion never
changes the storage-layer role: an identity-`admin` user is still a
storage-layer `"member"`. The two systems are intentionally
decoupled — identity manages product roles, tenant-shard-db just
manages "can write to this scope or not."

## What the schema lives in

- **Proto schema** — `proto/identity/schema/schema.proto`. Declares
  every EntDB node type (`User`, `RefreshToken`, `PasswordResetToken`,
  `PasskeyCredential`, `OAuthIdentity`, `Session`, …) with field
  types, indexes, single-field uniqueness, composite uniqueness, and
  PII tagging. Generated Go code lives in `gen/go/identity/schema/`.
- **SDK construction** — `internal/repo/entdb/entclient.New(...)` is
  the only entry point identity uses to dial the tenant-shard-db Go
  SDK. It wraps `sdk.NewClient` with `sdk.WithSchema(...)` pre-filled
  by `SchemaMessages()` — one zero-valued instance of every
  `(entdb.node)`/`(entdb.edge)` message in `schema.proto`. The SDK
  reads the proto descriptors at runtime, derives a name-free
  `SchemaDescriptor` + fingerprint, and rides them on the first
  `ExecuteAtomic` per tenant; the server materialises the registry
  in the same WAL event before the data ops (ADR-031). Embedders
  wiring their own `*sdk.DbClient` can pull the same list via
  `entclient.SchemaMessages()`.
- **Repo wiring** — `internal/repo/entdb/` translates between
  identity's domain types (`service.User`, `service.RefreshTokenRecord`,
  …) and the proto messages, then issues operations against the
  tenant-shard-db SDK.
- **tenant-shard-db** — stores opaque `(type_id, field_id, value)`
  tuples on the WAL; it learns identity's schema from the SDK
  auto-attach (above) and enforces field types, single- and composite-
  unique constraints, and required-field validation against it.

The `Organization` / `OrganizationMembership` node types were **removed in
v1.0** (type_ids 33 and 34 are retired and unallocated). The company
entity is now the **Tenant**, and membership is the `tenant_memberships`
table in the per-project data plane — not an EntDB node type. Project,
Tenant, Domain, login-policy, membership, and invitation state live in the
Postgres control plane / data plane described in
[`docs/redesign/schema.md`](./redesign/schema.md).

`OAuthIdentity` (type_id 31) carries a `(entdb.node).composite_unique`
declaration on `(provider, provider_user_id)`. Two concurrent
`CreateOAuthIdentity` calls for the same provider tuple collide on the
server-materialised unique index (ADR-031) — the repository's
pre-query is kept as a fast path for friendly errors and for the
in-memory fake, not as the only enforcement.

## Runtime

Background goroutines launched by `identityserver.Server.Start` and
drained by `Shutdown` (the container binary and any embedding host
control when they run — `New` starts nothing):

- **Async audit flusher** — `pkg/audit` enqueues `AuditEvent` writes
  on a bounded channel and drains them off the auth hot path.
  Configured by `GATEWAY_AUDIT_QUEUE_SIZE`; drops are counted and
  exposed on `/metrics`.
- **Expired-row sweeper** — `internal/app/sweeper.go` walks five
  ephemeral tables (`WebAuthnChallenge`, `EmailVerificationToken`,
  `PasswordResetToken`, `EmailChangeToken`, `LoginChallenge`) every
  `GATEWAY_SWEEPER_INTERVAL_SECONDS` and deletes up to
  `GATEWAY_SWEEPER_BATCH_SIZE` rows per table whose `expires_at` is
  older than `now() - GATEWAY_SWEEPER_GRACE_SECONDS`. Set the
  interval to 0 to disable the sweeper entirely (useful in tests and
  for deployers running their own GC). Deletions and errors are
  counted as `identity_sweeper_deleted_total{node_type}` and
  `identity_sweeper_errors_total{node_type}` on `/metrics`. All three
  shipping backends (memory, Postgres, EntDB) run the real sweep;
  the `ErrSweepNotImplemented` soft-skip remains for any future
  backend whose CRUD methods land ahead of its sweep.

## Deployment topology

- **One identity deployment per product.** glassa.work runs its own
  identity; easyloops.app runs its own. They share zero infrastructure
  beyond what they happen to colocate. There is no "one identity serves
  both products" mode — one deployment can host many **Projects**, but a
  deployment is still per-product, not cross-product.
- Each deployment has its own datastore — **Postgres** (which carries the
  Project/Tenant/Domain control plane) or tenant-shard-db/EntDB.
- A deployment serves every Project on the same code path; projects are
  resolved per request, not chosen at boot.

## What we don't promise (yet)

The Project/Tenant/Domain model is delivered. The items below are
deliberately deferred so future contributors don't try to fit features
that don't belong:

- **In-place upgrade from pre-v1.0 data.** v1.0 is a breaking schema reset
  with no automatic data migration. A legacy-data migration script (to
  materialise one `Project` per old org-shard and backfill `project_id`)
  and Postgres row-level-security hardening are tracked **v1.1**
  follow-ups (ADR-0002, ADR-0007).
- **Cross-product SSO.** Two products running their own identity
  deployments do not share sessions. If we ever need this, it'll be a
  separate service (an IdP that the per-product identities consume).
- **Multi-tenant users.** A single user belonging to two tenants in the
  same project is constrained by the per-project, login-by-email pool
  (ADR-0003); cross-project user federation is not modelled.
- **Workspaces / fine-grained authorization.** Workspaces, workspace
  membership, and ReBAC authorization are a **separate service**
  (ADR-0001). Identity stops at AuthN + Project/Tenant membership.
- **Federated identity migration.** Importing accounts from an existing
  IdP (Auth0, Cognito, custom) is out of scope. Per-product one-shot
  import scripts are fine; a general-purpose migration RPC is not.

## Decision log — read this before changing the tenancy model

The choices below are deliberate. If you're tempted to undo one,
write down what new constraint forced your hand and tell the team
before you ship.

1. ~~**Per-deployment mode flag, not per-request.**~~ **Superseded by
   [ADR-0002](./adr/0002-project-is-the-isolation-shard.md).** The
   `mode=single | multi` boot flag is removed. One code path resolves a
   **Project** (shard), then a **Tenant** (logical), per request.
2. ~~**Identity tenant ↔ tenant-shard-db tenant is 1:1.**~~ **Superseded
   by [ADR-0002](./adr/0002-project-is-the-isolation-shard.md).** The
   isolation shard is now the **Project** (one storage scope per Project,
   `Project.id != storage_scope_id`); many logical Tenants live inside a
   Project. The old "one tenant == one shard, same string" rule is gone.
3. ~~**Single-mode never exposes `OrganizationSignup`.**~~ **Removed in
   v1.0.** `OrganizationSignup` and the `Organization` concept no longer
   exist; the company entity is the **Tenant**, which auto-forms from a
   verified email domain (ADR-0004) rather than being created by an RPC.
4. **Identity's `User.Role` does not flow into
   tenant-shard-db's `TenantMember.Role`.** They evolve
   independently. An identity admin demoted to member shouldn't lose
   their write rights at the storage layer (or vice-versa).
5. **tenant-shard-db enforces identity's schema as of v2 (ADR-031).**
   Through v1.x the storage layer was schemaless and identity's proto
   was a contract with itself; the database accepted any bytes. The
   v2 release inverted that: the SDK auto-attaches identity's
   `SchemaDescriptor` to `ExecuteAtomic` so the server materialises
   the schema and enforces field types, unique constraints, and
   required-fields per tenant. The proto file at
   `proto/identity/schema/schema.proto` is still identity-owned and
   the only place schema changes are made; what changed is that
   adding an invariant there (`required`, `unique`, `composite_unique`)
   now actually binds at the storage layer. See §15 for the migration.
6. **JWT signing is a pluggable `jwt.Signer` interface, default
   file-backed.** Issue #90. The OSS image must work with no external
   KMS dependency, so the default backend reads a JSON keys file on
   disk and reloads on SIGHUP — every deployer can rotate keys without
   running anything else. One in-tree KMS backend ships as the worked
   example (`pkg/jwt/kmsaws`, AWS KMS): chosen over GCP KMS because
   the AWS SDK has the smaller transitive dependency footprint and
   the RSASSA_PKCS1_V1_5_SHA_256 + DIGEST flow maps 1:1 onto RS256
   without an extra envelope. Adding GCP-KMS / Vault / HSM is a
   matter of implementing `jwt.Signer` in a sibling package — every
   caller in this repo speaks only to the interface. A startup
   assertion fails fast if the JWKS endpoint does not include every
   active kid the signer reports, so signing and verification cannot
   drift. Rotation runbook lives at `docs/key-rotation.md`.
7. **Refresh-token revocation: ship both models, config-driven.**
   Different deployers have different tolerances for the access-token
   replay window after `DeleteRefreshTokensForUser`. We ship two
   models behind one knob (`GATEWAY_REVOCATION_MODE`) and pick the
   cheapest safe default (`ttl`).

   - `mode=ttl` (default). When a refresh token is revoked, in-flight
     access tokens stay valid until their natural JWT expiry. Zero
     hot-path cost; no extra repo reads on authenticated requests. A
     hard startup assertion (`GATEWAY_JWT_EXPIRY_SECONDS <= 900`)
     stops a deployer from silently raising the access-token lifetime
     without switching modes. Suitable for low-stakes deployments.

   - `mode=session` (opt-in). Access tokens carry a `sid` claim
     referencing a `Session` row (proto type_id 35); the verification
     middleware reads the row via an in-process cache
     (`GATEWAY_SESSION_CACHE_TTL_SECONDS`, default 60s; 0 = strict).
     `DeleteRefreshTokensForUser` additionally triggers
     `RevokeSessionsForUser`, so the existing replay-detection path
     also kills the access tokens. Same-process revocation is
     synchronous; cross-replica revocation is bounded by the cache
     TTL. Required for deployers handling sensitive data.

   The two paths share no fallback or translation layer — `mode=ttl`
   is the existing zero-cost path with the startup assertion added,
   and `mode=session` is a clean new code path selected by the
   config knob. The decision to ship both flows from identity being
   an OSS server image: the deployer-not-the-vendor picks the
   trade-off. Adding a third model in the future means a new value
   on this knob, not a translation layer wrapping the existing ones.
8. ~~**`OrganizationSignup` rollback is best-effort compensating
   deletes, not transactional.**~~ **Removed in v1.0.** `OrganizationSignup`
   and the on-demand `Admin.CreateTenant` tenant-provisioning flow no
   longer exist; tenants auto-form from verified email domains (ADR-0004)
   and projects are provisioned by the control-plane admin RPCs. The
   half-created-tenant rollback problem this entry described is moot.
9. **tenant-shard-db v1.14.0 alignment — sweeper contract, page
   cap, typed errors.** The v1.14.0 bump (SDK + server image)
   reworked three identity-side seams:

   - **Sweeper contract drops the row count, raw transport stays.**
     v1.14.0 ships `OpDeleteWhere` (#540), a single-RPC predicate-
     based delete that would collapse the existing `QueryNodes +
     batched OpDeleteNode` pair into one round trip. The upstream
     primitive **does not return a deleted-row count by design**
     ("applied, no count for v1"), so the `Repository.DeleteExpired*`
     contract changed from `(deleted int, err error)` to `error`
     across every backend (memory, postgres, entdb). The app-layer
     sweeper now publishes `identity_sweeper_runs_total{node_type}`
     (a per-tick "GC is alive" counter) instead of the v1.13.x
     `identity_sweeper_deleted_total{node_type}` (a rows-deleted
     counter); operators that scrape the old metric must update
     dashboards. Errors continue to bump
     `identity_sweeper_errors_total{node_type}`.
     **The entdb backend keeps the v1.13.x raw-transport
     QueryNodes + ExecuteAtomic(OpDeleteNode) implementation**:
     v1.14.0's typed `entdb.DeleteWhere[T]` requires server-side
     schema-aware resolution of `Filter.Field`, which the
     schemaless server identity runs against rejects with
     "cannot translate filter key 'expires_at' without a schema."
     Tracked upstream at elloloop/tenant-shard-db#545 — once the
     SDK exposes a numeric-field-id escape hatch on `Filter` (or
     the schemaless resolver accepts numeric-string field names
     directly, parallel to how `transport.QueryNodes` already
     does), the entdb sweeper migrates to the single-RPC primitive
     and `expiresAtSweepSpec` plus the QueryNodes batch loop in
     `sdkScope.deleteExpired` go away.
   - **Page-cap drain loops for user-scoped bulk deletes (#530,
     SEC-4).** v1.14.0's server caps `QueryNodes` at 1000 rows
     per call. The three delete-for-user paths
     (`DeleteRefreshTokensForUser`, `DeleteTotpCredentialsForUser`,
     `DeleteRecoveryCodesForUser`) drain in a
     `query → delete → re-query` loop until the next query is
     empty — capped at 100 iterations
     (`bulkDrainMaxIterations`) so a buggy backend cannot pin a
     goroutine. `RevokeSessionsForUser` is the one bulk-mutation
     path that **cannot** drain: it transitions
     `revoked_at_ms = 0 → atMs` rather than deleting the row, so
     already-revoked rows still match `user_id = X` and would
     occupy the cap window forever; a `revoked_at_ms = 0`
     filter on the query is not usable either because proto3
     zero scalars are not serialised on the wire (json_extract on
     an absent field returns NULL, so the predicate matches
     nothing on a freshly-created session). It runs a single
     QueryNodes and revokes every un-revoked row in the cap-sized
     result set; the tail beyond the cap (a user with > 1000
     active sessions) is left for the next revocation call —
     deliberately, because that count is an abuse signal worth
     alerting on rather than silently iterating through. The
     other unbounded list endpoints (`ListPasskeyCredentials`,
     `ListOAuthIdentitiesForUser`, the OAuth dup-checks, the
     duplicate-user safety net `queryUsersByEmail`) are bounded by
     reasonable per-user counts (well under 1000) and accept the
     server-side cap as the implicit limit. If a deployer starts
     hitting the cap on a list endpoint that's a product issue (a
     single user shouldn't legitimately accumulate 1000+ passkeys),
     not a cap-tuning issue.
   - **Typed error matching for `ALREADY_EXISTS` (#533, SEC-5).**
     The v1.14.0 SDK now wraps every gRPC status from the
     transport into a typed error: `*sdk.EntDBError` with
     `Code == "ALREADY_EXISTS"` for plain duplicate detections,
     and `*sdk.UniqueConstraintError` for single-field unique-key
     collisions. Identity's `isAlreadyExists` and
     `dbAdapterIsAlreadyExists` helpers were rewritten to match
     those typed errors via `errors.As`; the v1.13.x raw
     `status.FromError` path is gone, and so are the legacy
     substring matchers ("ALREADY_EXISTS" / "already exists" in
     `err.Error()`). The SEC-5 sanitization only rewrites the
     `codes.Internal` / `codes.Unknown` text on the wire, so
     `tenant not opened` (FailedPrecondition) and the typed
     ALREADY_EXISTS / NOT_FOUND paths the helpers care about are
     preserved verbatim. The
     `TestSEC4_DeleteRefreshTokensForUser_DrainsBeyondQueryCap`
     regression and the typed-error matrix on `TestIsAlreadyExists`
     / `TestDBAdapterIsAlreadyExists` are the unit-level
     guardrails; the conformance suite and `Integration (real
     entdb)` cover the live-server path.

10. **Hosted OAuth flow ships alongside the headless RPCs, off by
    default.** Issue #126. identity offers two OAuth shapes and the
    deployer picks; neither replaces the other.

    - **Headless (existing).** The SPA supplies its own `redirect_uri`
      to `BeginOAuthLogin`, hosts the provider callback page itself,
      and posts the `?code=` back to `OAuthLogin`. The state token
      (`pkg/oauth/state.go`) round-trips the PKCE verifier through the
      SPA. Kept for native/mobile (custom URL schemes can't use a
      hosted web callback cleanly) and for callers who want full
      control. **Its shape is unchanged by this work** — no claim was
      added to the headless state token.

    - **Hosted (new).** `GET /oauth/start/{provider}?return_to=` and
      `GET /oauth/callback/{provider}` are plain `http.Handler` routes
      (not Connect RPCs — the browser is 302-redirected through them).
      They are thin wrappers over the same `BeginOAuthLogin` /
      `OAuthLogin` service internals; there is no forked exchange path.
      The single redirect URI registered with the provider is
      `<identity-origin>/oauth/callback/{provider}`, derived from the
      request so `/start` and `/callback` agree.

    Three deliberate choices inside the hosted flow:

    - **One-time code, not fragment-token or cookie, for the SPA
      handover.** The callback mints an opaque single-use code, stores
      only its SHA-256 hash (proto type_id 36, `OAuthOneTimeCode`)
      bound to the user id with a 60s TTL, and 302-redirects to
      `return_to?code=<otc>`. The SPA exchanges it via the new
      `RedeemOAuthCode` RPC, which atomically consumes the code
      (`ConsumeOAuthOneTimeCode` — the same single-winner CAS shape as
      the refresh-token and QR-login consume paths) and mints a fresh
      token pair through the normal `issueTokens` path. **No token
      material is persisted at rest** — only the user id is stored, so
      a leaked code store yields nothing redeemable after the 60s
      window or a single redeem. Chosen over URL-fragment tokens (leak
      to browser history / `Referer`) and httpOnly cookies (awkward
      cross-origin and unusable for native callers).

    - **`return_to` is a separate signed artifact, not a headless
      state-token claim.** The hosted state token
      (`pkg/oauth/hosted_state.go`, `flow=hosted`) carries provider +
      PKCE verifier + `return_to` and IS the OAuth `state` parameter,
      so the callback recovers everything tamper-proof. It is distinct
      from the headless state token precisely so binding `return_to`
      did not become a breaking change to the headless flow.

    - **`return_to` allowlist, fail-closed, disabled by default.**
      `GATEWAY_OAUTH_ALLOWED_RETURN_URLS` is a comma-separated list of
      exact origins / URL prefixes. A `return_to` is allowed only if it
      equals or is prefixed by an entry; anything else is rejected with
      400 at `/oauth/start` before any provider round-trip. **Empty
      disables the hosted flow entirely** — the `/oauth/*` routes are
      not registered (404) and only the headless RPCs work. This is the
      provider-facing-redirect allowlist that did not exist before:
      with the headless flow the SPA owned the redirect URI as a
      free-form client param; now that identity owns the single
      provider-facing redirect, "where to send the user back" becomes
      an identity-side allowlist instead. The active allowlist is
      logged at startup.

11. **identity is embeddable as a library, not only a container.**
    Issue #127. The full wiring already lived in `internal/app`; it was
    promoted to a public `identityserver` package so a host program can
    `import` identity and mount it into its own Go server instead of
    standing up the dedicated container. See `docs/embedding.md` for the
    API. Three deliberate choices:

    - **Both mount surfaces ship in v1.** `Server.Handler()` returns the
      Connect `http.Handler` (the primary path: gRPC, gRPC-Web, Connect,
      plus health/JWKS, behind the full middleware chain).
      `Server.RegisterGRPC(*grpc.Server)` registers identity natively on a
      host's existing grpc-go server. Connect and grpc-go are different
      stacks, so the native path needs a bridge: `buf.gen.yaml` adds the
      pinned `buf.build/grpc/go:v1.5.1` plugin to emit the grpc-go server
      stub, and `identityserver/grpc_bridge.go` implements that stub by
      delegating every RPC to the same `*connect.Handler` the HTTP surface
      serves. There is **no duplicated handler logic** — one service-layer
      wiring backs both surfaces. The bridge copies incoming gRPC metadata
      into the Connect request headers, so client IP, user-agent and the
      authenticated user id are read the same way over both transports.

    - **The HTTP middleware chain is HTTP-only; native gRPC auth is the
      host's job.** The JWT-verifying auth middleware, CORS, rate-limit,
      health and JWKS live in the `http.Handler` and do not run on the
      native gRPC path. A host mounting via `RegisterGRPC` supplies its
      own server interceptor that verifies the bearer token and forwards
      identity's expected metadata (`x-authenticated-user-id`). This keeps
      the bridge a pure transport adapter rather than re-implementing the
      middleware twice.

    - **Background workers are consumer-controlled.** `New` does no I/O
      beyond construction-time setup (EntDB dial, AWS config, OTel init)
      and starts no goroutines. `Start(ctx)` launches the audit flusher,
      sweeper, and signer SIGHUP reload; `Shutdown(ctx)` drains them and
      releases everything `New` acquired, in reverse order. `cmd/identity`
      is now a thin shim: it loads `OptionsFromEnv()`, calls `New` / `Start`
      / `Shutdown`, and serves `Handler()` — the container behaves
      identically to embedding identity over HTTP, with no wiring
      duplicated between the binary and the library.

12. ~~**Per-request tenant resolution: host/jwt sources, JWT reuses the
    existing `tenant` claim, membership checked at the middleware.**~~
    **Superseded by [ADR-0002](./adr/0002-project-is-the-isolation-shard.md)
    (ADR-0009 covers per-project serving auth-domains).** The
    `internal/middleware/tenant.go` resolver and its
    `GATEWAY_TENANT_RESOLUTION_SOURCES` / `GATEWAY_TENANT_HOST_BASE_DOMAIN`
    config are removed. Resolution is now **Project-then-Tenant**: the
    project-resolution middleware (`internal/middleware/project.go`)
    resolves the project from an `X-Project-Key` credential, the `Host`
    header (a `project_auth_domains` hostname), or the default-project pin,
    and threads a project scope through the request context. The access
    token carries both a `tenant` and a `project` claim, surfaced to the
    project-scope guard via internal headers so the token is verified once.
    The logical Tenant is then derived from the user's verified email
    domain / `tenant_memberships` row.

13. ~~**Tenant-aware invitations: the invitation is the tenant binding,
    redemption mints the identity-layer membership.**~~ **Reworked for
    v1.0.** `Organization` / `OrganizationMembership` are removed.
    `InviteUser` / `AcceptInvitation` now operate on `tenant_invitations`
    and `tenant_memberships` (both `project_id`-scoped, see
    [`docs/redesign/schema.md`](./redesign/schema.md)): an invite is bound
    to a `(project_id, tenant_id)`; redemption resolves-or-creates the
    user by email inside the project's data plane and writes a
    `tenant_memberships` row whose materialised `status` overrides derived
    domain membership. Cross-tenant safety is still structural — the invite
    only exists in its issuing `(project, tenant)` scope.

14. **Passwordless email login (OTP code + magic link), unified by
    email.** Issue #136. A user can authenticate by proving control of an
    email — no password — via a 6-digit one-time code or a clickable magic
    link. Choices:

    - **One account per email, resolved through a single shared helper.**
      The by-email resolve-or-create logic was factored out of
      `upsertOAuthUser` into `resolveOrCreateUserByEmail`
      (`internal/service/auth_login.go`), and OAuth, OTP, and magic link
      all call it. A passwordless login for an address that already has a
      password or OAuth account links to the SAME user — it never mints a
      duplicate. OAuth's behaviour is unchanged: it still does its
      `(provider, sub)` fast-path lookup first, then falls through to the
      shared helper for the email leg, then applies its profile-update and
      identity-link side effects.

    - **Accounts are created only on verify/redeem, never on request.** An
      attacker cannot manufacture accounts for emails they don't control,
      because the account is provisioned only after a valid code is
      submitted or a valid link is clicked. Auto-create is gated by
      `GATEWAY_PASSWORDLESS_SIGNUP_ENABLED` (default true, mirroring
      `GATEWAY_PASSWORD_SIGNUP_ENABLED`). When false, an unknown email
      that proves control still cannot log in — it returns the same
      `Unauthenticated` shape every other failure does, so the endpoint
      reveals nothing about which addresses exist.

    - **Token storage is a small extension of the existing token
      node-type pattern, not a new framework** (decision log discipline,
      AGENTS.md rule 4). `EmailLoginCode` (proto type_id 37) is keyed by
      *email* (unique), because a 6-digit code is not globally unique and
      brute-force protection must find the active code for an address even
      when the guess is wrong (to bump `attempt_count`); a re-request
      overwrites the previous code so at most one is live per inbox.
      `MagicLinkToken` (type_id 38) is keyed by a high-entropy
      `token_hash` (unique), bound to the email and the
      allowlist-validated `return_to` — the same single-use `consumed_at`
      compare-and-set `OAuthOneTimeCode` uses. Both land across all three
      backends (memory, postgres, entdb) with the conformance suite
      extended, and both are swept by the existing GC sweeper.

    - **Spam controls are layered.** Per-IP rate limits on the two Request
      endpoints (`GATEWAY_RATE_LIMIT_PASSWORDLESS_PER_IP`, default 5/min,
      via the existing `PathLimit` middleware); a per-email send cooldown
      reusing `GATEWAY_EMAIL_SEND_COOLDOWN_SECONDS` so one inbox can't be
      flooded; an OTP brute-force cap (`GATEWAY_PASSWORDLESS_CODE_MAX_
      ATTEMPTS`, default 5) that invalidates the code once exhausted; a
      short OTP TTL (`GATEWAY_PASSWORDLESS_CODE_TTL_SECONDS`, default
      300); single-use replay rejection on both arms via the `consumed_at`
      CAS; and anti-enumeration on every Request response (identical
      output regardless of account existence). The magic link's
      `return_to` is validated against the same
      `GATEWAY_OAUTH_ALLOWED_RETURN_URLS` allowlist the hosted OAuth flow
      uses (decision log §10) — the validator
      (`service.ReturnAllowlist`) was moved into the service package so
      both flows share one fail-closed implementation.

    - **Project/Tenant interaction: auto-create the user, but tenant
      membership still requires a verified domain, an invitation, or an
      admin grant.** A passwordless login resolves into the request's
      project (the project-resolution middleware), so the auto-created
      user is created *inside that project's data plane* — one identity
      per person per project (ADR-0003). Auto-create does **not** grant
      tenant membership: the user belongs to a Tenant only by deriving
      from a verified email domain (ADR-0004) or by a `tenant_memberships`
      row written via invitation (§13) or admin grant. They can
      authenticate, but tenant-scoped access is still gated on membership.
      This keeps passwordless login a frictionless front door without
      turning it into an unauthenticated path to tenant membership.

15. **tenant-shard-db v2.0.5 alignment — self-describing schema,
    server-atomic composite uniqueness.** The v2.0.5 bump (SDK +
    server image) reworked two seams that had stayed unchanged across
    every v1.x release:

    - **Schema attach moves into the SDK (ADR-031).** identity no
      longer treats the storage layer as a "schemaless tuple store" —
      `internal/repo/entdb/entclient.New` wraps `sdk.NewClient` with
      `sdk.WithSchema(SchemaMessages()...)`, registering one
      zero-valued instance of every `(entdb.node)`/`(entdb.edge)`
      message in `schema.proto` (26 messages, 22 nodes + 4 edges).
      The SDK derives a name-free `SchemaDescriptor` + fingerprint
      from the proto descriptors; on the first `ExecuteAtomic` per
      tenant it rides them on the call, the server prepends a
      `register_schema` WAL op (establish-or-reject) before the data
      ops, and the registry — type ids, field options, composite-
      unique indexes — is rebuilt deterministically on replay. After
      the server confirms the matching fingerprint the descriptor is
      omitted (lean steady state) and re-attached on `SCHEMA_MISMATCH`.
      Every production entry point (`identityserver.New`) and every
      realentdb test/integration harness goes through `entclient.New`
      so the schema attaches consistently; embedders wiring their own
      `*sdk.DbClient` can pull the same list via
      `entclient.SchemaMessages()`.

    - **Composite uniqueness on `OAuthIdentity` is server-atomic.**
      `OAuthIdentity` declares
      `(entdb.node).composite_unique = { name: "provider_user_id",
      fields: ["provider", "provider_user_id"] }`. Two concurrent
      `CreateOAuthIdentity` calls for the same tuple now collide on
      the server-materialised unique index instead of racing past a
      query-then-create guard (identity#141). The repository keeps a
      pre-query inside `CreateOAuthIdentity` so the *common* "already
      linked" case returns the friendly composite-violation error
      instead of the generic `UniqueConstraintError` from the create
      itself, and so the in-memory fake (which has no schema path)
      keeps the same observable behavior. The conformance suite's
      `ConcurrentDuplicate_OAuthIdentity_SingleRow` subtest asserts
      "exactly one winner among 64 concurrent identical creates" on
      memory, postgres, **and** entdb.

      A `tenant_memberships` row could be promoted the same way (its
      "exactly one (project, tenant, user) row" invariant is
      structurally identical), but real membership writes are
      administrator-/invitation-initiated and naturally serialised, so
      the service-layer pre-check stays sufficient. The path is open if a
      future flow ever needs concurrent-safe membership creates.

    Module path migrated for major-version 2:
    `github.com/elloloop/tenant-shard-db/sdk/go/entdb` →
    `.../sdk/go/entdb/v2` (Go's semantic-import-versioning rule). The
    `entclient` wrapper keeps every call site free of that detail.

If any of those needs to change, update this document in the same
commit as the code change so the next reader sees them in sync.
