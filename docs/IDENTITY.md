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

## One-line summary

Identity is a **reusable, Firebase-style authentication and account
service**. One codebase, deployed per product, configured at boot to
match that product's tenancy model.

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

Two concrete shapes today, both pre-launch. The configuration model is
designed so any new product fits into one of these shapes (or grows a
new third shape we add deliberately, not by accident).

### Shape 1 — B2C single-tenant

**Example:** [easyloops.app](https://easyloops.app) (coursera-/
pluralsight-style learning product).

- The product has **one tenant for its entire lifetime.** Every
  end-user signing up becomes a member of that one tenant.
- There is no notion of "customer organisation" at the identity layer.
  If the product has groups, classes, teams etc., those are application-
  level concepts owned by the product, not by identity.
- Signup is self-serve; scale is millions of end-users.
- Multi-user accounts (an admin managing other users) are out of scope.

### Shape 2 — B2B multi-tenant SaaS

**Example:** [glassa.work](https://glassa.work) (Microsoft-Workspace /
Google-Workspace-style productivity suite — email, productivity tools).

- The product has **many tenants per deployment**, one per customer
  organisation (acmecorp, betaco, …).
- Each customer organisation maps **1:1** to a tenant. Strong data-
  layer isolation: a bug in one tenant's flow can't leak into another.
- Onboarding splits into two flows:
  1. **Organisation signup** — a new customer signs up; we create a
     fresh tenant, register the admin user, mark them as the tenant's
     owner.
  2. **User signup / invitation** — an existing tenant's admin invites
     someone or someone signs up via the tenant's signup link; we add
     them as a member of that existing tenant.
- Per-request tenant resolution is required: a request from
  `acmecorp.glassa.work` operates against tenant `acmecorp`.

## Tenancy model: identity vs tenant-shard-db

The identity service stores its data in [tenant-shard-db
(EntDB)](https://github.com/elloloop/tenant-shard-db). The two have
distinct concepts of "tenant" that must not be confused.

| | Identity layer | tenant-shard-db (EntDB) |
|---|---|---|
| What "tenant" means | A logical account scope for the product | A physical data-isolation unit (per-tenant SQLite + WAL stream) |
| Who creates one | Product wiring or org-signup RPC | `Admin.CreateTenant` on the storage layer |
| When | Per deployment (single) or per customer org (multi) | At identity-layer tenant creation time |
| Membership | Implicit in identity's User row (`tenant_id` scope) | Explicit `Admin.AddTenantMember(tenant, user, role)` rows |

**Mapping is always 1:1.** Every identity-layer tenant is exactly one
tenant-shard-db tenant. We never multiplex multiple identity tenants
into one EntDB tenant or split one identity tenant across two EntDB
tenants. The two layers' tenant identifiers are the same string.

**tenant-shard-db stores opaque `(type_id, field_id, value)` tuples.**
The proto schema (field names, types, indexes, composite-unique
tuples) lives in `proto/identity/schema/schema.proto` and is owned by
identity. As of tenant-shard-db v2 (ADR-031) the Go SDK auto-attaches
that schema to the first `ExecuteAtomic` per tenant, and the server
materialises a per-tenant registry — type ids, field options,
composite-unique indexes — in the same WAL event as the first data
ops. After that the server enforces field types, unique constraints,
and required-fields server-atomically; identity no longer relies on
"check before insert" guards alone for those invariants. See decision
log §15 for the migration and what changed.

tenant-shard-db still doesn't enforce identity's own role/status
semantics, and isn't involved in any identity-layer policy decision
beyond "is this actor allowed to write to this tenant."

## Configuration: the mode knob

A single config knob picks which shape a deployment runs in. Every
other tenant-related decision derives from it.

```
GATEWAY_IDENTITY_MODE = single | multi   # default: single
GATEWAY_DEFAULT_TENANT_ID = <string>     # required when mode=single

# Per-request tenant resolution (mode=multi only; see below):
GATEWAY_TENANT_RESOLUTION_SOURCES = host,jwt   # ordered precedence; default "host,jwt"
GATEWAY_TENANT_HOST_BASE_DOMAIN   = <domain>   # required when "host" is a source
```

### `mode=single` (B2C, easyloops shape)

- **Bootstrap & the first admin.** There is no startup-time admin
  seeding. A fresh deployment has zero admins, and because self-serve
  signup only ever mints `role=member` while every admin RPC requires
  an existing `role=admin` user (`requireAdmin` gates on the identity
  product role — *not* the storage-layer tenant-membership role, which
  is a separate axis), the first admin is created out of the normal
  signup flow by the **`InstanceSignup`** RPC. It is unauthenticated
  but self-disabling: it succeeds only while no admin exists (creating
  the first `role=admin` user in `DefaultTenantID` and returning a
  logged-in session), and returns `FailedPrecondition` forever after —
  so it cannot be replayed to mint additional admins or take over a
  running instance. The tenant row itself is opened lazily on first
  write (the storage layer treats an unopened `DefaultTenantID` as
  "no rows yet").
  - *Operational notes.* Because `InstanceSignup` is unauthenticated
    until the first admin exists, **bootstrap the instance before
    exposing it to untrusted networks** — otherwise a network-adjacent
    caller could win the race and claim admin (inherent to any
    unauthenticated bootstrap; shared with `OrganizationSignup`). It is
    per-IP rate-limited like the other signup endpoints. It always
    provisions a **password** admin and returns a working session even
    when `AuthAllowLocal` is disabled, but in that case the admin must
    use a non-password method (e.g. OAuth on the same email) for
    subsequent logins.
- **Every signup** writes the new User into the same `DefaultTenantID`.
  The repo layer also registers the new user globally in
  tenant-shard-db and adds them as a `"member"` of `DefaultTenantID`
  so that user-as-actor writes (refresh tokens, passkeys, audit events
  scoped to the user) are accepted by the storage layer.
- The `OrganizationSignup` RPC is disabled in this mode (returns
  `Unimplemented`). There is no organisation concept at the identity
  layer.
- **Tenant resolution:** every authenticated request operates on
  `DefaultTenantID`. We don't inspect host header or JWT claims for a
  tenant.

### `mode=multi` (B2B, glassa.work shape)

- **No startup tenant bootstrap.** Tenants are created on demand by
  the `OrganizationSignup` RPC.
- **`OrganizationSignup`** is the entry point: it takes an organisation
  name + the first admin user's credentials. The service creates the
  tenant in tenant-shard-db via `Admin.CreateTenant(slug, displayName)`,
  then writes the identity-layer admin `User` row inside the new
  tenant — the typed `Repository.CreateUser` path already handles
  global-registry registration (`Admin.CreateUser`) + adding the
  user as a `"member"` of the tenant (the v1.12+ actor invariant).
  Identity then promotes the storage-layer role to `"admin"` via
  `Admin.ChangeMemberRole` (a decision independent of identity's
  product role — see decision log §4), persists an `Organization`
  row (proto type_id 33), and links the admin via an
  `OrganizationMembership` row (type_id 34) so it can later answer
  "which organisations does this user belong to?" without re-querying
  the storage layer.
- **Required wiring.** `app.New` rejects `mode=multi` at boot if either
  the `TenantAdmin` (cross-tenant admin handle) or the
  `RepositoryForTenant` (per-tenant repo factory) is missing. The
  entdb driver wires the full `TenantAdmin` against tenant-shard-db's
  `Admin` handle. The postgres driver wires a degenerate
  `PostgresTenantAdmin` (slug uniqueness is enforced in-process plus
  by the `organizations.(tenant_id, slug)` unique index — postgres
  has no cross-tenant registry concept). The memory driver does not
  support `mode=multi`.
- **Subsequent user signups / invitation acceptances** resolve the
  tenant from the request (see below), then add the new user to the
  existing tenant — both as a storage-layer tenant member and, on
  invitation redemption, as an identity-layer `OrganizationMembership`
  member of that tenant's `Organization` with the role from the
  invitation.
- **Tenant resolution per request.** A middleware
  (`internal/middleware/tenant.go`, installed only in `mode=multi`)
  resolves the request's tenant from the configured, ordered sources
  in `GATEWAY_TENANT_RESOLUTION_SOURCES` (default `host,jwt`):
  - **`host`** — a subdomain of `GATEWAY_TENANT_HOST_BASE_DOMAIN`
    (`acmecorp.glassa.work` → tenant `acmecorp` when the base is
    `glassa.work`). Only a single subdomain label maps to a tenant; the
    apex domain and deeper nesting resolve to no tenant.
  - **`jwt`** — the access token's **`tenant`** claim. Identity reuses
    the existing `tenant` claim that every token already carries (the
    org slug in `mode=multi`); it does **not** add a separate `tid`
    claim (decision log entry below).

  The first source that yields a non-empty tenant wins. When both
  sources produce a value they must agree — a host that disagrees with
  the token's `tenant` claim is cross-tenant token reuse and is
  rejected with `PermissionDenied`. The resolver then verifies, via the
  slice-1 `ListOrganizationsForUser` membership view scoped to the
  resolved tenant, that the authenticated caller belongs to that tenant
  before any RPC runs; a non-member is rejected with `PermissionDenied`.
  The resolved tenant (plus a `Repository` scoped to it) is threaded
  through the request context so every handler/service call operates on
  the caller's tenant instead of a hardcoded default.

  Three request classes are handled distinctly:
  - **`OrganizationSignup`** provisions a brand-new tenant; it has no
    tenant to resolve and passes through with no scope (the service
    uses its own per-tenant repository factory).
  - **Unauthenticated, tenant-scoped paths** (e.g. `PasswordLogin`,
    `RequestPasswordReset`) get a tenant scope resolved from the host
    so the service finds the user inside the right tenant, but skip the
    membership check (the caller is proving identity, not asserting it).
  - **Authenticated paths** require a resolved tenant, a matching
    `tenant` claim, and a verified membership before serving.

  Boot is fail-closed: `mode=multi` rejects an empty
  `GATEWAY_TENANT_RESOLUTION_SOURCES`, and rejects a `host` source with
  no `GATEWAY_TENANT_HOST_BASE_DOMAIN`.

  In `mode=single` the middleware is never installed: the tenant is
  always `DefaultTenantID`, a clean constant, with no host/JWT
  inspection and no per-request lookup.

`mode=multi` lands across four feature-bounded slices on
[#93](https://github.com/elloloop/identity/issues/93):

1. **Organization foundation** *(landed)* — proto types, repo
   methods (`CreateOrganization`, `GetOrganization`,
   `GetOrganizationBySlug`, `ListOrganizationsForUser`,
   `AddOrganizationMember`) across all three backends, conformance
   suite coverage, postgres migration `0007_add_organizations`.
2. **`OrganizationSignup` RPC + multi-mode config flag** *(landed)* —
   `GATEWAY_IDENTITY_MODE=single|multi` selected at boot;
   `OrganizationSignup` RPC wired only in `mode=multi` and returns
   `CodeUnimplemented` in `mode=single` (decision log §3). The RPC
   provisions the tenant in tenant-shard-db (`Admin.CreateTenant`),
   then writes the identity-layer Organization + admin User +
   OrganizationMembership rows inside that new tenant via a per-tenant
   `Repository` (factory wired by the binary). The admin user is
   created through the typed repo path (which already handles the
   v1.12+ global-registry registration + default `"member"` tenant
   role), then promoted to `"admin"` at the storage layer via
   `Admin.ChangeMemberRole` — keeping the storage-layer role decision
   independent of identity's product role per decision log §4.
3. **Per-request tenant resolution middleware** *(landed)* —
   `internal/middleware/tenant.go` resolves the request tenant from the
   configured host/jwt sources, verifies the caller's membership of the
   resolved tenant, and threads a tenant-scoped `Repository` + tenant id
   through the request context so every handler scopes to the caller's
   tenant. `mode=single` is unchanged (the resolver is not installed;
   the tenant stays `DefaultTenantID`). See the resolution decision-log
   entry below.
4. **Tenant-aware invitations** *(landed)* — `InviteUser` issues an
   invitation bound to the inviting admin's resolved tenant (the
   invitation row lives only in that tenant's data plane), gated on the
   admin's identity `User.Role`. `AcceptInvitation` redeems the
   invitation inside the host-resolved tenant: it activates the
   resolve-or-create-by-email user and adds them to that tenant's
   `Organization` via `AddOrganizationMember`, carrying the role
   recorded on the invitation. Because the invitation only exists in its
   issuing tenant, an invite minted for tenant A is invisible to tenant
   B's scoped repository — a token replayed under B's host fails the
   lookup and is rejected (`Unauthenticated`), and a tenant-A admin
   cannot invite into B. `mode=single` is unchanged: no `Organization`
   exists there, so redemption adds no membership. This slice completes
   `mode=multi` (`closes #93`). See decision log §13.

### Why a flag, not separate binaries

Same code, same tests, same release. Two deployments differ only in
config. The product chooses its shape; identity doesn't fork.

## Onboarding flows (the things you'll be tempted to write twice)

The repo layer (`internal/repo/entdb/`) treats every signup the same:
on `CreateUser`, after the tenant-scoped User row commits, it also:

1. Registers the new user in tenant-shard-db's global user registry
   (`Admin.CreateUser`), and
2. Adds the user as a member of the scoped tenant
   (`Admin.AddTenantMember(scope.tenantID, userID, "member")`).

This works the same in both modes. The *mode* only changes which
tenant id the scope holds — in single mode it's always
`DefaultTenantID`; in multi mode it's resolved per request from the
host/JWT.

`OrganizationSignup` (multi mode only) sits one layer above:

1. Resolve / generate the new tenant id.
2. Call `Admin.CreateTenant(tenantID, orgDisplayName)`.
3. Then dispatch into the same per-user onboarding flow above with
   role `"admin"` (or whichever role upstream models org-owners as).

Single-mode first-admin bootstrap (`InstanceSignup`) is structurally a
trimmed `OrganizationSignup`: it skips tenant creation (the tenant is
the configured `DefaultTenantID`) and the Organization/Membership rows
(single mode has no organisation concept), guards on "no admin exists
yet" (`Repository.HasAnyAdmin`) instead of slug uniqueness, then runs
the same per-user onboarding with role `"admin"` and issues a session.

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
  every node type (`User`, `RefreshToken`, `PasswordResetToken`,
  `PasskeyCredential`, `Organization`, `OAuthIdentity`, …) with field
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

The `Organization` node (type_id 33) and `OrganizationMembership` node
(type_id 34) are the identity-layer storage for `mode=multi`
deployments. The `Organization.slug` field is the URL-safe identifier
deployers expose to end-users (e.g. `acmecorp.example.com` → slug
`acmecorp`); identity reuses the slug AS the tenant-id passed to
`Admin.CreateTenant`, so slug uniqueness collisions surface at signup
time as an EntDB error. `OrganizationMembership` is a per-tenant
secondary index keyed on `(organization_id, user_id)` that identity
uses for `ListOrganizationsForUser`; the tenant-shard-db `TenantMember`
table remains the storage-layer source of truth for write
authorisation.

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
  beyond what they happen to colocate. There is no "one identity
  serves both products" mode — that's what `OrganizationSignup` looks
  like *within* a multi-mode deployment, not *across* deployments.
- Each deployment has its own tenant-shard-db backend (Postgres in
  pre-launch; EntDB once the migration completes).
- Each deployment is configured for exactly one mode at boot.

## What we don't promise (yet)

`mode=multi` is fully delivered as of [#93](https://github.com/elloloop/identity/issues/93):
on-demand tenant provisioning (`OrganizationSignup`), per-request
tenant resolution, and tenant-aware invitations all ship. The items
below are features beyond that baseline that this service deliberately
defers, so future contributors don't try to fit features that don't
belong:

- **Cross-product SSO.** Two products running their own identity
  deployments do not share sessions. If we ever need this, it'll be a
  separate service (an IdP that the per-product identities consume),
  not a flag on this one.
- **Multi-tenant users.** A single user belonging to two organisations
  inside the same multi-mode deployment is not modelled. We add it
  when a concrete product requires it.
- **Federated identity migration.** Importing accounts from an
  existing IdP (Auth0, Cognito, custom) is out of scope. Per-product
  one-shot import scripts are fine; a general-purpose migration RPC
  is not.
- **Session-based revocation in `mode=multi`.**
  `GATEWAY_REVOCATION_MODE=session` is not yet tenant-scoped — the
  session cache + `GetSessionBySid` lookup run against the boot-time
  (`DefaultTenantID`) repository, while `mode=multi` sessions live in
  per-request tenants. The config validator rejects the combination at
  boot rather than silently looking sessions up in the wrong tenant;
  `mode=multi` deployments use the default `mode=ttl` revocation.
  Tenant-scoping the session lookup is a future slice.

## Decision log — read this before changing the tenancy model

The choices below are deliberate. If you're tempted to undo one,
write down what new constraint forced your hand and tell the team
before you ship.

1. **Per-deployment mode flag, not per-request.** Mixing single and
   multi semantics in one running service makes auth surface
   reasoning impossible. Each deployment is one or the other.
2. **Identity tenant ↔ tenant-shard-db tenant is 1:1.** No
   multiplexing, no splitting. The boundaries align so debugging and
   data-export tools stay simple.
3. **Single-mode never exposes `OrganizationSignup`.** Even if a
   single-mode deployment has only one tenant, the RPC stays
   `Unimplemented` so a misconfigured client can't accidentally
   create a second one.
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
8. **`OrganizationSignup` rollback is best-effort compensating
   deletes, not transactional.** tenant-shard-db does not expose a
   `DeleteTenant` primitive (true through at least v2.0.5), so once
   `Admin.CreateTenant`
   has succeeded the tenant exists in the storage layer until an
   operator removes it out-of-band. Identity's `OrganizationSignup`
   rolls back what it can — the per-tenant `Admin.RemoveTenantMember`
   call — and leaves the empty tenant in place. The next signup
   attempt with the same slug fails at `Admin.CreateTenant` with
   `AlreadyExists`, which the caller surfaces to the deployer's
   signup UI. We accepted this over a "tenant in pending state"
   marker because (a) the empty-tenant footprint is tiny and
   (b) introducing the marker would require a new schema-aware
   primitive upstream — a larger change than is justified for a
   failure mode that should be rare. If a deployer needs reliable
   cleanup of half-created tenants, that's a candidate upstream
   feature on tenant-shard-db, not an identity-layer workaround.
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
     `ListOAuthIdentitiesForUser`, `ListOrganizationsForUser`,
     the OAuth dup-checks, the duplicate-user safety net
     `queryUsersByEmail`) are bounded by reasonable per-user
     counts (well under 1000) and accept the server-side cap as
     the implicit limit. If a deployer starts hitting the cap on
     a list endpoint that's a product issue (a single user
     shouldn't legitimately accumulate 1000+ orgs or passkeys),
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

12. **Per-request tenant resolution: host/jwt sources, JWT reuses the
    existing `tenant` claim, membership checked at the middleware.**
    Issue #93 slice 3. `mode=multi` resolves the request tenant in a
    middleware (`internal/middleware/tenant.go`) from the configured,
    ordered sources in `GATEWAY_TENANT_RESOLUTION_SOURCES` (default
    `host,jwt`). Choices:

    - **No new `tid` claim — reuse the existing `tenant` claim.** Every
      access token already carries a `tenant` claim (the org slug in
      `mode=multi`). Adding a parallel `tid` claim would be two fields
      meaning the same thing, with a window for them to disagree. The
      `jwt` resolution source reads the existing `tenant` claim; the
      auth middleware surfaces the verified value to the resolver via an
      internal request header so the token is not verified twice.

    - **Host wins by default, but host and JWT must agree.** The
      default precedence is `host,jwt`: the host subdomain is the
      user-facing tenant boundary, so it is consulted first. When both a
      host tenant and a token tenant are present they must be equal — a
      host that disagrees with the token's tenant is cross-tenant token
      reuse and is rejected (`PermissionDenied`) rather than silently
      preferring one. A deployer that fronts identity without per-tenant
      hostnames sets `GATEWAY_TENANT_RESOLUTION_SOURCES=jwt`.

    - **Membership is verified in the middleware, before the handler.**
      Once a request is authenticated and a tenant resolved, the
      middleware checks the caller is an organisation member of the
      resolved tenant (slice-1 `ListOrganizationsForUser`, scoped to
      that tenant) before any RPC runs; a non-member gets
      `PermissionDenied`. Putting the check at the chain boundary keeps
      every handler free of repeated membership boilerplate and makes
      the cross-tenant guarantee one auditable place. Unauthenticated,
      tenant-scoped paths (login, password reset) get a tenant scope but
      skip the member check — the caller is proving identity, not
      asserting it — and `OrganizationSignup`, which creates the tenant,
      is resolved past entirely.

    - **The resolved tenant rides the request context; single mode stays
      a constant.** The middleware injects a tenant id + a tenant-scoped
      `Repository` into the context; services read it via small accessors
      (`s.tenantID(ctx)` / `s.repo(ctx)`) that fall back to the boot-time
      `DefaultTenantID` / boot Repository when no scope is present. In
      `mode=single` the resolver is never installed, so that fallback is
      always taken — the single-tenant path is unchanged, with no
      host/JWT inspection. Boot is fail-closed: `mode=multi` rejects an
      empty source list or a `host` source with no base domain.

13. **Tenant-aware invitations: the invitation is the tenant binding,
    redemption mints the identity-layer membership.** Issue #93 slice 4
    (completes `mode=multi`). Choices:

    - **No `tenant_id` field on the invitation — the storage scope IS
      the binding.** Like `Organization` (decision log §2: a row exists
      only inside its own tenant's data plane), a `UserInvitation` lives
      in the issuing tenant's scope. `InviteUser` writes it under the
      inviting admin's resolved tenant (`s.tenantID(ctx)`); a duplicate
      `tenant_id` payload field would be a second source of truth that
      can drift from the scope it already lives in. This makes
      cross-tenant safety structural rather than a checked invariant: an
      invitation minted for tenant A is simply not present in tenant B's
      scoped repository, so a token replayed under B's host fails
      `FindInvitationByHash` and is rejected (`Unauthenticated`) before
      any user is touched, and a tenant-A admin cannot reach into B.

    - **Redemption adds the identity-layer `OrganizationMembership`,
      not just the storage member row.** `InviteUser` already registers
      the invitee as a storage-layer tenant member (the v1.12+ actor
      invariant). `AcceptInvitation` additionally makes them an
      `OrganizationMembership` member of the resolved tenant's
      `Organization` (found by slug == tenant id, §2), with the role
      recorded on the invitation (identity's product role, independent
      of the storage role per §4). Without this the redeemed user could
      authenticate but would fail the middleware's membership check
      (slice 3) on their next request, so the membership add and the
      session issuance must be one atomic-from-the-caller operation —
      redemption fails closed if the membership cannot be written.

    - **Resolve-or-create by email is scoped to the resolved tenant.**
      Redemption looks the user up by the invitation's `user_id` then by
      email *within the resolved tenant's repository*. A single human
      who is invited into two tenants becomes two separate identity
      users — one per tenant — consistent with the 1:1 identity↔tenant
      boundary (§2) and the deliberately-deferred "multi-tenant users"
      item above. There is no global user lookup at redemption time.

    - **`mode=single` is unchanged.** Single-mode deployments never
      provision an `Organization`, so the org lookup returns nothing and
      redemption adds no membership — the single-tenant invitation flow
      is exactly as it was before this slice.

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

    - **mode=multi interaction: auto-create the user, but membership still
      requires an invitation or org-signup.** A passwordless login
      resolves into the request's tenant (the slice-3 resolution
      middleware), so the auto-created user is created *inside that
      tenant's data plane* — consistent with the 1:1 identity↔tenant
      boundary (§2): one human authenticating passwordlessly into two
      tenants becomes two separate identity users, one per tenant. But
      auto-create does **not** grant organisation membership: an
      auto-created user in `mode=multi` is not a member of any
      `Organization` until they accept an invitation (§13) or complete
      `OrganizationSignup` (§3). They can authenticate, but the membership
      check in the resolution middleware still gates tenant-scoped access.
      This keeps passwordless login a frictionless front door without
      turning it into an unauthenticated path to org membership. In
      `mode=single` there is no `Organization`, so the auto-created user
      is simply a normal user of the one tenant.

15. **tenant-shard-db v2.0.5 alignment — self-describing schema,
    server-atomic composite uniqueness.** The v2.0.5 bump (SDK +
    server image) reworked two seams that had stayed unchanged across
    every v1.x release:

    - **Schema attach moves into the SDK (ADR-031).** identity no
      longer treats the storage layer as a "schemaless tuple store" —
      `internal/repo/entdb/entclient.New` wraps `sdk.NewClient` with
      `sdk.WithSchema(SchemaMessages()...)`, registering one
      zero-valued instance of every `(entdb.node)`/`(entdb.edge)`
      message in `schema.proto` (25 messages, 21 nodes + 4 edges).
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

      `OrganizationMembership` could be promoted the same way (its
      "exactly one (org, user) row" invariant is structurally
      identical), but real membership writes are administrator-
      initiated and naturally serialised, so the service-layer pre-
      check stays sufficient. The path is open if a future flow ever
      needs concurrent-safe membership creates.

    Module path migrated for major-version 2:
    `github.com/elloloop/tenant-shard-db/sdk/go/entdb` →
    `.../sdk/go/entdb/v2` (Go's semantic-import-versioning rule). The
    `entclient` wrapper keeps every call site free of that detail.

If any of those needs to change, update this document in the same
commit as the code change so the next reader sees them in sync.
