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

**tenant-shard-db is schemaless.** It stores opaque
`(type_id, field_id, value)` tuples; the proto schema (field names,
types, indexes) lives in `proto/identity/schema/schema.proto` and is
known only to identity. tenant-shard-db doesn't validate field shapes,
doesn't enforce identity's own role/status semantics, and isn't
involved in any identity-layer policy decision beyond "is this actor
allowed to write to this tenant."

## Configuration: the mode knob

A single config knob picks which shape a deployment runs in. Every
other tenant-related decision derives from it.

```
GATEWAY_IDENTITY_MODE = single | multi   # default: single
GATEWAY_DEFAULT_TENANT_ID = <string>     # required when mode=single
```

### `mode=single` (B2C, easyloops shape)

- **At startup**, the service ensures `DefaultTenantID` exists in
  tenant-shard-db (idempotent bootstrap: create tenant if missing,
  create system user if missing, add system user as admin member of
  the tenant if missing).
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
  tenant in tenant-shard-db, registers the admin user globally, adds
  them as `"admin"` (or `"owner"` if upstream supports the distinction)
  of the new tenant, and creates the identity-layer admin User row
  scoped to the new tenant. Identity also persists an `Organization`
  row (proto type_id 33) and an `OrganizationMembership` row
  (type_id 34) so it can later answer "which organisations does this
  user belong to" without re-querying the storage layer.
- **Subsequent user signups / invitation acceptances** resolve the
  tenant from the request (see below), then add the new user as a
  `"member"` of the existing tenant.
- **Tenant resolution per request:** the tenant id comes from either
  (a) a subdomain on the request host (`acmecorp.glassa.work` →
  tenant `acmecorp`) or (b) a `tid` claim on the JWT for an already-
  authenticated session. Identity verifies that resolution matches the
  user's tenant membership before serving any RPC. Configuration knobs
  for this layer live alongside `GATEWAY_IDENTITY_MODE` once we
  implement it.

`mode=multi` is being landed in feature-bounded slices on
[#93](https://github.com/elloloop/identity/issues/93):

1. **Organization foundation** *(landed)* — proto types, repo
   methods (`CreateOrganization`, `GetOrganization`,
   `GetOrganizationBySlug`, `ListOrganizationsForUser`,
   `AddOrganizationMember`) across all three backends, conformance
   suite coverage, postgres migration `0007_add_organizations`. The
   `GATEWAY_IDENTITY_MODE` flag is **not yet wired**, and the
   `OrganizationSignup` RPC is **not yet implemented**.
2. `OrganizationSignup` RPC + multi-mode config flag.
3. Per-request tenant resolution middleware.
4. Tenant-aware invitations.

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

Single mode startup bootstrap is structurally the same as the
`OrganizationSignup` shape, except it runs once at boot rather than
per-request, and it uses the configured `DefaultTenantID` rather than
a user-supplied one.

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
  `PasskeyCredential`, `Organization`, …) with field types, indexes,
  uniqueness, and PII tagging. Generated Go code lives in
  `gen/go/identity/schema/`.
- **Repo wiring** — `internal/repo/entdb/` translates between
  identity's domain types (`service.User`, `service.RefreshTokenRecord`,
  …) and the proto messages, then issues operations against the
  tenant-shard-db SDK.
- **tenant-shard-db** — stores opaque tuples. It does not need a copy
  of our schema (the database is schemaless by design).

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

When v1.12+ of the Go server reimplementation lands a schema-loader
hook, identity will register the proto-extracted schema with the
server at startup. Until then, identity targets the Python server
image (≤ 1.10.x) which doesn't require client-side schema
registration. See `docs/v1.12-migration.md` (TODO) for the migration
plan when upstream is ready.

## Runtime

Background goroutines started by `app.New` and stopped by the
returned shutdown func:

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

Things this service deliberately defers, so future contributors
don't try to fit features that don't belong:

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
5. **tenant-shard-db remains schemaless from identity's view.** The
   proto schema is identity's contract with itself; the database
   never validates against it. When tenant-shard-db ships
   schema-extraction-and-loading, identity uploads the schema as a
   bootstrap step, but the database still treats its content as
   opaque storage.
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

If any of those needs to change, update this document in the same
commit as the code change so the next reader sees them in sync.
