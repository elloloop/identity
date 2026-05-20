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
  tenant from the request (see below), then add the new user as a
  `"member"` of the existing tenant.
- **Tenant resolution per request:** the tenant id comes from either
  (a) a subdomain on the request host (`acmecorp.glassa.work` →
  tenant `acmecorp`) or (b) a `tid` claim on the JWT for an already-
  authenticated session. Identity verifies that resolution matches the
  user's tenant membership before serving any RPC. Configuration knobs
  for this layer live alongside `GATEWAY_IDENTITY_MODE` once we
  implement it.

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
   deletes, not transactional.** tenant-shard-db (through v1.14.0
   today) does not expose a `DeleteTenant` primitive, so once
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

If any of those needs to change, update this document in the same
commit as the code change so the next reader sees them in sync.
