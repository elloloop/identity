# Identity redesign — implementation plan (PR-by-PR)

> **Original design document — kept as a design record, not find/replaced.**
> Where this references `EntDB` or `proto/identity/schema/schema.proto`, the
> implementation shipped as the SQLite driver (`internal/repo/sqlite/`) and
> the single proto is `proto/identity/v1/identity.proto`.

Sequenced, shippable slices to take the Project/Tenant/Domain redesign
(`docs/redesign/schema.md`) to done. Each slice is **one PR**, tests-first, and
goes through the AGENTS.md review-gate before merge. The order keeps every PR
independently shippable and stages the risky storage-model inversion with
expand → backfill → contract so live data is never at risk.

**Postgres is the primary datastore.** Each slice lands on all wired drivers
where it touches the shared `service.Repository`; control-plane stores are
Postgres-first (the registry of projects is a control-plane concern, not a
per-tenant one).

## Already shipped / in flight

| # | Slice | Status |
|---|---|---|
| 0a | `identity migrate` subcommand + DB-migrations docs | PR #195 |
| 0b | Foundation: schema + ADRs + migration `0013` (all new tables) | PR #196 |
| 1 | Control-plane **ProjectStore** (postgres): projects / credentials / auth-domains CRUD + Host→project resolution | in progress (stacked on #196) |

## Remaining slices

1. **Control-plane ProjectStore** *(in flight)* — Go types + postgres store over the
   `0013` control-plane tables; `CreateProject`, `GetProjectByID/StorageScope`,
   credential create/get-by-public-id/revoke, auth-domain create/list/get-by-hostname.
   Additive; does not touch `service.Repository`. Tests via the dockerpostgres suite.

2. **Project bootstrap + default project** — on boot, idempotently seed the default
   `Project` mapped to `GATEWAY_DEFAULT_TENANT_ID` (logical entity ≠ the storage id);
   config `GATEWAY_DEFAULT_PROJECT_ID`; `app.New` boot invariant. Wire a platform
   store handle into `Deps`.

3. **Project resolution (key + Host)** — middleware that resolves the request's
   Project from the publishable/secret key OR the `Host` header (via
   `project_auth_domains`), ahead of tenant resolution. Single project → pinned
   default (zero-config). Inject the resolved `project_id` into the request scope.
   Tests: key resolution, Host resolution, unknown host → default/deny, single-project
   pinning.

4. **Per-project token + link context** — carry `project_id` in the access-token
   claims; build email/OAuth/magic-link URLs and cookie domains from the project's
   **primary auth-domain**; per-project CORS allow-origins. (This is what makes a
   user see a product-branded domain.) Tests across mode=single (default project) and
   multi-project.

5. **Public-email-domain blocklist** — typed config + `config.IsPublicEmailDomain`
   (canonical punycode), consumed at the three gates (signup tenant-formation, domain
   verify, derived membership). Block gmail/outlook/yahoo/etc + disposable.

6. **Tenant + Domain entities (repo + service)** — `TenantStore`/`DomainStore`
   (postgres + memory + conformance); auto-form a `latent` Tenant from the first user
   of a non-public verified-able domain at signup; domain verification (DNS TXT /
   email) flips `latent`→`claimed` and makes the verifier `owner`. RPCs:
   `CreateDomain`/`VerifyDomain`/`ListTenantDomains`.

7. **Login policy** — `LoginPolicy` store + the login path consulting it for a user
   whose email domain ∈ a claimed tenant (allowed methods, SSO-required + connection,
   2FA-required); controls HOW, never WHETHER; fail-safe to email_otp on empty.

8. **Tenant membership + invitations** — `TenantMembership` (materialized rows +
   derived domain membership with the verified+claimed-only / row-overrides-derived
   precedence); `TenantInvitation` (atomic revoke-then-insert for one-open-invite);
   retire `UserInvitation` (M8). RPCs: invite/accept/list/remove; the `isMember`
   middleware rewritten off `TenantMembership`, not `ListOrganizationsForUser`.

9. **Drop Organization / WorkingGroup** — remove `Organization`,
   `OrganizationMembership`, `WorkingGroup`, the `MEMBER_OF` edge and its now-dead
   drain code, and `OrganizationSignup`; migration to drop the postgres tables (after
   data export for the workspace service). Update all three drivers + conformance.

10. **The storage-model inversion (B1)** — the consequential slice, staged:
    - **10a expand**: add nullable `project_id` to every existing data-plane table
      (migration), defaulting to the default project; dual-read tolerant.
    - **10b backfill**: data migration sets `project_id` = default project on all
      existing rows; rename `RepositoryForTenant` → `RepositoryForProject`; per-request
      resolution resolves PROJECT (shard) first, TENANT (logical) second.
    - **10c contract**: make `project_id` NOT NULL + leading column of every
      unique/secondary index; uniqueness → `(project_id, …)`; remove `mode=multi`
      (replaced by Project); add Postgres RLS as defense-in-depth.
    Existing `mode=multi` deployments: each org-shard becomes its own Project.

11. **Control-plane admin APIs** — `CreateProject` / mint-credential / create-tenant /
    create-tenant-admin, authenticated by mTLS client cert or short-lived secret
    (least-privileged per caller), served on an **optional internal-only port**
    deployers can bind private or disable. `InstanceSignup` stays for the
    single-project first-admin bootstrap.

12. **Project auth-domain verification + custom domains** — DNS/ownership verification
    for a project hostname; per-domain TLS guidance (wildcard vs ACME). Operational
    doc in `docs-site`.

13. **Docs sweep** — fold the shipped model into the Astro `docs-site` (Concepts,
    Installation, Auth) replacing the tenant=shard/mode=multi pages; factual tone.

## Conventions for every slice

- Tests-first; unit tests run always, real-Postgres e2e gated on
  `GATEWAY_TEST_POSTGRES_DSN` / the dockerpostgres testcontainers suite.
- A schema change that touches live data uses expand → backfill → contract across
  releases; back up before destructive prod migrations.
- New shared-`Repository` methods land on memory + postgres + entdb (until entdb
  retires from identity) and the conformance suite, with identical semantics.
- One review-gate per PR; clear blocking findings before merge.
