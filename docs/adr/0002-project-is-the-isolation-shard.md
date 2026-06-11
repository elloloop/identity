# ADR-0002 — Project is the isolation shard (storage cardinality inverts)

## Status

Accepted (2026-06-11).

**Supersedes** decision-log entry §1 ("Per-deployment mode flag, not
per-request") and §2 ("Identity tenant ↔ tenant-shard-db tenant is 1:1") in
[`docs/IDENTITY.md`](../IDENTITY.md). The `mode=single | multi` knob is removed
and the storage cardinality inverts: the **Project** is the shard, not the
tenant.

Depends on ADR-0001 (two-service split). Sets up ADR-0003 (global user pool per
project) and ADR-0009 (per-project serving auth-domains + Host resolution).

## Context

Three "tenant-like" concepts were conflated in the old model:

- The **storage scope** — the physical tenant-shard the data lives on (in the
  old single mode, `DefaultTenantID`).
- The **logical account scope** the product reasons about.
- The **company entity** a B2B customer maps to.

The old decision §2 forced "identity tenant ↔ storage tenant is 1:1, same
string". That made the *tenant* the unit of physical isolation, which is wrong
for the converged model: it means a single B2C product (millions of end-users,
one tenant) cannot grow per-company tenants without re-sharding, and a B2B
product's "company" and "shard" are forced to be the same object.

The verified fix **B1** inverts the cardinality:

> **PROJECT = shard (not tenant = shard).** `RepositoryForTenant` →
> `RepositoryForProject`. Per-request resolution resolves the **PROJECT**
> (shard) first, then the **TENANT** (logical) from the email domain /
> membership.

## Decision

Adopt three distinct concepts and make **Project** the isolation shard:

1. **Storage scope** (physical): a tenant-shard. In single deployments it
   equals `DefaultTenantID`. One storage scope per Project.

2. **Project** (control plane, logical): a control-plane isolation entity — a
   Firebase project. Exactly **one Project per storage scope**. The `Project`
   row carries `storage_scope_id` (UNIQUE), the shard it maps onto. The default
   project maps onto `DefaultTenantID` but **is not equal to it** (`Project.id
   != storage_scope_id`).

3. **Tenant** (data plane, logical): a company entity, auto-formed per verified
   non-public email domain (ADR-0004). **Many Tenants per Project.**

Mechanics:

- `RepositoryForTenant` is renamed/replaced by **`RepositoryForProject`**. The
  per-request flow resolves the **Project (shard) first** — by credential
  `public_id` (publishable/secret/mTLS) OR by `Host` header →
  `project_auth_domains.hostname` (ADR-0009) — and only then resolves the
  **Tenant** (logical) from the authenticated user's email domain / membership.

- **`mode=multi` is removed.** Each existing `mode=multi` org-shard becomes its
  own **Project**. Greenfield deployments use the **default project**, seeded on
  boot mapped to `DefaultTenantID` (a logical `Project` entity, not equal to the
  storage id).

- `project_id` is the leading column of every unique and secondary index on
  every data-plane table; the mandatory `WHERE project_id = $1` predicate is
  injected once at the `RepositoryForProject` boundary (see ADR-0007 for the
  Postgres datastore decision and the RLS defense-in-depth).

## Consequences

- **Positive.** A single B2C product is one Project with many auto-formed
  tenants; a B2B platform is one Project per customer-shard with tenants inside.
  The old "one tenant == one shard, same string" constraint is gone, so the
  physical-isolation decision is decoupled from the company-entity decision.
- **Positive.** The deployment no longer forks on a boot-time `mode` flag. One
  code path resolves Project-then-Tenant for every request. This also removes
  the `mode=single`/`mode=multi` config validator branches and the
  multi-only middleware install.
- **Negative / migration cost.** Every kept auth/data table's leading
  `tenant_id` column is renamed to `project_id` and its uniqueness re-scoped to
  `(project_id, …)`. That backfill is sequenced after the additive new-table
  migration (ADR-0007 / schema doc §2.3, §5).
- **Negative.** Operators with existing `mode=multi` org-shards must materialise
  one `Project` row per shard (with the shard id as `storage_scope_id`) and a
  fresh, distinct `Project.id`. The mapping is mechanical but must be done as a
  data migration, not silently inferred.
- **Follow-up.** ADR-0003 defines the user pool *inside* a Project; ADR-0009
  defines Host-based Project resolution; ADR-0008 defines how admin APIs
  authenticate against the control plane.
