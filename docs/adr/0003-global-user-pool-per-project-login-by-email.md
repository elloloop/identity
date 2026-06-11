# ADR-0003 — Global user pool per project; login is always by email

## Status

Accepted (2026-06-11).

**Supersedes** the per-tenant-user portions of decision-log entries §2
("Identity tenant ↔ tenant-shard-db tenant is 1:1" — the part that made a
user belong to exactly one storage tenant) and §13 (the "resolve-or-create by
email *within the resolved tenant*; one human invited into two tenants becomes
two separate identity users" choice) in [`docs/IDENTITY.md`](../IDENTITY.md).

Depends on ADR-0002 (Project is the shard). Sets up ADR-0004
(auto-tenant-by-domain) and ADR-0005 (tenant membership).

## Context

The old model scoped users to the storage *tenant*: one human authenticating
into two tenants became two distinct `User` rows (decision §13, "resolve-or-
create by email is scoped to the resolved tenant"). With the cardinality
inversion (ADR-0002), the shard is now the **Project**, and many logical
Tenants live inside one Project. If users stayed tenant-scoped, a single person
in a B2B Project could fragment into one identity per company-domain — there'd
be no single account to attach passkeys, OAuth links, or a password to, and
"the same person across two departments" would be two logins.

The converged model puts the user pool at the **Project** level and makes
**email the login key**:

> **User**: existing auth/profile fields PLUS `project_id`. Uniqueness becomes
> `(project_id, email)`. One identity per person per project. Login is always
> by email.

The verified fix **H2** pins the email representation:

> Keep the **canonical** email IN the `email` column — do NOT add a separate
> `canonical_email` field. This matches today's `canonicalizeEmail`.

## Decision

1. **The user pool is per Project, not per Tenant.** The `users` table gains
   `project_id`; uniqueness becomes `(project_id, lower(email))`. There is
   exactly **one identity per person per Project**, regardless of how many
   Tenants (company domains) that person touches inside the Project.

2. **Login is always by email.** Authentication resolves the identity by
   `(project_id, email)` first; the Tenant is derived afterward from the
   verified email domain and/or materialized membership (ADR-0004, ADR-0005).
   The Tenant is never an input to authentication — a user proves "I am
   `alice@acme.com` in project P", and the system derives "…and `acme.com` is a
   verified domain of tenant Acme."

3. **Canonical email stays in `email` (H2).** The canonical form
   (`canonicalizeEmail`) is stored directly in `email`; uniqueness uses
   `lower(email)`. No `canonical_email` column is added — that would be a second
   source of truth for a value the column already holds.

4. **Organisation linkage is dropped from the user.** With `Organization` gone
   (ADR-0001), the user row carries no org foreign key. Tenant association is
   expressed only through derived domain-membership or a `tenant_memberships`
   row (ADR-0005).

## Consequences

- **Positive.** One human = one account inside a Project. Passkeys, OAuth
  identities, password, TOTP, and recovery codes all attach to a single user
  row, so a person who belongs to two company domains in the same Project still
  has one login and one credential set.
- **Positive.** Login is uniform: every flow (password, OTP, magic link, OAuth,
  passkey) keys on `(project_id, email)` through the existing
  `resolveOrCreateUserByEmail` helper. The Tenant becomes a *derived* attribute
  of an authenticated identity, not a prerequisite for authenticating.
- **Positive (H2).** Keeping canonical in `email` means no dual-write, no drift
  between `email` and a canonical mirror, and no migration to populate a second
  column.
- **Negative.** A person who is genuinely a different identity in two companies
  but uses the same address in one Project cannot be two users there — they are
  one identity with membership in two Tenants. For products that truly need
  separate identities per company, that is a separate Project (separate shard),
  consistent with ADR-0002.
- **Negative / migration cost.** The old "two users per human across tenants"
  data (if any `mode=multi` deployment produced it) must be de-duplicated into
  one per-Project user during the backfill. Where two rows shared an email in
  what is now one Project, they merge; where they were genuinely separate
  shards, they land in separate Projects and stay separate.
