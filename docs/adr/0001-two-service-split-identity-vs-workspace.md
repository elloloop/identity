# ADR-0001 — Two-service split: identity owns AuthN + tenancy; workspace authz is a separate service

## Status

Accepted (2026-06-11).

Supersedes nothing (foundational ADR for the redesign). It is the premise
the other redesign ADRs (0002–0009) build on.

This ADR, together with ADR-0002 and ADR-0004, **supersedes** decision-log
entry §1 ("Per-deployment mode flag, not per-request") in
[`docs/IDENTITY.md`](../IDENTITY.md): the `single`/`multi` mode knob is
removed.

## Context

Today identity is a single service that tries to be both an
authentication/account service *and* the home of organisation membership.
The `mode=multi` path layered `Organization`, `OrganizationMembership`,
`WorkingGroup`, and the `MEMBER_OF` edge on top of the auth tables, and the
charter ([`docs/IDENTITY.md`](../IDENTITY.md)) already had to carve out
repeated disclaimers that fine-grained authorization "lives in the consuming
product." In practice the boundary leaked: per-request resolution, invitation
redemption, and membership checks all reached into organisation rows that are
really a *workspace* concern, not an *authentication* concern.

The converged target model draws a hard line. Two services, meeting only at
token issuance:

- **identity** owns AuthN, `User`, `Project`, `Tenant`, `Domain`, login
  policies, and tenant-level membership/admin.
- **A separate workspace service** owns workspaces, workspace membership, and
  fine-grained / ReBAC authorization. Identity never models "workspace".

The two never share a table. Identity issues a token; the workspace service
consumes it. That is the entire contract between them.

## Decision

Split the responsibilities along the AuthN / authz seam:

1. **identity keeps**: authentication (password, OAuth, passkeys, OTP, magic
   link, TOTP, recovery, QR), session/refresh issuance and revocation, the
   global `User` pool per project (ADR-0003), `Project` (ADR-0002), `Tenant`,
   `Domain`, `LoginPolicy` (ADR-0006), `TenantMembership`, `TenantInvitation`,
   and platform/tenant admin. Tenant-level membership stays here because it is
   an *authentication-time* fact ("which company does this verified identity
   belong to") that gates token claims.

2. **identity drops and relocates to the workspace service**: `Organization`,
   `OrganizationMembership`, `WorkingGroup`, and the `MEMBER_OF` edge. The dead
   `MEMBER_OF` code is removed, not left behind (project rule: delete dead
   code).

3. **The services meet only at token issuance.** Identity mints the access
   token; the workspace service reads it and applies its own ReBAC. There is no
   shared schema, no cross-service table, no synchronous membership callback
   from workspace into identity.

4. **Workspace membership is OUT; tenant membership is IN** (see ADR-0005 for
   the precise line between the two).

## Consequences

- **Positive.** Identity's surface area shrinks to a coherent
  authentication/account/tenancy service. The repeated "authz lives elsewhere"
  disclaimers in the charter become a structural fact rather than a convention.
  Each service can evolve its data model independently.
- **Positive.** The auth tables no longer carry organisation foreign keys; the
  `mode=multi` org-shard machinery (ADR-0002 replaces it with `Project`) and
  the `OrganizationSignup` entry point (ADR-0004 replaces it with
  auto-tenant-by-domain) are removed wholesale rather than maintained.
- **Negative / migration cost.** Existing `mode=multi` deployments that relied
  on `Organization`/`OrganizationMembership` for product membership must move
  that data to the workspace service. The org-as-shard rows themselves become
  `Project` rows (ADR-0002); the *membership* rows are workspace data.
- **Negative.** "Which workspaces does this user belong to" can no longer be
  answered by an identity query. Callers that need it call the workspace
  service. This is the intended boundary, but it is a new network hop for code
  that previously read `ListOrganizationsForUser`.
- **Follow-up.** The workspace service is out of scope for this repo. This ADR
  only commits identity to *not* modelling workspaces and to deleting the
  relocated tables in the migration sequence (ADR-0007 / schema doc §3).
