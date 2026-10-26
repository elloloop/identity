# ADR-0018 — Self-service tenants, and choosing a tenant for a token

## Status

Accepted (2026-10-26). Off by default: a project turns it on with
`tenants.self_service` in its `config_json`, and the default project with
`GATEWAY_SELF_SERVICE_TENANTS_ENABLED`.

**Amends** ADR-0001, ADR-0002 and ADR-0004, as listed under
[What this amends](#what-this-amends). It supersedes none of them.

## Context

Until now a tenant came into being in one of two ways: auto-formed from the
first signup on a non-public email domain, claimed once that domain was
verified (ADR-0004), or created by an operator through the admin RPCs. A group
of people with no company domain behind it had no way to get one: people on a
public mail provider, a team that does not control its organisation's domain,
a group drawn from several organisations. Without a tenant such a group has no
tenant membership, no invitations and no tenant-scoped token, so a product
built on identity has to model the group itself and keep a second membership
list outside identity.

Separately, an access token's `tenant` claim always carried the deployment's
default storage key. A person who belonged to several tenants could not get a
token that named any one of them.

## Decision

1. **A signed-in person may create a tenant they own.** `CreateTenant(name)`
   creates a tenant and the caller's active `owner` membership (source
   `created`) in one transaction. The tenant is `claimed` from creation, has
   no domain, and records its creator in `tenants.created_by`. Creation is
   bounded per user per window and per client IP, and refused to anonymous,
   agent, merged and inactive accounts. `ListMyTenants` lists the claimed
   tenants the caller is an active member of, with their role.

2. **A refresh may choose the token's tenant.** `RefreshToken` takes an
   optional `tenant_id`. It is granted only to an active member of a claimed
   tenant in the session's project; the resulting access token carries that
   tenant in its existing `tenant` claim. A refused choice issues nothing and
   leaves the refresh token unspent. Omitting it keeps the default. The
   choice is made again on every refresh.

3. **The claim is re-checked where identity can.** Identity's HTTP middleware
   accepts a token whose `tenant` is the default or a claimed tenant of the
   token's project, reading the tenant's status on every request, so a
   suspended tenant's tokens are refused at once. A membership that ends
   takes effect at the next refresh, within one access-token lifetime.

4. **A registered domain captures nothing until it is verified.** Once anyone
   can be a tenant admin, registering a domain must not be a way to collect
   that domain's signups. Several tenants may hold a pending claim on one
   domain; the tenant that verifies it holds the only verified row; signups
   join only the verified tenant or the latent tenant auto-formation made.
   The DNS TXT challenge names the tenant as well as the project, so the
   record one claimant publishes verifies no other claim. Registrations made
   before this change keep the challenge they were issued.

5. **Invitations are bounded.** Every invitation is an email from the
   deployment's sender to an address the inviter chose, and self-service
   tenants make anyone an inviter. Invitations are limited per client IP,
   per tenant per window, and per recipient by a resend cooldown. The name of
   a self-service tenant, which its creator typed, never appears in the email.

### Why this is a tenant, not a workspace

ADR-0001 keeps workspaces, and the fine-grained membership inside them, out of
identity. A self-service tenant is not a workspace. It is the same entity as a
domain-formed tenant: the same membership table and roles (owner, admin,
member), the same invitations, the same suspension, the same place a login
policy would hang. It differs only in how it came to exist and in having no
domain yet; verifying one later makes it an ordinary domain tenant. Identity
still models nothing below a tenant: no nested groups, no per-resource
membership, no authorisation. ADR-0001's reason for keeping tenant membership
in identity applies unchanged: which tenant a verified identity belongs to is
an authentication-time fact that gates a token claim. What that identity may do
inside the tenant remains the consuming service's decision.

Modelling it as a workspace instead would need a workspace service to exist
before any group without a domain could form, and would split one membership
model in two, with invitations, roles and suspension implemented twice.

### Why it goes in the existing `tenant` claim

- Verifiers already scope on `tenant`. A second claim (a "selected tenant"
  next to `tenant`) would leave two claims that can disagree, and every
  verifier choosing which one to trust.
- The claim's meaning stays "the tenant this token is for": the deployment
  default when nothing was chosen, otherwise a tenant the subject is an active
  member of. Storage is keyed by project (ADR-0002), not by this claim, so no
  storage scope changes.
- The cost is one compatibility edge: a verifier that pins `tenant` to the
  default refuses a token with a chosen tenant. Nothing changes until a client
  sends `tenant_id`, and the upgrade guide tells such verifiers to accept a
  non-default tenant first.

### What the claim asserts, and what it does not

A chosen `tenant` asserts **membership only**: when the token was refreshed,
its subject held an active membership in that claimed tenant of the token's
project. It does not assert:

- **A role in the tenant.** `role` remains the account-wide role on every
  token, chosen tenant or not. A service that needs the caller's role in a
  tenant reads it from `ListMyTenants`.
- **That the tenant's login policy was met.** A login policy (ADR-0006) is
  applied at sign-in, by the verified domain of the account's email. It is
  not applied when a tenant is chosen: a member who signed in some other way
  can choose a tenant whose policy would have required SSO. A tenant that
  needs its policy to gate access verifies its domain, so the policy applies
  to everyone signing in with it.
- **That the membership still exists.** It is re-checked at the next refresh,
  so the claim can outlive a membership by one access-token lifetime. Tenant
  suspension is re-checked per request by identity's HTTP chain; a host that
  verifies tokens itself, including over native gRPC, sees a suspension only
  when the token expires unless it checks the tenant's status too.

## What this amends

- **ADR-0001**, Decision §1 lists `Tenant` among what identity keeps. That
  stands; a tenant may now also be created by a signed-in user, and such a
  tenant is not a workspace (above). Decision §3, "the services meet only at
  token issuance", stands; the token may now name a chosen tenant.
- **ADR-0002**, Decision §3 defines a Tenant as "a company entity, auto-formed
  per verified non-public email domain". A Tenant is now a company or team
  entity that is auto-formed per non-public email domain, created by an
  operator, or created by a signed-in user where the project allows it. The
  mechanics' "resolves the Tenant from the authenticated user's email domain /
  membership" now includes the tenant a token was refreshed for.
- **ADR-0004** (tenant auto-formation from email domains; the redesign ADRs
  and `docs/IDENTITY.md` cite it). A tenant no longer becomes `claimed` only
  by verifying a domain: a self-service tenant is claimed from creation and
  has no domain. "One tenant per email domain" now holds for verified
  domains only: several tenants may hold a pending claim on one domain, and
  auto-formation never joins a pending claim.

## Consequences

- **Positive.** A group with no company domain gets the same membership,
  invitations and token scoping as any other tenant, without a second
  membership model in the consuming product.
- **Positive.** A person in several tenants can hold a token for one of them;
  the default claim is unchanged for every client that does not ask.
- **Negative.** Tenant-admin RPCs that were reachable only by vetted admins
  are now reachable by anyone a project lets create a tenant. Domain
  registration and invitations were hardened for that (decisions 4 and 5),
  and any tenant-admin RPC added later must assume an untrusted admin.
- **Negative.** A verifier outside identity's HTTP chain has to accept a
  non-default `tenant`, and does not see a suspension before the token
  expires unless it checks the tenant itself.
- **Neutral.** Schema: migration 0044 (`tenants.created_by`, the `created`
  membership source) and 0045 (contested domain claims, the per-tenant TXT
  challenge).
