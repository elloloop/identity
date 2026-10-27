# ADR-0018 — Self-service tenants, and choosing a tenant for a token

## Status

Accepted (2026-10-26). Off by default: a project turns self-service tenants
on with `tenants.self_service` in its `config_json`, and the default project
with `GATEWAY_SELF_SERVICE_TENANTS_ENABLED`; a server turns tenant selection
on with `GATEWAY_TENANT_SELECTION_ENABLED`.

**Amends** ADR-0001, ADR-0002, ADR-0004 and ADR-0016, as listed under
[What this amends](#what-this-amends). It supersedes none of them.

**Amended** (2026-10-27): suspension has operator RPCs.
`AdminSuspendTenant` and `AdminRestoreTenant` move a tenant between
`claimed` and `suspended` with a required reason that the audit trail
keeps, so suspending a tenant no longer needs database access and is no
longer unaudited. A restore, like every status change, revokes the
governed agents again, and today a suspension also stops the tenant's
login policy governing sign-in ([Suspension](#suspension)).

**Amended** (2026-10-27): ownership can move. `TransferTenantOwnership`
lets an owner hand a tenant to another member, and
`AdminRecoverTenantOwnership` lets an operator appoint an owner to a tenant
none of whose owners or admins can sign in any more, each audited
([Ownership](#ownership)). Removing a tenant's last owner is refused in the
same transaction that would remove them.

**Amended** (2026-10-27): a tenant may let the people on its verified
domains join it themselves. `SetDomainJoin` turns that on or off for one
domain, and it is off until an admin turns it on. `ListJoinableTenants` and
`JoinTenantByDomain` then let an account that auto-formation never joined,
such as one made before the domain was verified, find the tenant and join it
as a domain member, audited ([Joining by domain](#joining-by-domain)).

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
   agent, merged and inactive accounts, and to an account that has not
   verified its email: an unproven address makes an owner nobody can reach.
   `ListMyTenants` lists the claimed
   tenants the caller is an active member of, with their role.

2. **A refresh may choose the token's tenant.** `RefreshToken` takes an
   optional `tenant_id`. It is granted only to an active member of a claimed
   tenant in the session's project whose login policy admits the session
   (below); the resulting access token carries that tenant in its existing
   `tenant` claim. A refused choice issues nothing and leaves the refresh
   token unspent. A `tenant_id` no tenant could have, longer than 64
   characters or holding anything but ASCII letters, digits, `-` and `_`, is
   `INVALID_ARGUMENT` before the refresh token is read. Omitting it keeps the default. The
   choice is made again on every refresh. A membership that came from the
   email's domain counts only while that email is verified and on a domain
   the tenant has verified: an unverified address proves nothing about the
   domain, and an address moved off it no longer belongs to it. Moving the
   email off the tenant's verified domains also ends the membership
   (migration 0047), and moving back does not rejoin. Selection is a server
   switch, off by default and available only on the Postgres driver; with it
   off a `tenant_id` is `FAILED_PRECONDITION`, so a client can tell a server
   that does not select from a tenant it may not have. Every refused choice
   carries a `TenantSelectionRefusedDetails` error detail naming its reason;
   a refresh refused for any other reason may have spent the token, so a
   client retries without `tenant_id` only when the detail is present.

3. **The claim is re-checked where identity can.** Identity's HTTP middleware
   accepts a token whose `tenant` is the default or a claimed tenant of the
   token's project. It reads a selected tenant's status through an
   in-process cache with a short TTL (default 30 seconds, at most 300; `0`
   reads on every request), so a suspended tenant's tokens are refused
   within it. Without the cache every request carrying a selected tenant
   would cost a database read. A failed read is never cached and refuses the
   request as unavailable rather than serving it as signed out; a histogram
   times the reads by outcome. A membership that ends takes effect at the
   next refresh, within one access-token lifetime.

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
   per tenant per window, per inviter across all their tenants (so creating
   tenants sends no more email), per tenant and recipient in a window, and
   per tenant and recipient by a resend cooldown. The per-recipient count is
   each tenant's own, so one tenant using it up cannot stop another tenant
   inviting the same address. The name of a self-service tenant, which its
   creator typed, never appears in the email.
   Accepting an invitation needs a verified email at the invited address,
   and never lowers a role, so an invitation cannot demote a tenant's last
   owner.

6. **Domain registrations and verifications are bounded.** Each
   `VerifyDomain` makes identity look up a DNS name the tenant chose, and
   each `CreateDomain` answers whether another tenant verified a name. A
   tenant may make a bounded number of both together per window, spent only
   by a caller who administers it or, for a latent tenant, may claim it,
   and the two share a per-IP budget. A
   failed re-check leaves a verified domain verified: a lapsed or flapping
   record must not drop its login policy and sign its users' agents out; an
   operator removes a domain its tenant no longer holds. A suspended tenant
   verifies nothing, because verifying claims the tenant and would lift the
   suspension. It is not administered at all: every domain and membership
   RPC refuses its owners and admins, and an invitation to it cannot be
   accepted, through one check shared by both services, so a suspension
   stops a tenant growing as well as acting. Nor does auto-formation add
   anyone to it, through a domain it verified or one it was formed for.

7. **A tenant or domain change signs out only the agents it governs.**
   Delegated agent grants and agent machines are revoked when the
   governance behind them changes (ADR-0016). Until now every write to a
   tenant's status or primary domain, or to a domain row, revoked every
   agent grant and machine in the project. Once anyone can own a tenant,
   that let any tenant owner sign out the whole project's agents, by calling
   `VerifyDomain` on a claim that fails. Now:
   - only a change that moves governance revokes: a domain row that is, or
     becomes, verified changing status, tenant or name, or one inserted
     verified or deleted while verified; a tenant changing status or primary
     domain. Writes that change nothing are not made;
   - it revokes only the governed users' agents: the members of the tenants
     involved, in any membership status, and the accounts whose email is on
     the domains involved. A pending agent request with no owner yet is not
     revoked by these changes;
   - login-policy and project changes are operator actions and still revoke
     project-wide.

   The trigger collects the governed users once per change and reads
   accounts only when a domain is involved. It finds the accounts on a
   domain through a stored column, `users.email_domain`, and an index on
   `(project_id, email_domain)`, not through an expression index on the
   email: `users` has forced row-level security, under which only a
   leakproof comparison can be an index condition, and `lower()` and
   `substring()` are not, so an expression index would narrow the scan to
   the project and no further. This is the choice 0034 made for
   `users.email_fold`. The column costs one rewrite of `users` when the
   migration runs.

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

A chosen `tenant` asserts **membership, under the tenant's login policy**:
when the token was refreshed, its subject held an active membership in that
claimed tenant of the token's project, and the tenant's login policy
(ADR-0006) admitted the session. A policy that limits how its users sign in
(SSO required, 2FA required, or allowed methods) admits only a session it
governed at sign-in, which is one whose account's email is on a domain the
tenant has verified. Identity applies such a policy at sign-in by that
domain, and a session does not record how it signed in, so a member from
another domain is refused whatever method they used: identity fails closed
rather than trust a sign-in it cannot see. The policy's session timeouts
apply to every selection, against the session's start and last use. A
policy that cannot be read refuses the selection as unavailable. It does
not assert:

- **A role in the tenant.** `role` remains the account-wide role on every
  token, chosen tenant or not. A service that needs the caller's role in a
  tenant reads it from `ListMyTenants`.
- **That the membership still exists.** It is re-checked at the next refresh,
  so the claim can outlive a membership by one access-token lifetime, in
  `mode=session` too: removing a member ends none of their sessions. Tenant
  suspension is re-checked by identity's HTTP chain within the tenant-status
  cache TTL; a host that verifies tokens itself, including over native gRPC,
  sees a suspension only when the token expires unless it checks the
  tenant's status too (`docs/embedding.md` says how).

### Suspension

Suspension is the lever this design relies on to stop a tenant. An operator
suspends a claimed tenant with `AdminSuspendTenant` and restores it with
`AdminRestoreTenant`, each with the operator secret and a reason, recorded
as `tenant_suspended` or `tenant_restored`. Each is a compare-and-set on the
tenant's status: a tenant already in the status asked for is left as it is
and nothing is recorded, and a latent tenant, which governs nothing, cannot
be suspended.

A suspension revokes the agent grants and machines of its members, in any
membership status, and of the accounts on its verified domains and its
primary domain (decision 7), ends its selected tokens
within the cache TTL, and stops its admins administering it (decision 6).
Its members keep their accounts and their default-tenant tokens.

It also stops the tenant's login policy governing sign-in. The policy is
looked up only for a claimed tenant, so while the tenant is suspended the
accounts on its verified domains sign in under the project's default
controls: its allowed methods, SSO and 2FA requirements, password minimum
and session timeouts no longer apply to them, nor bound their agents'
grants. That is not what stopping a tenant should mean, since a tenant
suspended to contain its accounts ends up with looser controls on them, and
it is recorded here as the behaviour this amendment found, to be changed so
that a suspension never loosens sign-in controls.

Restoring a tenant gives back administration and selection at once, though a
replica that cached the suspended status refuses the tenant's selected
tokens until the entry expires, within the cache TTL. It brings back the
login policy. A restore is a status change like any other, so it revokes the
governed agent grants and machines again, including any connected during the
suspension, and revives none the suspension revoked: the conservative choice
for a tenant that may have been suspended for an investigation. A tenant
with no creator and no owner or admin cannot be restored until an operator
appoints an owner with `AdminRecoverTenantOwnership` (or adds an admin with
`AdminAddTenantAdmin`): a latent tenant suspended in SQL looks like that,
and restoring it would make it selectable without anyone having verified its
domain. A call that loses a race with another status change is refused as
aborted rather than as a precondition, so the caller reads the tenant again.

### Ownership

A tenant is never left without an owner by its members' own calls: the
last active owner cannot be removed (`RemoveTenantMember` refuses), and a
transfer always leaves one. The removal decides under locks on the tenant's
owners, which a transfer takes too, so neither two removals at once nor a
removal racing a transfer can together leave none. Ownership moves in two
ways, both audited; neither changes any other member's role.

- **An owner hands the tenant on.** `TransferTenantOwnership(tenant_id,
  user_id)` makes another active member an owner and the caller an admin,
  in one transaction that locks the tenant's owners and both memberships.
  Of two racing transfers by one owner only one succeeds. Naming a co-owner
  leaves them an owner and the caller an admin, so an owner can step down.
  Only an owner may transfer, and not while the tenant is suspended
  (decision 6); the status is read before the transaction, so a suspension
  that lands in between does not stop it. The new owner must be someone
  allowed to create a tenant: an active, signed-up person with a verified
  email, because an owner sends the tenant's invitations. A member through
  the email's domain must still be one, on a domain the tenant verifies,
  and becomes an `added` member, so the ownership does not end when that
  email leaves the domain (migration 0047). Recorded as
  `tenant_ownership_transferred`, the previous owner as actor and the new
  one as target.
- **An operator appoints an owner when nobody can govern.** The last-owner
  guard stops a removal, not an account being deleted, deactivated or merged
  away. A tenant whose owners cannot sign in has no owner, but it is still
  governed while an admin can sign in: that admin can invite a new owner
  (`CreateTenantInvitation` with `role = "owner"`). Once no owner or admin
  can sign in, nobody can invite, register a domain or transfer.
  `AdminRecoverTenantOwnership(project_id, tenant_id, user_id, reason)`,
  with the operator secret, makes an account that could own a tenant (the
  same rule as a transfer) an active owner, member or not, recorded as
  `tenant_ownership_recovered` with the reason and the operator's client. It
  is refused while any owner or admin who is a person can still sign in, so
  an operator never appoints an outside account above people who can act. An
  agent or anonymous admin does not count: it may not own a tenant itself,
  so it is no one the tenant can be left to. "Can sign in" is sign-in's own
  rule: an account pending deletion still can, since signing in cancels the
  deletion. Naming an account that is already an owner who can sign in
  returns its membership and records nothing, so a retry is safe. A latent
  tenant has never had an owner and is refused; a suspended one can be
  recovered, so that it has an owner when it is restored. A suspended tenant
  whose owner or admin can still sign in is refused like any other, and
  since suspension stops their transfer and invitations too, the operator
  restores it first and they act then. Recovery takes an owner whose account
  is deactivated or suspended to be gone, though either can be undone: an
  owner reactivated after a recovery is an owner again beside the appointed
  one, so the operator first makes sure the account will not come back.

Recovery does not reuse `AdminAddTenantAdmin`. That RPC provisions: it is
not audited, checks neither the account nor who governs the tenant, and
sets the role it is given, so it can lower an owner. Recovery is the lever
for a tenant whose governance has failed, and it is narrow on purpose.

It stays closed while an admin can act, even one who will not. When every
owner is gone and the admins left cannot be reached or refuse, the remedy is
explicit and audited at each step: a project admin deactivates those admins'
accounts with `DeactivateUser`, reversible with `ReactivateUser`, and the
operator then recovers the tenant. The cost is that a deactivated account is
signed out of every tenant, not only this one; that is the price of not
letting an operator appoint an owner over someone who can still govern.

A transfer is not idempotent. Once it succeeds the caller is an admin, so a
retry, like the losing call of two racing transfers, is refused as the
caller not being an owner; a client that lost the response reads the
tenant's members to see where ownership stands.

That only an owner may transfer does not yet keep the owner role from a
tenant's admins: an admin can invite an owner, themselves included, and
can remove an owner who is not the last (issue #657).

### Joining by domain

Auto-formation joins a signup on a verified domain to the tenant that
verified it, once, at signup. An account made before the domain was
verified is never joined, and until now could join only by an invitation.
A tenant may now let such people join themselves.

- **It is off until an admin turns it on, domain by domain.** Proving
  control of a domain is not agreeing to admit everyone on it, and a tenant
  that verified a domain before this change must not start admitting people
  it did not. `domains.allow_join` (migration 0050) records the choice,
  `false` on every row. `SetDomainJoin(domain_id, allow_join)`, by an owner
  or admin and not while the tenant is suspended (decision 6), sets it,
  recorded as `domain_join_set`. It governs only joining by request:
  auto-formation is unchanged, since putting it behind the setting would
  either stop signups joining the tenants that rely on it today or need the
  setting on by default.
- **Who may join is who a domain membership counts for** (decision 2): an
  active, signed-up person whose email is verified and on the verified
  domain, not a public provider's. `ListJoinableTenants` returns the one
  tenant that qualifies, if the caller is not already an active member: the
  `claimed` tenant holding the domain's verified row, while that row
  allows joining. A project holds a domain's verified row on one tenant at
  most (decision 4), so there is at most one.
- **A join makes a domain membership.** `JoinTenantByDomain(tenant_id)`
  grants an active `member` membership with source `domain`, which ends when
  the email leaves the domain (migration 0047) as auto-formation's does.
  An existing membership is returned as it is, never raised or lowered.
  Every tenant but the one that qualifies is refused alike, an unknown one
  included, so the call cannot be used to find tenants. Recorded as
  `tenant_joined_by_domain`.
- **Turning it off ends no membership.** The setting decides who may join,
  not who belongs; ending a membership is `RemoveTenantMember`'s.

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
- **ADR-0016**, which has sensitive tenant and domain changes "conservatively
  require fresh consent across that project". Tenant and domain changes now
  require it only of the users they govern (decision 7); login-policy and
  project changes still require it across the project.

## Consequences

- **Positive.** A group with no company domain gets the same membership,
  invitations and token scoping as any other tenant, without a second
  membership model in the consuming product.
- **Positive.** A person in several tenants can hold a token for one of them;
  the default claim is unchanged for every client that does not ask.
- **Negative.** Tenant-admin RPCs that were reachable only by vetted admins
  are now reachable by anyone a project lets create a tenant. Domain
  registration, invitations and agent sign-outs were hardened for that
  (decisions 4 to 7), and any tenant-admin RPC added later must assume an
  untrusted admin.
- **Negative.** A verifier outside identity's HTTP chain has to accept a
  non-default `tenant`, and does not see a suspension before the token
  expires unless it checks the tenant itself.
- **Negative.** A suspended tenant's selected tokens stay usable on
  identity's HTTP chain for up to the tenant-status cache TTL.
- **Negative.** A self-service tenant cannot be renamed or deleted yet, and a
  member cannot leave one; each needs an RPC of its own.
- **Negative.** A member from outside a tenant's verified domains cannot
  choose a tenant whose login policy limits sign-in, even after signing in
  through the tenant's SSO, until sessions record how they signed in.
- **Negative.** Removing a member ends none of their sessions, so a token
  carrying the tenant outlives the membership by one access-token lifetime,
  in `mode=session` as in `mode=ttl`.
- **Negative.** A tenant left with no owner or admin who can sign in stays
  ungoverned until an operator recovers it. Recovery reads who governs the
  tenant before it grants, so two operators recovering one tenant at once,
  naming different accounts, may each appoint an owner (both are audited).
- **Negative.** While joining by domain is on, a member removed with
  `RemoveTenantMember` who is still on the domain can join again. An admin
  turns joining off to keep them out; keeping out one person while others
  join needs a block list, which does not exist yet.
- **Negative, open.** These gaps are known and tracked as follow-ups: a
  session records no sign-in method, which would let a tenant's policy
  admit a cross-domain member it did govern; a refresh that chooses or
  changes a tenant records no audit event of its own; and the verifications
  that claim a latent tenant, made by callers who are not yet its members,
  count against that tenant's attempt budget rather than the caller's.
- **Neutral.** Schema: migration 0044 (`tenants.created_by`, the `created`
  membership source), 0045 (contested domain claims, the per-tenant TXT
  challenge) and 0046 (guarded, scoped agent-governance triggers,
  `users.email_domain` and its index, the `domain_attempts` table, the
  invitation-limit indexes) and 0047 (a trigger on `users` that ends a domain
  membership when the email leaves the tenant's verified domains); joining
  by domain adds 0050 (`domains.allow_join`).
