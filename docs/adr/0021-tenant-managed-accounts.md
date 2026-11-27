# ADR-0021 — Tenant-managed accounts

## Status

Accepted (2026-11-27). Off by default: a server turns managed accounts on
with `GATEWAY_MANAGED_ACCOUNTS_ENABLED` (postgres only, and only with
`GATEWAY_REVOCATION_MODE=session`), and a project admits them with
`access.admit_managed_accounts` in its `config_json`, plus
`access.admit_managed_accounts_self_service` for tenants made through
self-service `CreateTenant`. The switches gate new writes; the restrictions
on accounts that are already managed always apply.

## Context

A tenant owner or admin adds people with `CreateTenantInvitation(email,
role)`, and the invited address becomes the person's own account. A tenant
could not give its people accounts on its own verified domain, nor manage
them as workspace administrators do.

## Decision

An account may be **managed by exactly one tenant**: its address,
`<username>@<domain>`, is on a domain verified for that tenant; an owner or
admin creates it before its first sign-in; it belongs to that tenant only
(`users.managed_by_tenant_id`). Personal accounts and invitations by email
are unchanged, and no managed account exists before its domain is verified
for the tenant.

- **Creation and set-up.** `CreateTenantInvitation` with `account_username`,
  `account_domain` and `display_name` creates the account waiting to be set
  up (status `invited`, `set_up_at_ms` 0, `setup_epoch` 1) and mails a set-up
  link, an invitation carrying the account's id and epoch, to the address the
  caller names. Asking again for an account never set up bumps the epoch, so
  only the newest link sets it up. `SignUpWithTenantInvitation` redeems the
  link with a password only: the account becomes active with its email
  verified, joins the tenant, and the link is accepted, in one transaction.
  Revoking a link deletes an account that was never set up.
- **Refusals are typed.** `ManagedAccountRefusedDetails` says
  `MANAGED_BY_THIS_TENANT`, `ADDRESS_UNAVAILABLE`, `DOMAIN_UNVERIFIED` or
  `POLICY`. A holder outside the caller's tenant is never named, and an
  ordinary invitation to another tenant's managed address is sent as any
  other (acceptance refuses it), so no tenant can learn which addresses
  others manage.
- **One lock order.** Every managed-account write runs in one store
  transaction bound to its project, taking the account's row, then the
  tenant's memberships, then its invitations, so set-up, revoke, suspend,
  remove and reset cannot interleave.
- **Address rules.** A managed address may not be on the project's own
  account domain (`accounts.domain`), and the project's deny layer applies to
  it at creation and set-up.

- **Lifecycle events.** `user.created` is emitted when a managed account is
  first set up, not when it is created waiting: until then nobody can sign
  in to it. Revoking the link of an account never set up deletes it without
  `user.deleted`, since its creation was never announced. Both events carry
  the deployment's tenant id, as every user event does; the managing tenant
  is the account's own attribute, not the event's.

- **What a managed account may not do.** It adds no recovery email: its
  tenant recovers it with a reset to a new set-up link, never through an
  address of the person's own. It owns agents only while it stands in its
  tenant, and its suspension, removal or reset deactivates them. The project's operator does not stop a single managed account
  (AdminService deactivate, reactivate, delete, password reset and update all
  refuse it): its tenant's owners and admins suspend or remove it.
- **One tenant only.** A managed account, and an agent it owns, holds a
  membership in its managing tenant only. `GrantMembership` (an invitation
  accepted elsewhere), `JoinByDomain`, `AddMember`, `UpsertMembership`,
  `CreateOwnedTenant` and auto-formation refuse any other with
  `ErrManagedElsewhere`; auto-formation records the membership in the
  managing tenant and forms none; `ResetManaged` refuses an account that holds
  one. This may open later, as workspace guests do, through a decision of its
  own: guest memberships would need their own suspension, removal and reset
  rules.
- **Ending sign-ins under way.** Suspend, remove and reset revoke the
  account's and its agents' sessions and refresh tokens, expire approved QR
  hand-offs, spend unredeemed OAuth one-time codes and delete pending sign-in
  challenges in the same transaction. The server refuses managed accounts
  unless `GATEWAY_SESSION_CACHE_TTL_SECONDS` is at most 60, the longest
  another replica may serve a revoked session.
- **Set-up links stay set-up links.** A set-up link is never an open
  invitation and is never accepted as an ordinary one: `AcceptTenantInvitation`
  refuses another account, and a link still pending, with `PERMISSION_DENIED`,
  and for an accepted link only restores its own account's membership. It is
  never revoked as an ordinary invitation, works only while its issuer may
  still issue it, and never brings back a member the tenant removed.
- **Purge order.** Purging a managed account revokes its pending set-up
  links first, in their own transaction, and then runs the erasure cascade.
  The order is intended: it fails safe, as a failure between the two leaves
  the account in place with no live link, and a retry finishes the purge.
- **Taking an account back reaches every verifier within a minute.**
  Suspending, removing or resetting a managed account ends its sessions and
  refresh tokens in the same transaction, and the replica that wrote it drops
  them from its session cache. Other replicas, and services that verify
  access tokens themselves, would otherwise honour a token until it expires,
  so a managed account's access tokens (`managed: true`), and every token of
  an agent it owns or of an agent with no owner, last
  `GATEWAY_MANAGED_ACCESS_TOKEN_EXPIRY_SECONDS`, 60 by default and never more
  than 60, whether or not managed accounts are enabled, and its refresh
  rechecks its standing.
  Calls that attach a credential (a passkey, two-step, a
  phone, a provider link, a password, an agent) or administer a tenant read
  the account and the session from the store, so a token cached as live does
  nothing there.

- **A reset's link goes where the admin says.** `ResetManagedAccount` mails
  the new set-up link to any usable address the resetting owner or admin
  names, not only to the account's own: the person who lost access usually
  cannot read the account's mailbox, which is the account itself. The admin
  is trusted with that choice as with creating the account; the reset is
  audited with the address redacted, every address the account had is told
  first, a per-address daily cap applies, and an admin resetting another
  admin is reported to the tenant's owners.
- **Switching managed accounts off stops new ones, not the rules.** With
  `GATEWAY_MANAGED_ACCOUNTS_ENABLED` off no managed account is created, set
  up or reset, and help requests go to the project's admins; the accounts
  that exist keep every restriction, still sign in only while their
  membership is active, still get access tokens of at most a minute, and
  suspending or removing one still ends its sessions at once. What the flag
  no longer holds at boot is `GATEWAY_REVOCATION_MODE=session` and a session
  cache TTL of at most 60: a deployment that turns managed accounts off while
  some exist keeps both, or another replica may serve a suspended account's
  session for as long as its cache holds it.

## Consequences

- Rolling back past schema 68 once managed accounts exist turns them into
  personal accounts with no restriction: do not.
- A deployment that lets admins remove a verified domain must refuse while
  managed accounts use it; the first change in this repository that lets a
  domain be removed or un-verified must suspend its managed accounts in the
  same transaction.
- A later operation that adopts a personal account into a tenant must revoke
  all its sessions and refresh tokens in its transaction.
- Until a reset operation exists, a managed account whose credentials are
  compromised stays suspended; restoring its membership brings back whatever
  credentials it had.
- A suspension, removal or reset deactivates the account's agents, and a
  restore does not bring them back: `RestoreTenantMember` reports how many
  stay off (`agents_left_deactivated`, a count taken at the restore of every
  agent of the account then deactivated, whatever deactivated it), and the
  owner reactivates each, which needs the owner to stand in its tenant.
- A help request's source is kept only as an HMAC under a key derived from
  `GATEWAY_TOTP_RECOVERY_PEPPER`; rotating the pepper changes every source's
  key, so the per-source daily counts start again for up to a day.

## Later

- Record why an agent was deactivated (a `deactivation_reason` on the
  account, cleared by `ReactivateAgent`) and show it on the owner's agent
  list as an `AgentDeactivationReason` (owner suspended, removed or reset),
  so the owner sees why each agent is off without asking an admin.
