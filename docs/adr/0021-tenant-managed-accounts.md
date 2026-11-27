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
