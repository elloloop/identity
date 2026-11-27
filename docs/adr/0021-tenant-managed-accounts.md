# ADR-0021 — Tenant-managed accounts

## Status

Accepted (2026-11-27). Store and data layer; the RPCs build on it.

Off unless the server sets `GATEWAY_MANAGED_ACCOUNTS_ENABLED` and the project
sets `access.admit_managed_accounts`. Unset, nothing changes.

## Context

A tenant admin adds people with `CreateTenantInvitation(email, role)`, and the
invited address becomes the person's own account. A tenant cannot give its
people accounts on its own verified domain, nor manage those accounts as a
directory administrator manages a workforce's.

## Decision

1. **A managed account belongs to one tenant.** `users.managed_by_tenant_id`
   names the tenant that created it, on a domain verified for that tenant,
   before its first sign-in. It is fixed at creation; `''` is a personal
   account. Personal accounts and invite-by-email are unchanged.
2. **It holds a membership in its tenant only.** Every store write that would
   give it a membership elsewhere refuses with `ErrManagedElsewhere`:
   `GrantMembership` (an invitation accepted), `JoinByDomain`, `AddMember`,
   `UpsertMembership`, `CreateOwnedTenant` and auto-formation; and
   `ResetManaged` refuses an account that somehow holds one. This may open
   later, as a workforce directory lets an organisation's accounts be guests
   elsewhere, through a decision of its own: guest memberships would need
   their own suspension, removal and reset semantics.
3. **It is set up from a link, not by accepting an invitation.** Its set-up
   link is a `tenant_invitations` row with `user_id` set, sent to a delivery
   address, whose token goes only into that email. Only the link carrying the
   account's current `setup_epoch` sets it up, and only while its issuer may
   still issue it. It is never an open invitation, never accepted, never
   revoked as an ordinary invitation, and never brings back a member the
   tenant removed.
4. **One lock order for every managed write.** The membership's advisory
   lock, the account's `users` row (then its agents' rows), the domain row and
   then the `tenants` row `FOR SHARE` where read, the tenant's memberships in
   one ordered pass, then `tenant_invitations`. Each write is one transaction
   bound to its project.
5. **Suspend, remove and reset end every way in.** In the same transaction
   they revoke the account's and its agents' sessions and refresh tokens,
   delete pending sign-in challenges, expire approved QR hand-offs and spend
   unredeemed OAuth one-time codes, and deactivate its agents. A reset also
   clears every credential and outstanding link and issues a new set-up link
   with the member's current role.
6. **Session revocation only.** The server refuses managed accounts unless
   `GATEWAY_REVOCATION_MODE=session` and `GATEWAY_SESSION_CACHE_TTL_SECONDS`
   is at most 60, the longest another replica may serve a revoked session.

## Consequences

- A managed account cannot be used in a second tenant until decision 2 is
  revisited.
- Rolling migration 0068 back once managed accounts exist turns them into
  personal accounts that nothing restricts (UPGRADE.md).
- Identity never un-verifies a domain today; the change that first lets a
  verified domain be removed must suspend its managed accounts in the same
  transaction.
