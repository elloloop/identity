# ADR-0014 — Agent accounts (non-human accounts a person owns)

## Status

Accepted (2026-10-09).

Depends on ADR-0002 (Project is the isolation shard) and follows the pattern
ADR-0013 set for anonymous accounts: a thin account is a user row, not a
parallel table.

## Context

Applications want assistants, bots and automations to act under their own
user id: to be mentioned, to own data, and to have work attributed to them,
without impersonating the person who runs them. Today the only way to get
such an id is to create a person account for the bot, which gives it a
sign-in method, a mailbox-shaped address, a place in the directory and a
lifecycle disconnected from the person responsible for it.

Two things are deliberately out of scope here:

- **How an agent obtains tokens.** Delegation, where an owner's session
  mints a scoped token for one of their agents, depends on token-exchange
  work not yet built. This change ships the account model and the standing
  check that the token path will run; it ships no path that issues an agent
  a token from outside the service.
- **What an agent may do.** Which applications an agent may act in, and on
  what, is application authorization. Identity says *this is an agent, and
  this person owns it*; it does not model teams, roles within an
  application, or reporting lines.

## Decision

### An agent is a user row with a kind and an owner

`users.kind` is `person` (every existing row, by default) or `agent`;
`users.owner_user_id` names an agent's owner and is empty on a person. A
CHECK constraint holds the two together. Downstream services key data on the
user id exactly as before and need no second code path. `User.kind` and
`User.owner_user_id` are on the wire (with `User.pending_owner_user_id`,
below); the proto enum's zero value is
unspecified, and the server always sets one of the two kinds.

The owner is an active, non-anonymous, non-merged person **in the same
project** (the project is the isolation shard, ADR-0002); an agent cannot own
an agent.

### An agent has no sign-in method

An agent has no email, username, password, address or linked provider, and
every credential-attach path refuses it. That alone is not relied on: the
interactive sign-in chokepoint (`issueSignInTokens`) refuses an agent
before any session is written, so a row that somehow acquired a credential
still cannot sign in. Each sign-in method has its own refusal test.

### Standing is derived from the owner, at every issue

An agent is usable only while it is active and its owner is an eligible
person. The check runs in the one function every token issue goes through,
refresh included (`issueTokensWithSessionStart`), so it holds however the
owner lost standing, including paths that do not know agents exist. Nothing
is written to the agent when its owner changes, so restoring the owner
restores the agents.

The issue-time check bounds how long an agent outlives its owner to one
access-token lifetime. Where the owner's standing changes through identity
(deactivation, deletion, scheduled deletion, SCIM deprovisioning, parental
consent withdrawal, market change), the sessions of every agent the owner
owns are revoked with the owner's, so the window closes at once. Changes to
the owner's *credentials* (password change, reset) do not cascade: they say
nothing about whether the owner still stands behind their agents.

Introspection, when it lands, reuses the same check.

### An agent is admitted as its owner is

An agent can never do more than its owner. It has no email or username for
a project's access mode or deny layer to judge, so the access check judges
its owner instead: in an `allowlist` or `closed` project, or under a deny
rule that blocks the owner's address, the agent is refused whenever the
owner would be. Where the deployment requires identity verification, the
owner's verification is the one that counts; an agent cannot verify anyone.
Both checks run with the standing check at every token issue, so the
token-issuing path for agents inherits them rather than having to remember
them. (Before this rule an agent was judged as the empty address, which
refused it under every allowlist whatever its owner's standing.)

### The token says it is an agent

An agent's access token carries `"kind": "agent"`. A person's token carries
no `kind` claim, so every existing token is byte-identical and no verifier
has to change. An application that must never treat an agent as a person has
a claim to check without a lookup.

### Owner and admin manage, with one guard

The management RPCs (create, list, update, transfer, cancel a transfer,
deactivate, reactivate, delete) admit the agent's owner or a project admin
at one chokepoint. Everyone else
gets one indistinguishable `PERMISSION_DENIED`, whether the id names an
agent, a person or nothing, so the surface is not an oracle for which ids are
agents. Separate admin RPCs were rejected: they would duplicate the
validation and the audit for no difference in behaviour.

A per-owner cap (`GATEWAY_AGENTS_MAX_PER_OWNER`, default 25, at most 500)
and a per-IP rate limit on creation bound how many accounts a single person
can mint. The cap is checked before the write and is not transactional; the
rate limit bounds the overshoot. A merge can carry an owner past the cap, so
listing and the revocation cascade page through every agent rather than
assuming one page.

An agent's role is always `member`. Its role in an application is the
application's to decide.

### A transfer needs the recipient's consent

Ownership is responsibility for what the agent does, so it cannot be handed
to someone who did not agree to take it. `TransferAgent` records an offer
(`users.pending_owner_user_id`); the agent stays with its owner, usable and
managed by them, until the recipient answers. `AcceptAgentTransfer` and
`DeclineAgentTransfer` are the recipient's alone (an admin cannot accept on
someone's behalf), and `CancelAgentTransfer` is the owner's or an admin's.
`ListIncomingAgentTransfers` lists what waits on the caller. A new offer
replaces a pending one.

The per-owner cap is checked at acceptance, when the recipient's count is
known, not at the offer. Acceptance and refusal are one conditional write
that settles only the offer the caller read (`SettleAgentTransfer`), so an
acceptance never lands on an offer that was cancelled or replaced in
between. Accepting ends the agent's sessions: whatever the previous owner
approved for it does not carry over. A merge re-points offers made to the
retired account at the survivor, and drops one the survivor would make to
itself. Recipients answer with the same uniform `PERMISSION_DENIED` as the
management RPCs, so the answer RPCs are not an oracle either.

**Orphans are the exception.** An agent whose owner no longer exists has
nobody left to hand it over, so a project admin's transfer of it takes
effect at once, within the recipient's cap, and ends its sessions. Requiring
an acceptance there would leave the admin, the only party able to act, with
no way to finish. An owner who is suspended or scheduled for deletion still
exists and may return, so their agents are not orphans and a transfer of
them is an offer.

### Off until a deployment turns it on

The surface is opt-in (`GATEWAY_AGENTS_ENABLED`, default `false`). Upgrading
adds the columns and the refusals (an agent row cannot sign in whatever the
switch says) but lets no one create an agent until the operator decides to.
While off, every management RPC answers `FAILED_PRECONDITION`, so a client
can tell "not offered here" from "not allowed".

### Agents stay out of person-shaped surfaces

The admin `ListUsers` omits agents unless `include_agents` is set; the
admin `UpdateUser` refuses one (its profile is edited through `UpdateAgent`,
which keeps the validation and the audit in one place); the directory lookup
(which resolves email addresses) and SCIM never see them.
Merging moves a retired owner's agents to the survivor and refuses to merge
an agent.

### Deleting the owner does not delete the agents

`owner_user_id` carries no foreign key. Deleting the owner leaves the agents
naming them, unusable by the standing check, until an admin transfers them
(at once, as above) or deletes them. Deleting them with the owner was rejected as destroying data
applications may hold under the agent's id with no chance to hand it over;
it can be revisited once there is a product answer for orphans.

## Consequences

- Every repository driver and test fake carries the three columns, the
  list filters and the conditional settle; the conformance suite pins the
  round trip, the default exclusion, the owner and pending-owner updates,
  the settle (accepted, declined, stale) and the merge behaviour on every
  driver.
- Webhook payloads for an agent carry `kind` and `owner_user_id`, and
  `pending_owner_user_id` while a transfer is pending; a person's payload
  is unchanged.
- The token-issuing path for agents (delegation) and the RPCs an agent token
  may call are follow-up work; both will run the standing check this ADR
  introduces.
