# Upgrade guide

## Next — built with go-jose v4.1.6 for CVE-2026-116587; v4.26.0 withdrawn (no API or schema change)

The binary now links `github.com/go-jose/go-jose/v4` v4.1.6, which fixes
CVE-2026-116587, a denial of service when parsing a JSON Web Key that holds an
RSA key. Every release from v4.19.0 to v4.26.0 links the vulnerable v4.1.4:
v4.19.0 brought go-jose in with the OpenID provider library behind the agent
OAuth endpoints (`internal/app/agent_oauth.go`), its only user. Those endpoints
are mounted only with `GATEWAY_AGENT_OAUTH_ENABLED=true`, or
`Config.AgentOAuthEnabled` in a program that builds `identityserver.Config`
itself (off by default), so a deployment with the flag off does not serve them;
upgrade either way, since an image scanner flags the library regardless. govulncheck has no entry for the
advisory yet, so it gives no reachability answer, and the release image scan
gates on any fixable HIGH finding, so the fix is the upgrade rather than a
suppression.

Code that imports only `pkg/...` does not link go-jose. A program embedding
`identityserver` links it through the same provider library: require the commit
of `github.com/elloloop/identity` that carries this entry, or a later one, or
run `go get github.com/go-jose/go-jose/v4@v4.1.6` in the host module. A host
module that also uses go-jose v4 itself should know that v4.1.6 no longer
exports `RandReader` and refuses RSA keys over 4096 bits in a JSON Web Key by
default (`MaxRSAModulusBits`).

v4.26.0 is singled out only because its release scan ran after the advisory was
published: its image was built, signed and published before the scan failed.
Do not deploy it. Move any deployment running v4.19.0 through v4.26.0 to
v4.26.1, which is v4.26.0 plus this entry. Coming from an earlier release, you
also owe every entry added since it: `git diff <your tag> v4.26.1 --
docs/UPGRADE.md` lists them. Until v4.26.1 is published, the `4.26`, `4` and
`latest` image tags resolve to v4.26.0's image, so pin `4.26.1` rather than a
floating tag. v4.26.1 adds no other upgrade entry, so the three entries below
that v4.26.0 introduced (joining a tenant by domain with migration 0051, a
suspended tenant's login policy, and the removal record with migration 0052,
with their rollout notes) apply to it unchanged.

## Next — a member removed from a tenant cannot rejoin it by domain (migration 0052; behaviour change; `RemoveTenantMember` audited; `MembershipStore.RemoveMembership`, `JoinByDomain`, `IsRemoved` and `MembershipService.RemoveTenantMember` (Go API))

Until now `RemoveTenantMember` deleted the membership and kept no trace of
it. While the tenant let its domain's people join (`SetDomainJoin`), a
member removed who was still on the domain could join again at once with
`JoinTenantByDomain`, and nothing recorded the removal.

A removal is now recorded, and while it stands the person removed:

- does not see the tenant in `ListJoinableTenants`;
- is refused by `JoinTenantByDomain` with `PERMISSION_DENIED` and the
  message "you were removed from this tenant; an owner or admin must invite
  you back";
- is not added back by auto-formation, which matters only for an account
  promoted from an anonymous one, as auto-formation runs for new accounts.

A membership from any other source lets them back in and deletes the
record: an invitation they accept, or an operator's `AdminAddTenantAdmin` or
`AdminRecoverTenantOwnership`. An admin who removes themselves is recorded
the same way. A domain membership that ends because the email left the
domain is not a removal, and records nothing.

`RemoveTenantMember` is now audited as `tenant_member_removed`: the caller
as actor, the person removed as target, the request's IP and user agent,
and `project_id`, `tenant_id` and the membership's `role` and `source` in
the details. A call that removes nothing, and a refused one, record
nothing.

A join now decides, in the transaction that writes the membership, whether
the domain is still verified on the tenant with joining on, the tenant is
still claimed, and no removal stands. Joins, grants and removals of one
person in one tenant take a transaction-scoped advisory lock first, so a
removal racing a join leaves the person outside the tenant with the record
standing, whichever lands first. One window remains, as before: the
caller's email domain is read before that transaction, because accounts
are under row-level security. A confirmed email change off the domain that
lands in between leaves a `domain` membership the tenant does not count
while the email is off the domain.

Removals made before this release left no trace, so they have no record. A
person removed earlier who is still on the domain can join again while
joining is on. Removing them after they rejoin records it.

### Migration 0052

0052 creates `tenant_member_removals`, keyed by `(project_id, tenant_id,
user_id)` with `removed_at_ms`, and an index on `user_id`. Each id is a
foreign key that cascades, so deleting the project, the tenant or the
account deletes the record. Like `tenant_memberships`, it is a governance
table without row-level security (0016).

Creating a table with foreign keys takes `SHARE ROW EXCLUSIVE` locks on
`projects`, `tenants` and `users`. Those block writes to the three tables,
signups and account changes included, while the catalog changes. While the
migration waits for the locks behind a transaction that has one of the
tables open, new writes to it queue behind the migration too, for up to its
10-second `lock_timeout`. On a lock timeout the file rolls back and version
52 is recorded dirty: run `identity migrate force 51`, then `identity
migrate` again.

This release reads or writes `tenant_member_removals` on every membership
write, auto-formation at signup included, and on every join, so until 0052
has run those calls fail on its replicas. `GATEWAY_POSTGRES_AUTO_MIGRATE`
is off by default, so run `identity migrate` as its own job, and let it
finish, before the deploy starts.

Replicas of the previous release keep working against the new schema, but
they neither record removals nor check them. During the rolling deploy a
removal one of them serves records nothing, and a join one of them serves
admits a removed person. The down migration drops the table, and with it
every record, so everyone removed can join by domain again.

### Go API

- `MembershipStore.RemoveMembership(ctx, projectID, tenantID, userID)` now
  returns `(*TenantMembership, error)`: the membership as it stood when
  removed, or `nil` when there was none. It must record the removal in the
  same step, and record nothing when it removes nothing.
- `MembershipStore.JoinByDomain(ctx, projectID, tenantID, userID,
  domainID) (*TenantMembership, bool, error)` is new. It makes an active
  `member` with source `domain` only while the domain is verified on the
  tenant with joining on, the tenant is claimed and no removal stands, all
  decided where it writes. It returns `nil` when the domain or the tenant
  does not let the user join, `service.ErrRemovedFromTenant` while a
  removal stands, and otherwise the membership and whether it wrote it.
- `MembershipStore.IsRemoved(ctx, projectID, tenantID, userID) (bool,
  error)` is new.
- `MembershipStore.UpsertMembership` and `GrantMembership` must delete the
  removal record when they write a source other than `domain`.
- `MembershipService.RemoveTenantMember` takes the request's `ip` and
  `userAgent` after `targetUserID`, for the audit entry.
- New: `service.ErrRemovedFromTenant`, mapped to `PERMISSION_DENIED`, and
  `audit.EventTenantMemberRemoved`.

## Next — a suspended tenant's login policy keeps governing sign-in (behaviour change; no migration)

A tenant's login policy now governs the sign-ins through its verified
domains while the tenant is suspended, as it does while it is claimed.
Until now the policy was looked up only for a claimed tenant, so suspending
a tenant, through `AdminSuspendTenant` or in SQL, put the accounts on its
verified domains under the project's default controls, and where the
tenant's policy was stricter than the project's, the suspension loosened
them. A suspension stops a tenant being chosen for a token and administered
by its members; it never loosens sign-in controls
([ADR-0018, Suspension](adr/0018-self-service-tenants-and-tenant-selection.md#suspension)).

While a tenant is suspended, the accounts on its verified domains get the
same answers from its policy as while it is claimed:

- a method the policy does not allow is `PERMISSION_DENIED`;
- any method but SSO, when the policy requires SSO, is
  `FAILED_PRECONDITION` (`ErrSSORequired`);
- a single-factor sign-in, when the policy requires 2FA, goes on to the
  second-factor step, and is `FAILED_PRECONDITION` (`ErrTotpRequired`)
  for an account with no second factor enrolled;
- a new password must be at least the policy's minimum length;
- sessions end at the policy's idle and absolute timeouts, which also
  bound how long an agent the account connects keeps its grant.

This works in both directions. A tenant's policy replaces the project's
defaults rather than adding to them, so where a suspended tenant's policy
is looser than the project's, its accounts now sign in under the looser
policy, as they did before the suspension, where the previous release put
them under the project's stricter defaults. Before upgrading, check the
policies of the tenants you have suspended (`GetLoginPolicy`), and tighten
any that should be stricter while the tenant is investigated with
`UpsertLoginPolicy`.

Restoring the tenant leaves sign-in as it was. A latent tenant still
governs nothing. An operator who wants a suspended tenant's accounts to
sign in under other controls changes or deletes its policy with
`UpsertLoginPolicy` or `DeleteLoginPolicy`, which work on a suspended
tenant as on a claimed one and are audited.

There is no new setting and no schema change, and a rolling deploy needs
no care beyond the usual: until every replica runs this release, a replica
of the previous one still applies the project's defaults to a suspended
tenant's accounts.

## Next — join a tenant by its domain: `SetDomainJoin`, `ListJoinableTenants` and `JoinTenantByDomain` (migration 0051; additive RPCs; `Domain.allow_join`; `DomainStore.SetDomainAllowJoin` (Go API))

A person who signs up, or promotes an anonymous account, with a verified
email joins the tenant of that email's domain through auto-formation
(ADR-0004): the latent tenant formed for the domain, which becomes the
domain's tenant once it verifies the domain. Some people on a verified
domain are in no tenant of it all the same, and until now could join only
by an invitation:

- people auto-formation put in the domain's latent tenant before a
  *different* tenant verified the domain;
- people whose email moved onto the domain after they signed up, since
  auto-formation runs only at signup and promotion;
- people whose membership ended, for example when their email left the
  domain and later came back.

A tenant admin can now let such people join themselves, domain by domain.
It is off on every domain, existing ones included, until an admin turns it
on, so no tenant admits anyone it did not before.

- **`SetDomainJoin(domain_id, allow_join)`**, called by an owner or admin
  of the domain's tenant with their access token, turns joining by that
  domain on or off and returns the `Domain`, which now carries
  `allow_join`. It may be set before the domain is verified and takes
  effect once it is. A change is recorded as `domain_join_set` (the caller
  as actor, the domain as target, `allow_join` in the details); setting the
  value the domain already has records nothing.
  - `PERMISSION_DENIED`: the caller is not an active owner or admin, or the
    tenant is suspended.
  - `NOT_FOUND`: an unknown domain.
  - `INVALID_ARGUMENT`: a blank `domain_id`.
- **`ListJoinableTenants()`** returns the tenant the caller's verified
  email's domain lets them join, as `JoinableTenant` (`tenant_id`, `name`):
  the `claimed` tenant that has verified the domain, while it allows
  joining and the caller is not an active member. A project holds a
  verified domain on one tenant at most, so the list has at most one entry.
  It is empty for an unverified email, a public provider's domain, an
  anonymous, agent or inactive account, or a person removed from the
  tenant.
- **`JoinTenantByDomain(tenant_id)`** makes the caller an active `member`
  of that tenant with source `domain`, so the membership ends when the
  email leaves the domain, as a membership auto-formation made does. It
  returns the membership and records `tenant_joined_by_domain`. A caller
  who is already a member, as `ListMyTenants` counts membership, gets
  their membership back unchanged, whatever its role or source, and
  nothing is recorded. That is checked before whether the domain lets them
  join, so a retry after joining was turned off still returns it.
  - `PERMISSION_DENIED`: the caller is not an active, signed-up person, was
    removed from the tenant, or `tenant_id` is not the tenant their domain
    lets them join. An unknown,
    suspended or latent tenant gets the same answer, so the call reveals
    nothing about tenants the caller cannot join.
  - `FAILED_PRECONDITION`: the caller's email is not verified.
  - `INVALID_ARGUMENT`: a blank `tenant_id`.

Turning joining off ends no membership; remove members with
`RemoveTenantMember`, which keeps them from joining again by domain until an
invitation they accept lets them back in. Two joins racing for one account
make one membership and are recorded once.

### Migration 0051

0051 adds `domains.allow_join BOOLEAN NOT NULL DEFAULT false`. A constant
default rewrites no rows, but the `ALTER TABLE` takes an `ACCESS EXCLUSIVE`
lock on `domains` while the catalog changes, so reads and writes to it,
signup's auto-formation included, wait that long. While the `ALTER` waits
for that lock behind a transaction that has `domains` open, new reads and
writes to `domains` queue behind it too, for up to the migration's 10-second
`lock_timeout`. The agent-governance
trigger of 0046 fires on a domain's status, tenant or name only, so writing
`allow_join` signs no agent out.

This release reads `allow_join` on every read of `domains`, so until 0051
has run every such read fails on its replicas. A call that reads a domain
fails with an error, except the login-policy lookup, which fails open for
people by design:
sign-ins on a tenant's domains stop applying its login policy (SSO only,
allowed methods, 2FA, password length), and the only trace is a
`login_policy_domain_lookup_failed` WARN line. `GATEWAY_POSTGRES_AUTO_MIGRATE`
is off by default, so run `identity migrate` as its own job, and let it
finish, before the deploy starts. Replicas of the previous release keep
working against the new schema.

During the rolling deploy, replicas of the previous release answer the
three new RPCs with `UNIMPLEMENTED` and return a `Domain` without
`allow_join`, which reads as `false`. A client should not offer the toggle
or the join until every replica runs this release.

On a
lock timeout the file rolls back and version 51 is recorded dirty: run
`identity migrate force 50`, then `identity migrate` again. The down
migration drops the column, and with it every tenant's choice.

### Go API

`Domain` gains `AllowJoin`. `DomainStore` gains
`SetDomainAllowJoin(ctx, projectID, domainID, allowJoin) (*Domain, bool, error)`,
which returns the domain as it then stands and whether the call changed it:
`nil` for an unknown domain, and the domain with `false` when it already
has the value. It must not change the domain's status, tenant or name. `MembershipService.WithDomains(DomainStore)` enables
`ListJoinableTenants` and `JoinTenantByDomain` (without it both return
`UNIMPLEMENTED`), and `DomainService.WithAudit` records `SetDomainJoin`;
`internal/app` wires both.

## Next — teammate keys: `TeammateKeyService`, and `teammate_key_id` on the machine challenge and exchange (migration 0050; additive RPCs and fields behind `GATEWAY_TEAMMATE_KEYS_ENABLED`, off by default; the `teammate_key_manager` credential kind; `jwt.TeammateSigner` and `jwt.VerifyTeammateAccessToken` (Go API))

A service that manages workstations can register a key for an agent account,
bound to one claim on one workstation, and revoke it when the claim ends. The
workstation exchanges a single-use challenge signed with that key, Ed25519 or
ECDSA P-256, for a 300-second `at+jwt` access token whose `sub` is the agent
and which carries `claim_id`, `workstation_id` and `company_id` from the key.

- Migration 0050 adds `teammate_keys` and `teammate_key_challenges` and widens
  `project_credentials_kind_check` with `teammate_key_manager`. It holds
  ACCESS EXCLUSIVE on `project_credentials` while it validates the new check.
  Rolling it back deletes teammate keys and their credentials.
- `GATEWAY_TEAMMATE_KEYS_ENABLED` (default `false`) mounts
  `identity.v1.TeammateKeyService` and lets `CreateAgentMachineChallenge` and
  `ExchangeAgentMachineCredential` take `teammate_key_id`. Turning it on needs
  the postgres driver, `GATEWAY_JWT_ISSUER` and `GATEWAY_JWT_AUDIENCE`; boot
  fails without them. Off, a request naming a teammate key answers
  `FAILED_PRECONDITION` and the service is not served. The challenge and
  exchange share the `GATEWAY_AGENT_OAUTH_PROTOCOL_PER_IP` budget.
  `TeammateKeyService` is served over Connect and HTTP; an embedding host's
  native gRPC registration (`Server.RegisterGRPC`) does not carry it,
  while the teammate challenge and exchange work there as on HTTP.
- `RevokeTeammateKey` refuses the key for every challenge and exchange that
  starts after it returns. A token issued by an exchange that consumed its
  challenge just before the revocation committed stays valid until it expires,
  at most 300 seconds.
- The two `TeammateKeyService` RPCs share the `GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP`
  budget, applied to them separately from `LookupUsers`.
- Mint the managing service's credential with
  `AdminCreateProjectCredential(kind = "teammate_key_manager")` and present it
  in `X-Teammate-Key-Manager-Key`.
- Machine-agent exchanges are unchanged. They are now counted in
  `identity_agent_exchanges_total{key_kind="agent_machine"}`.
- Go API: `jwt.TeammateAccessClaims`, `jwt.TeammateSigner` (implemented by the
  file, AWS KMS and jwttest signers) and `jwt.VerifyTeammateAccessToken`.

## Next — tenant ownership moves: `TransferTenantOwnership` and `AdminRecoverTenantOwnership` (additive RPCs; no migration; removing a tenant's last owner refused atomically (behaviour change under concurrency); `MembershipStore.TransferOwnership`, `MembershipStore.RemoveMembership`, `MembershipStore.GrantMembership` and a required `UserDirectory` argument to `NewControlPlaneAdminService` (Go API))

A tenant's ownership could not move before: an owner could not hand the
tenant on, and a tenant that nobody could govern any more, because its
owners and admins had all lost their accounts, could not be governed again
without an `UPDATE` on `tenant_memberships`. Two RPCs fix that, each
audited.

- **`TransferTenantOwnership(tenant_id, user_id)`**, called by an owner with
  their access token, makes `user_id`, another active member of the tenant,
  an owner and the caller an admin, in one transaction, so the tenant is
  never left without an owner. It returns both memberships (`owner`,
  `previous_owner`) and records `tenant_ownership_transferred`, the caller
  as actor and the new owner as target. The new owner may already be a
  co-owner: the caller then steps down to admin and the tenant has one owner
  fewer. They must be an active, signed-up person with a verified email, as
  `CreateTenant` requires of its caller, since an owner sends the tenant's
  invitations. A member only through their email's domain must still be
  one, on a domain the tenant verifies. Their membership becomes an `added`
  one, so it does not end when the email leaves the domain; any other
  source is kept.
  - `PERMISSION_DENIED`: the caller is not an active owner, or the tenant
    is suspended. The tenant's status is read before the transfer's own
    transaction, so a suspension that lands in between does not stop it.
  - `NOT_FOUND`: `user_id` is not an active member.
  - `FAILED_PRECONDITION`: `user_id` cannot own a tenant.
  - `INVALID_ARGUMENT`: a blank id, or the caller's own.
  - A transfer is not idempotent: once it succeeds the caller is an admin,
    so a retry of it is `PERMISSION_DENIED`, as is the losing call of two
    racing transfers. A client that lost the response reads
    `ListTenantMembers` to see where ownership now stands.
- **`AdminRecoverTenantOwnership(project_id, tenant_id, user_id, reason)`**,
  with the `X-Admin-Secret` header, appoints an owner to a tenant nobody can
  govern: no owner or admin of it who is a person can sign in, because each
  was deleted, deactivated or merged away. The account must be one that
  could own a tenant (the same rule), and need not be a member; it gets an
  active `owner` membership, with source `added` unless it already held one
  with another source (`invited`, `created`), which is kept. It returns that
  membership and records `tenant_ownership_recovered` with the `reason`
  (required, at most 500 characters) and the operator's IP and user agent.
  - `FAILED_PRECONDITION`: an owner or an admin who is a person can still
    sign in, the account cannot own a tenant, or the tenant is `latent` (it
    has never had an owner). A `suspended` tenant can be recovered. An
    account pending deletion can still sign in (signing in cancels the
    deletion), so an owner or admin in that state still governs the tenant.
    While an owner can sign in, they transfer the tenant; while an admin
    can, they invite a new owner with `CreateTenantInvitation(role =
    "owner")`. A suspended tenant refuses both, so restore it first;
    recovering it before a restore helps only when nobody can sign in.
  - `NOT_FOUND`: an unknown tenant or account, or an account of another
    project.
  - `INVALID_ARGUMENT`: a blank id, or a reason that is blank, longer than
    500 characters, or holds a control or invisible formatting character.
  - `UNIMPLEMENTED` while `GATEWAY_ADMIN_API_SECRET` is unset, and
    `PERMISSION_DENIED` for a wrong `X-Admin-Secret`, like the other
    operator RPCs.
  - Naming an account that is already an owner who can sign in returns its
    membership unchanged and records nothing, before the account is judged
    again, so a retry after a lost response gets the first answer.
  - A refused recovery is not audited.
  - A deactivated or suspended account can be reactivated. An owner whose
    account comes back after a recovery is still an owner, beside the one
    the operator appointed, so make sure the account will not come back
    before recovering.

When every owner is gone and the admins left cannot be reached or will not
act, recovery stays refused while they can sign in. A project admin who
decides the tenant must be governed again deactivates those admins' accounts
with `DeactivateUser`, which is audited and reversible with `ReactivateUser`
but signs each account out everywhere, not only in this tenant, and the
operator then recovers the tenant. A reactivated admin is still an admin.

Recovery does not reuse `AdminAddTenantAdmin`, which provisions a tenant: it
is not audited, checks neither the account nor who governs the tenant, and
sets the role it is given, so it can lower an owner. An operator holding the
admin secret can therefore appoint an owner with it whoever governs the
tenant, without a record. Keep using it to seed a tenant's first admins, and
use recovery for a tenant nobody can govern.

Removing a tenant's last active owner was already refused, but the check
read the owners before the removal deleted, so two removals at once, or a
removal racing a transfer to the member removed, could leave the tenant
without an owner. `RemoveTenantMember` now checks and deletes in one
transaction that locks the tenant's owners, as a transfer does, so the
second of two such writes sees what the first did and is refused
(`FAILED_PRECONDITION`) or finds the member gone (`NOT_FOUND`).

One race is known: recovery reads who governs the tenant and then grants,
so two operators recovering one tenant at once, naming different accounts,
may each appoint an owner; both are audited.

### Go API

- `MembershipStore` gains `TransferOwnership(ctx, projectID, tenantID,
  fromUserID, toUserID) (from, to *TenantMembership, err error)`. It must
  lock the tenant's active owners and both memberships, refuse with
  `ErrPermissionDenied` unless `from` is an active owner and with
  `ErrNotFound` unless `to` is an active member, then make `to` an owner (a
  `domain` source becomes `added`) and `from` an admin in the same
  transaction.
- `MembershipStore.RemoveMembership` must refuse with `ErrLastOwner` to
  remove the tenant's last active owner, deciding under the same locks as
  `TransferOwnership`, so neither a concurrent removal nor a transfer can
  leave the tenant without an owner. `RemoveTenantMember` no longer checks
  first.
- `MembershipStore.GrantMembership` also returns whether it wrote anything:
  `(granted *TenantMembership, changed bool, err error)`, `changed` false
  when the membership already held the role and kept its source.
- `NewControlPlaneAdminService` takes a `users UserDirectory` after
  `memberships`, which it requires; `service.RepositoryUserDirectory(repo)`
  builds one.

## Next — an operator suspends and restores a tenant: `AdminSuspendTenant` and `AdminRestoreTenant` (additive RPCs; no migration; `TenantStore.SetTenantStatus` replaces `ClaimLatentTenant` (Go API))

A platform operator can now suspend a tenant and restore it over the API,
with the `X-Admin-Secret` header, where before it took an `UPDATE` on the
`tenants` table. Each call takes a required `reason` (at most 500
characters) and records it in the audit trail.

- **`AdminSuspendTenant(project_id, tenant_id, reason)`** moves a `claimed`
  tenant to `suspended` and records `tenant_suspended`. The suspension does
  what the SQL did ([Suspending a tenant](#suspending-a-tenant)): a refresh
  that chooses the tenant is `PERMISSION_DENIED`, the tokens that already
  chose it are refused by identity's HTTP chain within
  `GATEWAY_TENANT_STATUS_CACHE_TTL_SECONDS` (default 30, at most 300) and by
  a host that verifies tokens itself only when they expire, its owners and
  admins can no longer administer it, and the agent grants and machines of
  its members, in any membership status, and of the accounts on its verified
  domains and its primary domain are revoked. Its
  domains, members and invitations are kept, and its login policy keeps
  governing the sign-ins through its verified domains (see
  [Suspending a tenant](#suspending-a-tenant)).
- **`AdminRestoreTenant(project_id, tenant_id, reason)`** moves a
  `suspended` tenant back to `claimed` and records `tenant_restored`.
  Administration works again at once, and so does a refresh that chooses the
  tenant; identity's HTTP chain accepts the tokens that chose it within the
  same cache TTL, as each replica's cached status expires. Like any change
  of a tenant's status, **a restore revokes again** the agent grants and
  machines of the same members and accounts, including any connected while
  it was suspended; no grant revoked by the suspension comes back. A tenant
  with no creator and no owner or admin is `FAILED_PRECONDITION`: an
  auto-formed tenant suspended in SQL while it was still `latent` looks like
  that, and restoring it would make it selectable without anyone having
  verified its domain. A tenant you created with `AdminCreateTenant` and
  never gave an owner or admin is refused the same way, and so is one whose
  owners and admins were all deleted. Appoint an owner with
  `AdminRecoverTenantOwnership`, which is audited (or add an admin with
  `AdminAddTenantAdmin`), then restore it.

Both return the tenant as it now stands, and record the operator's IP
address and user agent with the reason. A tenant already in the status asked
for is returned unchanged and nothing is recorded, so a retry after a lost
response is safe; only the call that changes the status records its reason.
A tenant in any other status is `FAILED_PRECONDITION`: a `latent` tenant
governs nothing yet, so it cannot be suspended. An unknown tenant is
`NOT_FOUND`. A blank id is `INVALID_ARGUMENT`, and so is a reason that is
blank, longer than 500 characters, or holds a control or invisible
formatting character such as a newline; a reason is trimmed. The change is
compare-and-set, so two operators racing on one tenant record one change
between them; a call whose tenant changed status between its read and its
write is `ABORTED`, and reading the tenant again shows where it now stands.

Stop suspending tenants in SQL: an `UPDATE` is not audited. A tenant already
suspended that way is restored with `AdminRestoreTenant`.

### Go API

`TenantStore.ClaimLatentTenant(ctx, projectID, tenantID)` is replaced by
`SetTenantStatus(ctx, projectID, tenantID, from, to) (bool, error)`, which
moves the tenant only while it is in `from` and reports whether it moved; a
domain's verification claims a latent tenant with `SetTenantStatus(…,
"latent", "claimed")`. A custom `TenantStore` must implement it with the
same compare-and-set, and refuse with `service.ErrInvalidArgument` a status
that `service.IsTenantStatus` does not accept or a `from` equal to `to`. The
new `service.ErrTenantStatusChanged` is the lost race, mapped to `ABORTED`.

## Next — an operator reads a project's tenants: `AdminGetTenant` and `AdminListTenants` (migrations 0048 and 0049; additive RPCs; `TenantStore.ListTenants` takes a `TenantListQuery` (Go API))

A platform operator can now read a project's tenants with the
`X-Admin-Secret` header, as for the other control-plane admin RPCs. Both
return a tenant's own record (`Tenant`: id, name, primary domain, status,
creator and timestamps), never its members, domains or login policy. With
`GATEWAY_ADMIN_API_SECRET` unset they return `UNIMPLEMENTED`, as the other
admin RPCs do.

- **`AdminGetTenant(project_id, tenant_id)`** returns the tenant in any
  status. A tenant the project does not hold is `NOT_FOUND`; a blank id is
  `INVALID_ARGUMENT`.
- **`AdminListTenants(project_id, limit, cursor)`** returns one page of the
  project's tenants, latent, claimed and suspended alike, newest first by
  creation time, then id. `limit` defaults to 50 and is capped at 200. Pass
  each page's `next_cursor` back as `cursor` to read the next; it is empty on
  the last page. A blank `project_id`, or a cursor that does not decode, is
  `INVALID_ARGUMENT`. The cursor holds the last tenant's position, not an
  offset, so paging never repeats or skips a tenant that existed when it
  began; a tenant created meanwhile may or may not appear, since its
  creation time comes from the creating replica's clock. A cursor is not
  bound to the project it came from: the page is always of `project_id`'s
  tenants alone, and a project with no tenants, or one that does not exist,
  is an empty page.

### Migrations 0048 and 0049

0048 builds `tenants_project_created_idx` on `tenants (project_id,
created_at_ms, id)`, which serves the listing's order. The build holds a
`SHARE` lock on `tenants` for its duration: reads continue, and writes to
`tenants` (auto-formation at signup, `CreateTenant`, `AdminCreateTenant`, a
domain's verification) wait for it. 0049 then drops `tenants_project_idx`,
which the new index makes redundant, in its own transaction: its `ACCESS
EXCLUSIVE` lock is held for a moment, but while it waits for transactions
already using `tenants`, new reads and writes of `tenants` queue behind it,
for at most the 10s `lock_timeout`.

On a large `tenants` table, build the index first without blocking writes,
and 0048 then skips the build:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS tenants_project_created_idx
    ON tenants (project_id, created_at_ms, id);
```

Use exactly this name and definition: the migration skips what exists
without comparing it. A `CONCURRENTLY` build that fails leaves an invalid
index under that name, which `IF NOT EXISTS` skips too; 0049 would still
drop `tenants_project_idx`, and every listing would then read and sort the
project's tenants with nothing reporting an error. Check the index before
migrating, and drop and rebuild it if it is not valid:

```sql
SELECT indisvalid FROM pg_index
 WHERE indexrelid = 'tenants_project_created_idx'::regclass;
-- false: DROP INDEX CONCURRENTLY tenants_project_created_idx; then build it again.
```

Once it is valid, drop the old index the same way, and 0049 has nothing
left to wait for (it drops `IF EXISTS`):

```sql
DROP INDEX CONCURRENTLY IF EXISTS tenants_project_idx;
```

Replicas of the previous release keep working against the new schema, so the
migrations can run before or during a rolling deploy. Each file rolls back on
its own failure. If 0048 fails (a lock timeout, or a build that fails),
version 48 is recorded dirty: run `identity migrate force 47`, then
`identity migrate` again. If 0049 times out, version 49 is recorded dirty:
run `identity migrate force 48`, then `identity migrate` again. The down
migrations restore `tenants_project_idx` and drop the new index; nothing else
changes.

### Go API

`TenantStore.ListTenants(ctx, projectID)` is now
`ListTenants(ctx, service.TenantListQuery{ProjectID, After, Limit})`: it
returns at most `Limit` tenants, newest first, after the position `After`. A
custom `TenantStore` must implement the new signature.

## Next — self-service tenants and tenant selection on `RefreshToken` (migrations 0044, 0045, 0046, which rewrites `users`, and 0047; stop every earlier replica before migrating; `RefreshTokenRequest.tenant_id` behind `GATEWAY_TENANT_SELECTION_ENABLED`, off by default (additive); contested domain claims, a per-tenant TXT challenge, domain and invitation limits, agent sign-outs scoped to the users a change governs, domain memberships that need a verified email on a verified domain and end when the email leaves it, the product age gate checked before a refresh token is spent, a suspended tenant's admin calls refused, accepting an invitation only with a verified email (behaviour changes); `MembershipStore`, `TenantStore`, `DomainStore`, `InvitationStore`, `UserDirectory`, `AuthService.RefreshToken` and the auth middleware (Go API); verifiers that pin the `tenant` claim (behaviour change when used))

A signed-in person can now create a tenant they own, list the tenants they
belong to, and get an access token for one of them. The rationale, and what
the `tenant` claim does and does not assert, is
[ADR-0018](./adr/0018-self-service-tenants-and-tenant-selection.md).

- **`CreateTenant(name)`** creates a claimed tenant and the caller's active
  `owner` membership (source `created`) in one transaction, and records a
  `tenant_created` audit event. It is off by default. A project turns it on
  in its `config_json`:

  ```json
  { "tenants": { "self_service": true } }
  ```

  The default project takes the same setting from
  `GATEWAY_SELF_SERVICE_TENANTS_ENABLED` (default `false`), but only for a
  request that falls through to it, naming no project by key or auth
  hostname. A request that reaches the default project by its own project
  key or auth hostname reads that project's `config_json`, so set
  `tenants.self_service` there too if clients reach it that way. Refusals:
  no caller → `UNAUTHENTICATED`; the setting off, or a caller who has not
  verified their email → `FAILED_PRECONDITION`; a
  name that is blank after trimming, longer than 100 characters, invalid
  UTF-8 or carrying control or format characters → `INVALID_ARGUMENT`; an
  anonymous, agent, merged or inactive account → `PERMISSION_DENIED`; over
  the limit → `RESOURCE_EXHAUSTED`, audited as a failed `tenant_created`
  with reason `creation_limit`.
- **The limit** is deployment-wide: at most
  `GATEWAY_SELF_SERVICE_TENANTS_MAX_PER_USER` tenants (default 10, at most
  1000; `0` selects the default) per user per project in
  `GATEWAY_SELF_SERVICE_TENANTS_WINDOW_SECONDS` (default 86400, at most 30
  days). Concurrent calls by one user are serialised, so the limit holds
  under a race. The RPC also has a per-IP budget of its own, tag
  `tenant_create`, the size of the signup budget
  (`GATEWAY_RATE_LIMIT_SIGNUP_PER_IP`) but not shared with it, on the HTTP
  surface only ([Per-IP budgets are HTTP only](#per-ip-budgets-are-http-only)).
  `CreateTenant` takes no idempotency key: a retried call can create a
  second tenant, bounded by the limit. Reconcile with `ListMyTenants`.
- **`ListMyTenants()`** returns `{tenant_id, name, role}` for every claimed
  tenant in the project where the caller's membership is active, ordered by
  name. A membership that came from the email's domain is listed only while
  that email is verified and on a domain the tenant has verified (see
  [Domain memberships](#domain-memberships-follow-the-verified-email-behaviour-change)).
  It does not depend on the setting.
- **`RefreshTokenRequest.tenant_id`** (field 2) asks for an access token
  whose `tenant` claim is that tenant. It is off by default: a server
  answers it only with `GATEWAY_TENANT_SELECTION_ENABLED=true` on the
  Postgres driver, and otherwise refuses it with `FAILED_PRECONDITION`.
  When on, it is granted only to an active member of a claimed tenant in
  the session's project, and a member only through their email's domain
  must have verified that email and still be on a domain the tenant has
  verified, and the tenant's login policy must admit the session (see What
  the claim asserts). Anything else is `PERMISSION_DENIED` (`UNAVAILABLE`
  when the membership or the policy could not be read; the message is
  generic, and the store's error is logged as
  `tenant_selection_lookup_failed`). Each of these refusals carries a
  `TenantSelectionRefusedDetails` error detail naming its reason
  (`NOT_ENABLED`, `NOT_A_MEMBER`, `LOGIN_POLICY` or `UNAVAILABLE`), issues no token and does
  **not** consume the refresh token, so a client that finds the detail
  refreshes again without `tenant_id`. The code alone does not say which
  refusal it is: `RefreshToken` refuses an account over its own state (not
  active, or needing an identity verification) with the same codes, before
  it looks at the tenant, and that refusal may have consumed the token,
  which a retry would replay, signing the account out everywhere. So retry
  only when the detail is present. Omitting the field, or sending the
  default tenant, keeps today's behaviour: the claim is the deployment default
  (`GATEWAY_DEFAULT_TENANT_ID`). The selection is not sticky: each refresh
  chooses again, and one without `tenant_id` returns to the default. A
  client reads the tenant it got from the access token's `tenant` claim.
  A `tenant_id` longer than 64 characters, or holding anything but ASCII
  letters, digits, `-` and `_`, is `INVALID_ARGUMENT`, with no detail,
  before the refresh token is read. A server with selection on and
  `GATEWAY_DEFAULT_TENANT_ID` empty refuses to start.
- **The product age gate is checked before the refresh token is spent.**
  For an active account, `RefreshToken` now refuses a product the account is
  too young for (`PERMISSION_DENIED`, as before) before it consumes the
  refresh token, as it already did for anonymous sessions, so a product that
  gains a minimum age mid-session no longer spends the account's token.
  The refusal carries no selection detail: refreshing again without
  `tenant_id` is refused the same way.
- **What the claim asserts.** A selected `tenant` asserts membership, and
  that the tenant's login policy admitted the session when the token was
  issued. The `role` claim is still the account's role and is **never** a
  role in that tenant; a service that needs the tenant role reads it from
  `ListMyTenants`. A policy that limits how its users sign in (SSO
  required, 2FA required, or allowed methods) admits only a session it
  governed at sign-in, one whose account's email is on a domain the tenant
  has verified: a session does not record how it signed in, so a member
  from another domain is refused with `LOGIN_POLICY` whatever method they
  used. The policy's session timeouts apply to every selection, and a
  session past them is refused the same way, logged as
  `tenant_selection_refused_by_login_policy`.
- **Revocation.** Identity's own HTTP middleware accepts a token whose
  `tenant` claim is the default or a claimed tenant of the token's project.
  It reads a selected tenant's status through an in-process cache, so
  suspending a tenant refuses its tokens within
  `GATEWAY_TENANT_STATUS_CACHE_TTL_SECONDS` (default 30, at most 300; `0`
  reads the store on every request). A read that fails is never cached: the
  request is answered `503`, on auth-exempt paths too, and logged as
  `token_tenant_lookup_failed` without the token. The histogram
  `identity_token_tenant_lookup_duration_seconds` times the reads, labelled
  `outcome` (`hit`, `miss`, `error`). Ending a membership takes
  effect at the next refresh, so a selected token outlives it by at most the
  access-token lifetime (`GATEWAY_JWT_EXPIRY_SECONDS`), in `mode=session`
  too: removing a member ends none of their sessions. Over native gRPC the
  host verifies tokens itself, so a suspension takes effect there when the
  token expires unless the host checks the tenant's status as
  `docs/embedding.md` describes.
- **Accounts in other projects.** `CreateTenant` and
  `AcceptTenantInvitation` look the caller up in the request's project.
  `AcceptTenantInvitation` used to look in the default project, so a caller
  signed in to any other project could not accept an invitation; that is
  fixed.

### Domain registrations are claims until verified (behaviour change)

Self-service tenants make anyone a tenant admin, so registering a domain no
longer captures its signups:

- **Several tenants may register the same domain.** `CreateDomain` refuses a
  domain only when the same tenant already holds it, or another tenant has
  verified it (`ALREADY_EXISTS`). The tenant that verifies first holds the
  only verified row; `VerifyDomain` for a later claimant then fails with
  `ALREADY_EXISTS` ("verified by another tenant"). That answer tells a
  tenant admin that another tenant in the project has onboarded the domain.
  The disclosure is accepted; every such call, refused or not, counts
  toward the tenant's attempt limit below, so it cannot sweep a project's
  domains.
- **Auto-formation joins only a proven tenant.** A signup on a non-public
  domain joins the tenant that verified the domain, or else the latent tenant
  auto-formation made for it (creating it on the domain's first signup). It
  never joins a tenant that merely registered the domain, and no longer
  joins a suspended tenant, whether it verified the domain or auto-formation
  made it: the next signup on the domain joins or forms a latent tenant
  instead, and a reinstated tenant takes the domain's signups again. A signup that already holds a membership in the tenant,
  invited, added or created, keeps that source; auto-formation used to
  relabel it `domain`.
- **The DNS TXT challenge now names the tenant.** `CreateDomain` returns a
  value derived from the project, the tenant and the domain, so the record
  one claimant publishes verifies no other claim. A `dns_txt` registration
  made before migration 0045 keeps accepting the value it was issued, so a
  record you already published still verifies; new registrations must
  publish the value they are given.
- **Domain registrations and verifications are limited.** A tenant may make
  `GATEWAY_TENANT_DOMAIN_ATTEMPTS_MAX_PER_TENANT` (default 100, at most
  10000; `0` selects the default) `CreateDomain` and `VerifyDomain` calls
  together in `GATEWAY_TENANT_DOMAIN_ATTEMPTS_WINDOW_SECONDS` (default
  86400, at most 30 days). Past that they are `RESOURCE_EXHAUSTED`, logged as
  `tenant_domain_attempts_limited`. Only a caller who administers the tenant
  spends its budget. Both RPCs also share a per-IP budget,
  `GATEWAY_RATE_LIMIT_DOMAIN_PER_IP` (default 20 per rate-limit window, tag
  `tenant_domain`; `0` switches it off), on the HTTP surface only
  ([Per-IP budgets are HTTP only](#per-ip-budgets-are-http-only)).
- **A failed check no longer un-verifies a domain.** `VerifyDomain` on a
  verified domain whose TXT record has gone leaves it verified; only an
  unverified claim is marked `failed`. An operator removes a domain its
  tenant no longer holds.
- **A suspended tenant verifies nothing.** Its `VerifyDomain` is
  `PERMISSION_DENIED`: verifying claims the tenant, which would lift the
  suspension.

### Domain memberships follow the verified email (behaviour change)

A membership with source `domain` comes from the account's email, so it
counts only while the email is the tenant's. `ListMyTenants` lists it and
a refresh selects its tenant only while the account's email is verified
and on a domain the tenant has verified; before, an account that signed up
unverified on the domain, or moved its email off it, kept the tenant.
Memberships from an invitation, a grant or a tenant's creation are not
affected.

Migration 0047 also ends a domain membership when the email leaves the
tenant's verified domains: confirming an email change, a SCIM or admin
update of the email and an account merge set it `inactive` in the same
transaction as the change. Coming back to the domain does not rejoin the
tenant; invite the account again.

### Agent sign-outs follow the users a change governs (behaviour change)

A tenant or domain change used to revoke every delegated agent grant and
agent machine in the project, on every write to those rows. With
self-service tenants that let any tenant owner sign out a whole project's
agents: a failed `VerifyDomain` on an unproven claim was enough. Migration
0046 narrows it:

- **Only a change that moves governance revokes.** A domain row that is, or
  becomes, verified changing status, tenant or name, or one inserted
  verified or deleted while verified; a tenant changing status or primary
  domain. A pending claim turning `failed`, or a status written again
  unchanged, revokes nothing, and the service no longer makes such writes.
- **It revokes only the governed users' agents:** the members of the tenants
  involved, in any membership status, and the accounts whose email is on
  the domains involved. A pending agent request with no owner yet is not
  revoked by these changes.
- **Login-policy and project changes still revoke project-wide.** They are
  operator actions.

### Suspending a tenant

An operator suspends a tenant with `AdminSuspendTenant` and restores it with
`AdminRestoreTenant` (above); suspending it in SQL leaves no audit record.

A suspension revokes the agent grants and machines of the tenant's members,
in any membership status, and of the accounts on its verified domains and
its primary domain. Its selected tokens are refused by identity's HTTP chain
within the tenant-status cache TTL, and by a host that verifies tokens
itself only when they expire. Its owners and admins are refused
(`PERMISSION_DENIED`) by every domain and membership RPC, and an invitation
to it can no longer be accepted; its domains, members and pending
invitations are kept. Its members keep their accounts and their
default-tenant tokens, and the tenant's login policy keeps governing the
sign-ins through its verified domains: its allowed methods, SSO and 2FA
requirements, password minimum and session timeouts apply to those accounts
while it is suspended as they did while it was claimed. A suspension never
loosens sign-in controls.

Restoring it gives back selection, at once for a refresh and within the
cache TTL on identity's HTTP chain, and administration, at once. It leaves
sign-in as it was, and, like every change of a tenant's status, revokes
again the agent grants and machines of the same members and accounts,
including any connected during the suspension. It revives no grant the
suspension revoked.

### Accepting an invitation needs a verified email (behaviour change)

`AcceptTenantInvitation` now refuses a caller whose email is unverified with
`FAILED_PRECONDITION`, after checking that it is the invited address. The
invitation stays pending, so the invitee verifies their email and accepts
again. `CreateTenant` asks the same of its caller.

### Invitation limits (behaviour change)

Every `CreateTenantInvitation` sends an email, so it is now bounded five
ways. Past any limit but the per-IP one the call is `RESOURCE_EXHAUSTED`,
logged as `tenant_invitation_limited` with the recipient redacted, and
nothing is sent or stored. Past the per-IP one it is refused before the RPC
runs ([Per-IP budgets are HTTP only](#per-ip-budgets-are-http-only)):

- per client IP: `GATEWAY_RATE_LIMIT_INVITATION_PER_IP` (default 20 per
  rate-limit window, tag `tenant_invitation`; `0` switches it off), on the
  HTTP surface only;
- per tenant: `GATEWAY_TENANT_INVITATION_MAX_PER_TENANT` invitations (default
  100, at most 100000; `0` selects the default) in
  `GATEWAY_TENANT_INVITATION_WINDOW_SECONDS` (default 86400, at most 30 days),
  counting every invitation created, whatever its status;
- per inviter: `GATEWAY_TENANT_INVITATION_MAX_PER_INVITER` invitations
  (default 100, at most 100000; `0` selects the default) from one user's
  tenants together in the same window, so creating more tenants sends no
  more email;
- per tenant and recipient: `GATEWAY_TENANT_INVITATION_MAX_PER_RECIPIENT`
  invitations (default 10, at most 1000; `0` selects the default) from one
  tenant to one address in the same window. Each tenant has its own count,
  so one tenant reaching it never stops another inviting that address;
- resend cooldown: inviting the same address from the same tenant again
  within `GATEWAY_TENANT_INVITATION_RESEND_COOLDOWN_SECONDS` (default
  300, at most 86400; `0` selects the default) is refused.

The limits apply to every tenant, operator-created ones included. Bulk
onboarding meets three of them: a tenant inviting more than 100 people a
day needs a higher `GATEWAY_TENANT_INVITATION_MAX_PER_TENANT`, an admin
sending them a higher `GATEWAY_TENANT_INVITATION_MAX_PER_INVITER`, and one
client sending more than 20 per rate-limit window a higher
`GATEWAY_RATE_LIMIT_INVITATION_PER_IP`. The invitation email no longer
names a self-service tenant, whose name its creator typed; it invites to "a
team". Operator-created and domain tenants are named as before.

Accepting an invitation never lowers a role. An owner or admin who accepts
a `member` invitation keeps the role they hold; it used to replace it, so an
invitation could demote a tenant's last owner.

### Per-IP budgets are HTTP only

The three per-client-IP budgets above, `tenant_create` (`CreateTenant`),
`tenant_domain` (`CreateDomain` and `VerifyDomain`) and `tenant_invitation`
(`CreateTenantInvitation`), are enforced by identity's HTTP middleware
before the RPC runs. Past one, the call gets HTTP status 429 with a
`Retry-After` header of the rate-limit window in seconds
(`GATEWAY_RATE_LIMIT_WINDOW_SECONDS`), which a Connect client surfaces as
`UNAVAILABLE`, not `RESOURCE_EXHAUSTED`: retry after that many seconds. A
host that serves identity's services over native gRPC (`docs/embedding.md`)
gets none of these budgets and applies its own.

### Migration

`0047_end_domain_memberships_off_domain` adds the function
`end_domain_memberships_off_domain` and an `AFTER UPDATE OF email` trigger
on `users`, `tenant_domain_membership_email`, which fires only when
`users.email_domain` changes. It is catalog-only: it rewrites nothing and
ends no existing membership, since the read rule above already refuses a
domain membership whose email left the domain before the upgrade. Creating
the trigger takes a `SHARE ROW EXCLUSIVE` lock on `users`, which blocks
writes, not reads, for the moment it holds it; `lock_timeout = 10s` bounds
the wait to acquire it. If it fails, version 47 is left dirty: confirm the
function is absent, then run `identity migrate force 46` and `identity
migrate` again. Its down migration drops the trigger and the function;
memberships it ended stay ended.

`0046_scope_governance_revocation` **rewrites `users`.** It adds
`users.email_domain`, a stored generated column holding the address's
domain under 0034's ASCII fold, and `users_project_email_domain_idx` on
`(project_id, email_domain)`, through which the scoped triggers above find
the accounts on a domain. It is a column rather than an index on an
expression for 0034's reason: under `FORCE ROW LEVEL SECURITY` only a
leakproof comparison can use an index, and `lower()` and `substring()` are
not leakproof, so an expression index would serve only `project_id` and
every trigger that fires would read every account in the project. The
migration also replaces the tenant and domain agent governance triggers
with the guarded, scoped ones above, adds the `domain_attempts` table,
replaces `tenant_invitations (project_id, tenant_id)` with three indexes
over `created_at_ms` (per tenant, per inviter, and per tenant and recipient)
for the limits,
adds a partial index on email-method `domains` rows for auto-formation,
drops `domains (project_id, tenant_id)`, which 0045's unique index covers,
and validates 0044's widened `tenant_memberships.source` check.

**Locking and sizing.** It takes these locks in this order, and holds each
until it commits:

- adding the column rewrites the whole `users` table under an `ACCESS
  EXCLUSIVE` lock, and its index is then built in the same transaction:
  sign-in, token refresh, SCIM and every other read or write of `users`
  waits until both finish, for a time that grows with the table;
- each other `CREATE INDEX` holds a `SHARE` lock on its table, which blocks
  writes to it but not reads;
- `VALIDATE CONSTRAINT` holds a `SHARE UPDATE EXCLUSIVE` lock on
  `tenant_memberships`, which blocks neither;
- the `DROP INDEX` and `DROP TRIGGER` statements come last and take `ACCESS
  EXCLUSIVE` locks on `tenant_invitations`, `domains` and `tenants`, so from
  then until the commit reads of those tables wait too.

Estimate the rewrite by timing the migration on a restored copy of
production, or at least check the table's size:

```sql
SELECT pg_size_pretty(pg_total_relation_size('users'));
```

**Do not rely on auto-migrate for a large `users` table**, for the reason
given under [migration 0034](#migration-0034-rewrites-users-postgres): a
probe that gives up first restarts the booting replica part-way through the
rewrite. Auto-migrate is in any case unsafe for this release while an
earlier replica runs (see Rolling out). `lock_timeout = 10s` bounds only the
wait to acquire each lock, not the rewrite.

**Pre-building the column.** Both statements are guarded with `IF NOT
EXISTS`, so you can add the column and build its index yourself beforehand,
as a role that owns the tables, while the earlier release still serves (it
reads only the columns it names):

```sql
-- 1. In a window: the rewrite (ACCESS EXCLUSIVE on users for its duration).
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_domain TEXT COLLATE "C"
    GENERATED ALWAYS AS (substring(lower(email COLLATE "C") FROM '@([^@]*)$')) STORED;
-- 2. Afterwards, without blocking writes (not inside a transaction):
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_project_email_domain_idx
    ON users (project_id, email_domain) WHERE email_domain IS NOT NULL;
-- 3. Then, with the earlier replicas stopped, `identity migrate`.
```

Use exactly these names and definitions: the migration skips what exists
without comparing it. A `CONCURRENTLY` build that fails leaves an invalid
index under that name, which `IF NOT EXISTS` skips too, and the triggers
would then scan the project's accounts. Check the index before migrating,
and drop and rebuild it if it is not valid:

```sql
SELECT indisvalid FROM pg_index
 WHERE indexrelid = 'users_project_email_domain_idx'::regclass;
-- false: DROP INDEX CONCURRENTLY users_project_email_domain_idx; then step 2 again.
```

**If 0046 fails.** On a lock timeout, or any other failure, the migration
rolls back as one transaction and version 46 is left dirty: confirm the
table `domain_attempts` is absent, then run `identity migrate force 45` and
`identity migrate` again. A column and index you pre-built stay, and are
skipped.

**Its down migration** restores 0041's unguarded triggers, which revoke
project-wide again, drops `domain_attempts`, which holds only limit
history, and drops `users.email_domain` and its index (catalog-only: `users`
is not rewritten).

`0045_contest_domain_claims` adds `domains.legacy_txt_challenge` (`BOOLEAN
NOT NULL DEFAULT false`, catalog-only) and sets it on every existing `dns_txt`
row. It replaces the unique index on `(project_id, lower(domain))` with a
unique index over verified rows only, a unique index on `(project_id,
tenant_id, lower(domain))` and a plain lookup index. Its `ALTER` takes an
`ACCESS EXCLUSIVE` lock on `domains` that is held until the migration commits,
so reads and writes on `domains` wait for the index builds; `lock_timeout =
10s` bounds the wait to acquire it. If it times out, version 45 is left dirty:
confirm `domains.legacy_txt_challenge` is absent, then run `identity migrate
force 44` and `identity migrate` again. The down migration keeps one row per
domain (the verified one, else the oldest) and **deletes the others**, then
restores the old index.

`0044_add_self_service_tenants` adds `tenants.created_by` (`TEXT NOT NULL
DEFAULT ''`, catalog-only), a partial index on `(project_id, created_by,
created_at_ms)`, and widens the `tenant_memberships.source` check to admit
`created` (added `NOT VALID`, so no table scan). It takes a short `ACCESS
EXCLUSIVE` lock on both tables, bounded by `lock_timeout = 10s`. The down
migration maps `created` memberships to `added` before restoring the old
check.

Self-service tenants and tenant selection need the Postgres driver. On the
memory and SQLite drivers, setting `GATEWAY_SELF_SERVICE_TENANTS_ENABLED`
or `GATEWAY_TENANT_SELECTION_ENABLED` fails at boot, and so does a host that
injects its own repository without the tenant stores. With both off,
`CreateTenant` and `ListMyTenants` answer `UNIMPLEMENTED` there, as the
other membership RPCs do, and `RefreshToken` refuses `tenant_id` with
`FAILED_PRECONDITION`.

### Rolling out

An earlier replica enforces none of the rules above, and beside migrations
0045 and 0046 it does harm, so this release does not roll replica by
replica. In this order:

1. **On the release you run now, settle your domain registrations** in a
   window in which agents can authorize again (see "Operators who
   registered a domain" below), and pre-build `users.email_domain` if
   `users` is large (above).
2. **Stop every replica of the earlier release before migrating.** Beside
   0045 and 0046, an earlier replica forms a second latent tenant for a
   domain that already has one, puts a signup into whichever tenant's
   unverified claim it reads first, and issues and accepts the old
   project-wide TXT value for new claims, which one claimant can satisfy
   with the record another tenant published. Neither a rolling deploy nor
   `GATEWAY_POSTGRES_AUTO_MIGRATE` beside earlier replicas is safe.
3. **Migrate, then start this release.** Run `identity migrate` as its own
   job; this release's replicas need 0044 to 0047 before they serve.
4. **Turn on self-service tenants** (`tenants.self_service`,
   `GATEWAY_SELF_SERVICE_TENANTS_ENABLED`) only once every replica runs this
   release.
5. **Turn on `GATEWAY_TENANT_SELECTION_ENABLED` on every replica before any
   client sends `tenant_id`**, and only once every resource server that
   checks the `tenant` claim accepts a selected one. A replica without it,
   or an earlier one, answers a selected tenant's token with `401`. On
   refresh, a replica without it refuses `tenant_id` with
   `FAILED_PRECONDITION` and the `NOT_ENABLED` detail, leaving the refresh
   token unspent, and an earlier one ignores the field and issues a
   default-tenant token.

**Rolling back.**

- Have clients stop sending `tenant_id` first. Turning
  `GATEWAY_TENANT_SELECTION_ENABLED` off then rejects every outstanding
  selected token at once (`401`); a client refreshes without `tenant_id`,
  and its refresh token still works. Running an earlier release has the
  same effect on selected tokens.
- To migrate down, stop this release's replicas first. The earlier release
  lets any registration capture its domain's signups, verified or not, so
  while 0046 is still in place, and its triggers revoke nothing for it,
  delete the unverified claims of self-service tenants:

  ```sql
  DELETE FROM domains d USING tenants t
   WHERE t.project_id = d.project_id AND t.id = d.tenant_id
     AND t.created_by <> '' AND d.status <> 'verified';
  ```

  0047's down migration drops its trigger; memberships it ended stay
  ended. Then 0046's down migration restores 0041's project-wide triggers. 0045's
  keeps one registration per domain (the verified one, else the oldest) and
  deletes the other claims; each delete fires those triggers, so every agent
  in a project that loses a claim signs in again. 0044's maps `created`
  memberships to `added`. Self-service tenants stay, as claimed tenants with
  their owners.

### Who has to act

- **Services that verify identity's tokens themselves.** If you call
  `pkg/jwt.VerifyAccessToken` with an expected tenant, or otherwise pin the
  `tenant` claim to the default, a token with a selected tenant fails there.
  Nothing changes until a client sends `tenant_id`; before you let clients
  select, accept a non-default `tenant` and authorise on it.
- **Operators who registered a domain and rely on it.** On the earlier
  release any registration captured its domain's signups, verified or not;
  on this one only a verified registration does, or else the latent tenant
  the domain formed. A signup on a domain whose registration is unverified
  when this release starts forms its own latent tenant and is not moved
  later. Find the registrations to act on. Before the upgrade, when
  `tenants.created_by` does not exist yet:

  ```sql
  SELECT d.* FROM domains d
    JOIN tenants t ON t.project_id = d.project_id AND t.id = d.tenant_id
   WHERE d.status <> 'verified'
     AND NOT (d.verification_method = 'email' AND t.status = 'latent');
  ```

  After it, the same query with `t.created_by = ''`, which leaves out the
  claims of self-service tenants, whose admins verify them:

  ```sql
  SELECT d.* FROM domains d
    JOIN tenants t ON t.project_id = d.project_id AND t.id = d.tenant_id
   WHERE d.status <> 'verified' AND t.created_by = ''
     AND NOT (d.verification_method = 'email' AND t.status = 'latent');
  ```

  Each row is one of two kinds:

  - **`dns_txt`.** Make sure the TXT record `CreateDomain` gave you is
    published, then call `VerifyDomain(domain_id)`.
  - **`email`.** `VerifyDomain` does not implement this method, so replace
    the row with a `dns_txt` registration. Delete it (`domains` has no
    row-level security, and no RPC removes a domain):

    ```sql
    DELETE FROM domains
     WHERE project_id = '<project>' AND id = '<domain id>'
       AND verification_method = 'email' AND status <> 'verified';
    ```

    Then call `CreateDomain(tenant_id, domain, verification_method =
    "dns_txt")`, publish its `dns_txt_value` as a TXT record at
    `dns_txt_name`, and call `VerifyDomain` with the new `domain_id`. A
    record published on the earlier release stays valid after the upgrade:
    0045 marks every existing `dns_txt` registration legacy, and such a
    registration keeps accepting the value it was issued.

  Doing this **before the upgrade** is recommended. On the earlier release,
  0041's triggers revoke every agent grant and agent machine in the project
  on the `DELETE` and on each `VerifyDomain`, a failed one included (the
  pending `CreateDomain` insert revokes nothing). Done back to back, in one
  window in which agents can authorize again, that costs one project-wide
  agent sign-out and misplaces no signup. Call `CreateDomain` straight after
  the `DELETE`: the earlier release allows one registration per domain, and
  a signup in between forms a latent tenant that takes it, after which
  `CreateDomain` answers `ALREADY_EXISTS` and the domain can only be
  registered after the upgrade.

  Doing it **after the upgrade** revokes less: 0046 revokes only the agents
  of the users each change governs, and deleting an unverified row revokes
  nothing. But from the moment this release starts until each registration
  is verified, signups on its domain form a latent tenant and stay there;
  invite them to the operator's tenant afterwards.
- **Clients that select a tenant.** Send `tenant_id` only once every replica
  runs this release with `GATEWAY_TENANT_SELECTION_ENABLED` on (Rolling out,
  step 5), read the granted tenant from the access token's `tenant` claim
  rather than assuming the request was honoured. When `RefreshToken`
  refuses, refresh again without `tenant_id` only if the error carries
  `TenantSelectionRefusedDetails`; any other refusal may have spent the
  refresh token, so do not retry it.
- **Embedders with their own stores** (these are `internal/` packages, so
  this matters only to forks). `service.TenantStore` gains
  `CreateOwnedTenant` and `GetTenantStatus`, and its `SetTenantStatus`
  compares and sets (below), so a domain's verification moves a tenant to
  claimed only while it is still latent and a suspension made during a
  verification stands; `service.MembershipStore` gains
  `ListActiveTenantsForUser` and `GetActiveTenantForUser` (through the new
  `UserTenantReader`), which must only return a tenant that is claimed, in
  the given project, with the user's membership active. Both take the
  caller's email domain, `""` unless the email is verified, and must count
  a membership whose source is `domain` only when that domain is one the
  tenant has verified.
  `service.InvitationStore.CreateInvitation` takes a
  `service.InvitationLimits` and must enforce it under a per-tenant lock.
  `service.UserDirectory` is now `GetUserInProject(ctx, projectID, userID)`;
  `service.RepositoryUserDirectory` adapts a `Repository`.
  `service.DomainStore.CreateDomain` must allow several tenants' claims on one
  domain and refuse one only against the same tenant or a verified row.
  `GetDomainByName` is replaced by `GetVerifiedDomain`, which returns only
  the verified row, and `RecordDomainAttempt` must enforce
  `service.DomainAttempt`'s cap under a per-tenant lock.
  `service.MembershipStore` gains `GrantMembership`, which must never lower
  a role, and gives a kept membership whose source is `domain` the granted
  source while leaving any other source as it is. `SetTenantStatus` becomes
  a compare-and-set, `SetTenantStatus(ctx, projectID, tenantID, from, to)
  (bool, error)`, which moves a tenant only while it is in `from`; a domain's
  verification claims a latent tenant with it, and an operator suspends or
  restores one with `AdminSuspendTenant` or `AdminRestoreTenant` (see the
  entry for those RPCs above, and Suspending a tenant).
  `SetDomainStatus` should write nothing when the status is unchanged, and
  must never move a verified domain to another status: a domain stops being
  verified only by being removed. A store you supply
  must be wired for both tenant switches, or `app.New` refuses to start
  with either on.
- **Callers of the middleware constructors.** `middleware.AuthMiddleware`
  and `middleware.SessionAuthMiddleware` take a `middleware.TokenTenants`
  where they took the expected tenant string: `TokenTenants{Default: id}`
  keeps the old check, and setting `Selectable` (a `TenantLookup`, which
  `TenantStore` satisfies through `GetTenantStatus`) also accepts selected
  tenants; `middleware.NewTenantStatusCache` wraps one in the TTL cache.
  `Logger` records failed tenant reads.
- **Callers of `AuthService.RefreshToken`** pass the tenant to select as a
  new third argument, `""` for the default; `AuthService.WithTenantSelection`
  supplies the reader it checks against, and without one (or with `nil`)
  selection is off.

## Next — built with Go 1.26.10 for the `crypto/x509` advisory (no API or schema change)

The image and every CI job build with Go 1.26.10, which fixes GO-2026-6809:
`x509.Certificate.Verify` now distrusts compromised intermediate certificates,
so a chain through one of them fails verification. Identity reaches it on every
outbound TLS connection (OAuth provider token exchange, webhook delivery, SMTP,
SMS and CAPTCHA providers), because `crypto/tls` verifies a server's chain with
it, and in App Attest verification (`pkg/assurance/appattest`). Anyone building
identity or embedding its `pkg/` libraries should build on Go 1.26.10 or later
on the 1.26 line, or on Go 1.27.3 or later: Go 1.27.0 to 1.27.2 lack the fix
too.

v4.23.0 was tagged, but its release stopped at this vulnerability scan, so no
v4.23.0 image or release was published. The next release is the first to carry
the PKCE and `/auth/code` change below, the one change v4.23.0 added.

## Next — bind a hosted sign-in to the app with PKCE, and the `/auth/code` page (migration; `/oauth/start` refuses malformed PKCE parameters (behaviour change); `pkg/oauth.IssueHostedStateToken` signature (Go API); custom repositories must match the code challenge)

An app can now bind the hosted flow's one-time code to itself: it sends
`code_challenge` and `code_challenge_method=S256` to `GET /oauth/start/{provider}`
and redeems with the new `RedeemOAuthCodeRequest.code_verifier` field. An app
that cannot take the callback's redirect (a CLI on a remote server) can name
the new code page, `<identity-origin>/auth/code?state=<app-state>`, as
`return_to`: it shows `<code>#<app-state>` with a copy button for the person to
paste into the app. The page shows only codes bound to a challenge, and a
`state` only when it is 16-64 lowercase hex characters. See the hosted flow in
`docs/oauth.md`, including what PKCE does not protect against there.

Apps that send no challenge are unaffected: their codes redeem without a
verifier, as before. A verifier sent for such a code is refused.

**An app that already sent a challenge is affected.** `/oauth/start` used to
ignore `code_challenge` and `code_challenge_method`. It now binds the code to
a valid S256 pair, so an app that already sent one (a generic OAuth helper
may add PKCE to every authorization URL) must redeem with `code_verifier`, or
`RedeemOAuthCode` answers `Unauthenticated`. Check your apps before
upgrading: drop the parameters, or send the verifier.

An app's verifier must be at least 32 random octets from a cryptographically
secure generator, base64url-encoded, and fresh for every sign-in (RFC 7636
§4.1). Identity checks its alphabet and length, not its randomness.

Operators:

- **Migration.** Postgres `0043_add_oauth_one_time_code_challenge` and SQLite
  `0026_add_oauth_one_time_code_challenge` add `oauth_one_time_codes.code_challenge`
  (`TEXT NOT NULL DEFAULT ''`, a catalog-only change). Rolling back drops it,
  and the outstanding bound codes then redeem without a verifier for the rest
  of their 60 seconds.
- **Roll out before apps rely on it.** While old and new replicas serve
  together, an old replica ignores `code_challenge` at `/oauth/start` and
  consumes a bound code without checking a verifier, and an old replica that
  serves `/oauth/callback` mints an unbound code from a new replica's state
  token, whose verifier a new replica then refuses. Finish the rollout before
  enabling an app that sends a challenge.
- **To offer the code page,** add it exactly to the allowlist, on each host it
  should show codes on, for example
  `GATEWAY_OAUTH_ALLOWED_RETURN_URLS=…,https://auth.example.com/auth/code`. It is
  served only while the hosted flow is enabled. An existing origin, path-prefix
  or wildcard entry that covers identity's own host does not enable it: on a
  host whose exact entry is missing, the page answers 404 and shows no code,
  whichever host the sign-in started on. The page compares the scheme and
  host the request reached, as `X-Forwarded-Proto` and `X-Forwarded-Host`
  report them, the values the provider redirect URI is already built from.
  `/oauth/start` also answers 400, before the person signs in, to a return to
  the code page on its own hostname that lacks the exact entry, an S256
  `code_challenge`, or a `state` the page shows. That check matches the
  hostname on any port, so an app of your own that serves `/auth/code` on
  identity's hostname at another port (a local development setup, say) now
  needs the same exact entry, challenge and hex state, or another path. Leave the page out unless an
  app needs it. A person persuaded to sign in through someone else's start URL
  and hand over the code gives away their account (see `docs/oauth.md`).
- `/oauth/start` now answers 400 to a `code_challenge_method` other than
  `S256`, to either parameter without the other, and to a malformed challenge.
  It used to ignore them.

Embedders: `oauth.IssueHostedStateToken` takes the app's challenge after the
CSRF token. `service.Repository.ConsumeOAuthOneTimeCode` takes the challenge
after the code hash, and a custom repository must consume only on an equal
challenge (the conformance suite checks it).

## Next — export log lines to an OpenTelemetry collector (additive)

The `identity` command can send its log lines to an OTLP/HTTP collector beside
the JSON it writes to its own output. It is off by default: set
`GATEWAY_OTEL_LOGS_ENABLED=true` and `GATEWAY_OTEL_LOGS_ENDPOINT` to the
collector's base URL, and records are posted to `<endpoint>/v1/logs`. They
carry the trace resource's `service.name`, `service.version`
(`GATEWAY_OTEL_SERVICE_VERSION`) and `deployment.environment.name`
(`GATEWAY_OTEL_DEPLOYMENT_ENV`); `OTEL_SERVICE_NAME` and
`OTEL_RESOURCE_ATTRIBUTES` override or add to them. No schema, proto or wire
change, and no operator action is required.

- With the export enabled, an empty or malformed endpoint stops the process at
  start; `Config.Validate` checks it too.
- While the export is on, OpenTelemetry export failures, trace export included,
  are reported as `otel_export_failed` at most once a minute.
- Servers embedding `identityserver` are unaffected; they supply their own logger.
- The internal constant `observability.TracerName` is now `InstrumentationName`,
  since it names the scope of exported log records too.

## Next — the log-only email and SMS senders no longer log message content

`email_disabled_no_transport` and `sms_disabled_no_sender` are written when a
message is dropped: no SMTP server or SMS provider is configured, or every SMTP
provider in the chain failed. They used to carry the full recipient and the
first 240 characters of the body, which for sign-in codes, magic links and
reset links is a live credential. They now carry the redacted recipient
(`a***@example.com`, `+1********67`), the email's subject, and the body's size
(`text_bytes` / `html_bytes`, `body_bytes`); the `preview` field is gone.

Anyone who read sign-in codes from these lines during local development reads
them from a mail catcher or SMS provider sandbox instead. No configuration,
schema or wire change.

## Next — isolate machine challenge and account creation rate limits

`CreateAgentMachineChallenge` now uses the configured
`GATEWAY_AGENT_OAUTH_PROTOCOL_PER_IP` budget instead of accidentally sharing
`CreateAgent`'s signup budget. Rate-limit prefixes match complete path segments,
so distinct RPC names cannot capture one another. Directory prefixes such as
`/scim/v2/` still cover their descendants. No quota, environment variable, schema,
or wire format changes; no operator action is required.

## Next — hosted provider sign-in for agent consent

The agent review page now offers only the current project's enabled hosted
OAuth providers, alongside any enabled password sign-in. Add the exact public
consent page, for example `https://auth.example.com/auth/agent-consent`, to
`GATEWAY_OAUTH_ALLOWED_RETURN_URLS` if provider sign-in should return there.
An existing nonempty allowlist is insufficient unless it actually admits that
page. No allowlist, provider, project or authentication policy is widened.
Hub-shared providers still require the original `project_key` and start on the
configured hub origin.

The browser keeps a short-lived nonsecret login intent in tab session storage;
no access or refresh token is persisted. The one-time code leaves the address
bar before redemption, and the intent is consumed before redemption or refusal.
Provider cancellation returns `access_denied` only after the signed state,
project/provider and browser CSRF binding validate. Invalid state still fails
without redirecting. Sign-in never approves an agent: selection and Allow remain
explicit. Existing password/TOTP behavior is unchanged; the current hosted
redemption response cannot carry a required TOTP challenge, and such sign-ins
fail closed rather than issuing access. There is no schema or proto change.

## v4.19.0 → v4.20.0 — CORS allow-lists accept an exact origin on an application's own scheme (additive); a stored project CORS list that fails closed today can come back (behaviour change)

No schema change and no migration.

- **`GATEWAY_ALLOWED_ORIGINS` and a project's `cors.allowed_origins` accept
  an exact origin on an application's own scheme**, such as
  `app://example-desktop`. A desktop or mobile shell that serves its web
  client from a scheme it registers as standard (an Electron app, or a native
  web view with a custom scheme handler) runs those pages at that origin, and
  its browser engine sends it as their `Origin`. The entry is
  `scheme://host` with a lower-case scheme and a host of lower-case DNS
  labels, and no port, path, trailing slash, query, fragment or userinfo. It
  matches byte for byte, like any exact entry, and the response echoes it with
  credentials. The host must be a DNS name: a placeholder such as `app://-`,
  a host with an underscore, an IP address (`app://127.0.0.1`) and a host
  whose last label is a number (`app://1`, which Chromium sends rewritten as
  `app://0.0.0.1`, or `app://0x7f`) are refused.
  Where the helper that serves a shell's pages defaults to a placeholder, set
  its host name option to a distinctive name instead.
- **Still refused:** `*`, `null` and empty entries; a wildcard on any scheme
  but `https`; any other form of entry on an application scheme; and the
  schemes the URL standards give a meaning of their own (`file:`, `data:`,
  `blob:`, `javascript:`, `about:`, `filesystem:`, `ws:`, `wss:`, `ftp:`),
  whose pages send `null`, the origin of a URL inside them, or an origin every
  local file shares, or which name sockets or pages browsers no longer load;
  and the schemes a browser or a platform keeps for its own pages (`chrome:`,
  `chrome-untrusted:`, `chrome-search:`, `devtools:`, `edge:`,
  `view-source:`, `resource:`, `content:`). An extension's scheme
  (`chrome-extension:`, `moz-extension:`) is accepted. Such an entry fails
  startup in `GATEWAY_ALLOWED_ORIGINS`, and the admin API
  refuses it in a project's list.
- **A misspelled http(s) scheme is still refused.** A scheme one edit away
  from `http` or `https` (`htps://`, `hhttps://`, `httsp://`) is refused as a
  misspelling, not loaded as an application scheme.
- **Logged apart.** The startup line `cors_allowed_origins` lists the
  application-scheme entries of `GATEWAY_ALLOWED_ORIGINS` again under a new
  field, `app_scheme_origins`. Its `origins` field still lists every exact
  entry, these included, so a log reader that expects only http(s) values
  there sees the new schemes too.
- **http(s) entries and patterns are unchanged.** Every
  `GATEWAY_ALLOWED_ORIGINS` that starts today starts unchanged and admits the
  same origins. An entry refused for its scheme (a non-http(s) scheme, an
  upper-case scheme, or none) gets a new message naming the rule it breaks,
  at startup and in the admin API's `InvalidArgument` for a project's list.
  The error code is unchanged. `GATEWAY_OAUTH_ALLOWED_RETURN_URLS` still
  takes http(s) URLs only.
- **A project list that fails closed today can come back.** A stored
  `cors.allowed_origins` holding an entry an older release refused is
  dropped whole, and each resolution logs
  `project_cors_config_invalid_failing_closed`. If every such entry is one
  this release accepts, the upgrade turns the whole list back on, its http(s)
  entries included. Review stored entries that are not http(s) before
  upgrading. Only the Postgres driver serves per-project CORS lists:

  ```sql
  SELECT p.id, o.entry
  FROM projects p,
       jsonb_array_elements_text(
         CASE WHEN jsonb_typeof(p.config_json -> 'cors' -> 'allowed_origins') = 'array'
              THEN p.config_json -> 'cors' -> 'allowed_origins' ELSE '[]'::jsonb END
       ) AS o(entry)
  WHERE o.entry !~ '^https?://';
  ```
- **Why this admits no website.** A browser sets `Origin` itself; page script
  cannot change it. A page loaded over http or https presents that origin,
  a sandboxed or `data:` page presents `null`, and a `file:` page presents
  `null` or, in some shells, `file://` (both refused), so no web page can
  present `app://example-desktop`. Only an application that registered the
  scheme, and loads its own pages from it, does. A non-browser client can
  send any `Origin` whether or not the entry exists. The origin is not an
  application's identity: another application can register the same scheme,
  and a framework's default origin (`capacitor://localhost`) is shared by
  every app built on it. Give a shell a distinctive host.
- **Rolling back:** a release before v4.20.0 refuses an application-scheme
  entry. Remove it from `GATEWAY_ALLOWED_ORIGINS` first, or the older release
  fails startup. A project whose stored `cors.allowed_origins` holds one keeps
  serving on the older release, but its whole per-project list is dropped and
  each resolution logs `project_cors_config_invalid_failing_closed`, and that
  release's `UpsertProjectConfig` refuses the project's whole config until the
  entry is gone (targeted writes, such as OAuth providers and assurance, are
  unaffected). Remove such entries before rolling back.

## v4.18.0 → v4.19.0 — native delegated agent OAuth

The new feature remains off unless `GATEWAY_AGENT_OAUTH_ENABLED=true`. It requires
agent accounts, `GATEWAY_REVOCATION_MODE=session`, an HTTPS origin for
`GATEWAY_JWT_ISSUER` without a path, query, fragment or trailing slash, and
dedicated resource credentials. PostgreSQL migration 0041 / SQLite 0024
add consent, code and refresh-family state plus terminal security fences. Down
migrations erase that state and revoke its usefulness; retain needed audit
evidence before rollback. Ordinary sign-in and legacy human JWT compatibility
are unchanged. A human without a durable SID must sign in normally again only
when beginning this new consent flow.

Native resource registrations can now supply `product` alongside `resource`
and `scopes`; delegated authorization requires it. Existing registrations
without a product remain valid registry metadata but cannot issue grants.
An update advances the registration revision and requires fresh consent.

The four new session RPCs GetAgentAuthorization, DecideAgentAuthorization,
ListAgentDelegations and RevokeAgentDelegation implement explicit human consent
and access management. HTTP publishes only OAuth code+S256 and rotating refresh,
not OIDC. Resources must use authenticated current introspection on every call;
verifying the JWT signature alone is insufficient. See ADR-0016 and the runnable
`examples/agent-delegation` journey before enabling the feature.

## v4.17.0 → v4.18.0 — native public OAuth client registrations

PostgreSQL migration 0040 (SQLite 0023) adds the project-scoped `oauth_clients`
table. It contains public registration metadata only: no client secrets, codes,
tokens or consent. Rolling back drops these registrations; export them before
using the down migration. Existing sign-in and token behavior is unchanged.

Four admin-session RPCs create, read, list and replace native public clients.
Updates require the exact revision and advance it, including disable/re-enable.
Custom `service.Repository` implementations must implement the four OAuth-client
methods with the documented atomic and project-isolation semantics.

This does not enable an OAuth authorization server or agent delegation. No
provider endpoints or discovery claims are added. See the native-client registry
documentation for validation limits and the remaining protocol work.

## v4.16.0 → v4.17.0 — agent accounts; custom repositories must implement ownership and transfer semantics

**Migration 0038** (SQLite 0021) adds `users.kind` (`'person'` or
`'agent'`), `users.owner_user_id` and `users.pending_owner_user_id`, all with
constant defaults (catalog-only), three `NOT VALID` CHECK constraints, and
partial indexes on `(project_id, owner_user_id)` and
`(project_id, pending_owner_user_id)` that index no existing row, plus a
person-only `(project_id, created_at_ms, id)` directory index
(`lock_timeout = 10s`; on timeout confirm `kind` is absent, then
`identity migrate force 37` and `identity migrate`). Every existing account
becomes a person.

For large PostgreSQL deployments, migration 0038 holds `ACCESS EXCLUSIVE`
while building its indexes. To keep those builds outside that lock, first
add the columns, then build the indexes concurrently, outside a transaction:

```sql
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'person',
  ADD COLUMN IF NOT EXISTS owner_user_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS pending_owner_user_id TEXT NOT NULL DEFAULT '';
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_project_owner_idx
  ON users (project_id, owner_user_id) WHERE owner_user_id <> '';
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_project_pending_owner_idx
  ON users (project_id, pending_owner_user_id) WHERE pending_owner_user_id <> '';
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_project_created_id_person_idx
  ON users (project_id, created_at_ms, id) WHERE NOT is_anonymous AND kind <> 'agent';
```

Then run `identity migrate`; it reuses those columns and indexes. If a
concurrent build fails, drop its invalid index before retrying. The earlier
anonymous-excluding directory index stays available for callers opting into
agents.

**Migration 0039** (SQLite 0022) adds `agent_creation_receipts` and lifecycle
invalidation triggers. Apply it before running this service version. The table
is scoped by project; PostgreSQL enables and forces row-level security using
`app.current_project_id`, matching the other data-plane tables. Its primary key
is `(project_id, caller_id, request_id)`, with additional owner and subject
indexes. The project FK removes receipts on project deletion; there are no user
FKs because an erased subject must not be recreated by an old request.

**Custom repositories must implement the new atomic
`CreateAgent(context.Context, AgentCreation) (*User, bool, error)` operation.**
The boolean is true only for a newly committed subject. In one transaction or
critical section, recheck current caller/owner eligibility and caller authority,
look up an optional scoped receipt, enforce the owner limit for a new subject,
and commit the subject and receipt together. Do not implement this as a
separate receipt write around `CreateUser`. All calls, including those without
a key, use this operation and share its atomic capacity check.

`CreateAgentRequest.client_request_id` is optional. An empty key preserves
independent creation on every successful call. A nonempty, case-sensitive key
is at most 128 UTF-8 bytes without controls. It is bound to the trimmed name,
avatar URL and resolved owner (an omitted owner is the caller). Matching retries
return the existing subject's current profile without consuming quota or
emitting another creation event; a different normalized payload is
`ALREADY_EXISTS`. Current authority is checked even on a matching retry.

Receipts are permanently invalidated by actual ownership changes, account
revocation/deactivation, merging, erasure, or removal of the caller's admin
role. Reassignment back or reactivation does not restore replay access. Pending
transfer offers and profile edits do not invalidate receipts. Custom stores
must fence these changes atomically across every lifecycle writer. The SQL
triggers cover all user writers; memory applies the equivalent rule under its
mutex. PostgreSQL creation locks caller/owner person rows in ID order before
an existing agent, matching merge's person-before-agent lock order. SQLite
acquires its writer before reading so concurrent connections cannot upgrade a
stale read transaction. The PostgreSQL migration bounds schema lock waits at
10 seconds; creation lock waits remain bounded by the request context.

**Destructive rollback loses retry history.** The down migrations remove the
triggers and receipt table, including invalidation tombstones. They leave agent
accounts intact. After such a rollback, do not replay previously used creation
keys: without their receipts they could create another subject. A normal
application rollback must retain this additive schema and its durable receipts.
Send keyed retries only to a service version implementing this field; retaining
the schema cannot make an older application version retry-safe.
Receipts contain opaque identifiers and a request digest and remain until
project deletion, including after individual account erasure.

- **Custom `Repository` implementations must persist the three new `User`
  fields**, default `Kind` to person, and honor `IncludeAgents` (false by
  default), `OwnerUserID` and `PendingOwnerUserID` identically in `ListUsers`
  and `CountUsers`. Implement `SetAgentOwnership` and `SettleAgentTransfer`
  as conditional, atomic writes that return false on a stale owner or offer,
  and extend `ApplyAccountMerge` to re-point owned agents and pending offers,
  clearing offers that become self-transfers. The service's pure in-memory
  row helpers express those rules; SQL drivers must preserve them within
  their transactions.
- **`CreateAgent` has its own per-IP rate-limit bucket, `agent_create`,**
  using `GATEWAY_RATE_LIMIT_SIGNUP_PER_IP`. Include that bucket in monitoring.
- **Agent accounts (new, off by default).** A non-human account a person
  owns, with no way to sign in. `CreateAgent`, `ListAgents`, `UpdateAgent`,
  `TransferAgent`, `CancelAgentTransfer`, `DeactivateAgent`,
  `ReactivateAgent` and `DeleteAgent` serve the owner and a project admin,
  and `AcceptAgentTransfer`, `DeclineAgentTransfer` and
  `ListIncomingAgentTransfers` serve a transfer's recipient, once
  `GATEWAY_AGENTS_ENABLED=true`
  (new, default `false`); until then each answers `FAILED_PRECONDITION`.
  At most `GATEWAY_AGENTS_MAX_PER_OWNER` (new, default 25, 1 to 500; 0
  selects the default and anything else outside the range is refused at
  boot) per owner. See *Agent accounts* in the docs and
  [ADR-0014](./adr/0014-agent-accounts.md).
- **A transfer is an offer the recipient accepts.** `TransferAgent` sets the
  agent's `pending_owner_user_id`; ownership moves only on
  `AcceptAgentTransfer`, which checks the recipient's limit then. The agent
  stays with its owner meanwhile. An offer or an answer that raced a change
  (the agent changed hands, or the offer was cancelled or replaced) is
  refused with `PERMISSION_DENIED`; re-read and retry. A project admin's transfer of an orphan
  (an agent whose owner was deleted) takes effect at once, with no
  acceptance, because nobody is left to hand it over.
- **An agent is admitted as its owner is.** In an `allowlist` or `closed`
  project, under a deny rule, or with `GATEWAY_IDV_REQUIRED`, an agent's
  refresh is judged by its owner's address and verification.
  With `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL`, the owner must also have a
  proven address. A refused agent refresh preserves its refresh token and,
  under session revocation, ends its access session until a fresh rotation.
- **`User` gains `kind`, `owner_user_id` and `pending_owner_user_id`.** Every existing account
  reports `USER_KIND_PERSON`. A client that treats every user as a person
  should check `kind` before showing an account as one.
- **An access token issued to an agent carries `"kind": "agent"`.** No path
  issues one from outside the service yet (delegation is follow-up work). A
  person's token carries no `kind`, so verifiers see no change.
- **The admin `ListUsers` leaves agents out** unless the new
  `include_agents` is set. The directory lookup and SCIM never return them.
- **Webhook payloads for an agent carry `kind` and `owner_user_id`**, and
  `pending_owner_user_id` while a transfer is pending. A person's payload
  is unchanged.
- **Deactivating or deleting a person also revokes their agents' sessions**,
  and an agent's token is refused at refresh while its owner is not active.
  Deleting a person does not delete their agents: an admin transfers (at
  once) or deletes them (`ListAgents` with the deleted owner's id finds them).
- **Merging moves the retired account's agents to the survivor**, and
  transfers offered to it now wait on the survivor. An agent
  account cannot itself be merged.
- **The admin `UpdateUser` refuses an agent**; edit one with `UpdateAgent`.
- **Eleven new audit event types:** `agent_created`, `agent_updated`,
  `agent_transfer_requested`, `agent_transferred`,
  `agent_transfer_declined`, `agent_transfer_cancelled`,
  `agent_deactivated`, `agent_reactivated`, `agent_deleted`,
  `agents_listed`, `agent_sign_in_refused`.

## v4.15.0 → v4.16.0 — sign-in hardening follow-ups (behaviour changes); `GATEWAY_RATE_LIMIT_QR_POLL_PER_IP` and `gate` on `login_locked` audit rows (additive); `Repository.DeletePasskeyCredential` (custom repositories must add it)

No schema change and no migration.

### QR sign-in (behaviour changes)

- **A refused QR poll is audited at its own gate, paced (behaviour change).**
  A `PollQrLogin` refused for an unverified address or a lockout leaves the
  hand-off approved, so the device replays the refusal on every poll, and each
  poll wrote a row. The `login_failure` row (`reason: email_not_verified`) of
  a refused poll now carries `gate: qr_poll` instead of `gate: sign_in`, and
  its `login_locked` row carries `gate: qr_poll` (see below). Both are written
  at most once per account and reason per 10 minutes per replica, like a
  refused refresh. Every poll is still refused. Alerting that counted QR
  refusals under `gate: sign_in` should add `qr_poll`.
- **An account that could not sign in cannot approve a QR hand-off (behaviour
  change).** `ApproveQrLogin` with `approve: true` is refused, with the codes a
  sign-in uses, when the approving account is deactivated, has a pending
  invitation, is locked by failed sign-ins (`resource_exhausted`, audited as
  `login_locked` with `gate: qr_approve`), or is unverified while identity
  verification is required; the hand-off stays `pending`. A locked approver
  keeps its access token and can repeat the approval, so its `login_locked`
  row is written at most once per account per 10 minutes per replica, like a
  refused poll's. An approver whose account no longer exists gets
  `not_found`. Rejecting (`approve: false`) is unchanged. The poll still
  re-checks the account at collection.
- **An approved QR hand-off can be collected for 30 seconds past its window
  (behaviour change).** v4.15.0 made an approved hand-off expire with
  `GATEWAY_QR_LOGIN_EXPIRY_SECONDS` like a pending one, so an approval landing
  in the device's last poll interval was reported `expired`. `PollQrLogin` now
  collects an approved hand-off until 30 seconds after the window; a pending
  one still expires at the window, and approval itself must still happen
  within it. Clients should poll more often than every 30 seconds.
- **QR sign-in RPCs are rate-limited per client IP (behaviour change).**
  `InitiateQrLogin` now counts against `GATEWAY_RATE_LIMIT_LOGIN_PER_IP` (its
  own budget of that size), and `PollQrLogin` against the new
  **`GATEWAY_RATE_LIMIT_QR_POLL_PER_IP`** (default 120 per
  `GATEWAY_RATE_LIMIT_WINDOW_SECONDS`; 0 disables it; negative refused at
  boot). An over-limit call gets HTTP 429 with a `Retry-After` header, which
  Connect clients report as `unavailable`, as for the other per-IP limits.
  A client polling faster than every half second from one address, or many
  devices behind one NAT, should poll less often or raise the limit. Like the
  other sign-in limits, these are enforced on the HTTP surface only; a host
  serving identity through `RegisterGRPC` must apply its own.

### Audit

- **`login_locked` rows name the gate that refused (additive).** A
  `login_locked` row now carries a `gate` detail, as a refused session's
  `login_failure` row already did: `sign_in` for a sign-in by any method,
  `refresh` for a refresh, `qr_approve` for a QR approval, `qr_poll` for a QR
  poll. Rows written before the upgrade have no `gate`. Filter on it to tell
  a lockout replayed through a refresh or a QR approval or poll, which is
  paced, from a sign-in attempt, which is audited every time.

### Proving an address voids credentials added while the proof runs (behaviour change)

- The first proof of an unverified account's address (a verified provider
  sign-in, an emailed sign-in code, or a verification link for an address a
  provider claimed) now also voids credentials added *while the proof runs*:
  it clears whatever password the account holds when it marks the address
  verified (not only one it saw earlier), and lists the account's passkeys
  again after that write, deleting any that escaped the first listing and
  ending the account's sessions.
- `CompletePasskeyRegistration` on an account whose address was unverified
  when the call began now re-reads the account after storing the passkey. If
  the address was proven in the meantime, the passkey it just stored is
  deleted and the call fails with `unauthenticated` ("the account's address
  was proven while registering; sign in again"), audited as `passkey_added`
  with `success=false` and `reason=address_proven_while_registering`. Clients
  should prompt the user to sign in again and register the passkey once
  more. This mirrors what `LinkIdentity` already does for provider links.
  Only that one passkey is withdrawn: passkeys the account registered earlier
  are left to the proof, so a verification link, which voids none, keeps
  them. If the re-read fails, the new passkey is deleted the same way and the
  call fails with `unavailable`; if the account was deleted meanwhile, it
  fails with `not_found`.
- Custom `Repository` implementations must add
  `DeletePasskeyCredential(ctx, userID, credentialID)`: delete the one
  passkey with that WebAuthn credential id, only when `userID` owns it, and
  return `ErrNotFound` when no row matches. No migration is needed.
- The `unproven_credentials_voided` audit event's `password_cleared` field
  now reports whether the verified write actually cleared a password. A
  proof racing another proof of the same address no longer reports a
  password the other one already cleared.
- In `GATEWAY_REVOCATION_MODE=ttl` (the default), an access token minted
  before the proof stays valid for the rest of its lifetime (at most 15
  minutes) and can still add a passkey or provider link after the proof
  completes. Deployments that need that window closed should use
  `GATEWAY_REVOCATION_MODE=session`, where the proof's session revocation
  also ends those access tokens.

### Credential mail and linking

- **Credential emails sent in the background are capped (behaviour
  change).** Password-reset, email sign-in code and magic-link mails now run
  at most 128 at once per instance. A request arriving while all 128 are in
  flight still gets its usual answer, but its mail is dropped. Every drop is
  counted in the new **`identity_email_send_dropped_total{op}`** metric
  (`op` is `password_reset`, `email_login_code`, `magic_link` or
  `email_verification`); alert on it to learn when mail is being shed. The drops are also logged as
  `email_send_dropped_at_capacity` (WARN), at most once per `op` per minute,
  with the number `dropped` since that `op`'s previous line.
- **The verification email a refused sign-in or QR poll sends goes out in
  the background (behaviour change).** With
  `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` on, a sign-in or `PollQrLogin`
  refused for an unverified address sends a verification email, throttled
  per address by `GATEWAY_EMAIL_SEND_COOLDOWN_SECONDS`. It used to send inline
  before answering; it now sends like the other credential mail, under the
  same cap (`op` `email_verification`), and a refusal whose resend is
  throttled no longer reads the account again. The refusal is unchanged.
- **`SynchronousEmailSend` is for tests only.** With
  `identityserver.Options.SynchronousEmailSend` set, reset, code and
  magic-link responses take as long as the account lookup and send they
  trigger, so their timing tells a caller whether an address has an account.
  Leave it false in any deployment.
- **`LinkIdentity` on an account deleted mid-call returns `not_found`
  (behaviour change).** It returned `unauthenticated` ("the account's address
  was proven while linking") and wrote an `identity_linked` failure row with
  reason `address_proven_while_linking`; it now writes no such row.

## v4.14.0 → v4.15.0 — sign-in hardening (behaviour changes); an `email_unverified` and an `unproven_credentials_voided` audit event (additive)

No schema change and no migration. `password_reset_tokens.email`, empty until
now, records the address a reset link was mailed to (see below).

### A GitHub sign-in needs a verified GitHub address (behaviour change)

- **A GitHub sign-in needs a verified address from `/user/emails`
  (behaviour change).** When GitHub listed no verified address, or
  `/user/emails` could not be read (a token without the `user:email`
  scope), the sign-in fell back to the profile's public email, which GitHub
  lets a user set to any address without proving it, and treated it as
  verified. That sign-in is now refused with `unauthenticated`. A user who
  hits this verifies an address at GitHub and signs in again. The verified
  primary address is still preferred, then the first verified one.

### A QR sign-in checks the account before completing (behaviour change)

- **A QR sign-in runs the account checks every sign-in runs, before it
  consumes the hand-off (behaviour change).** `PollQrLogin` issued a session
  to an approved hand-off whatever the approving account's state: a
  deactivated, invited or locked account still signed the device in. Now:
  - It is refused with the codes a passkey sign-in gets:
    `failed_precondition` for a deactivated account, a pending invitation or
    (with identity verification required) an unverified identity, and
    `resource_exhausted` for an account locked by failed sign-ins (the
    approver has already signed in, so naming the lock reveals nothing). This
    differs from `PasswordLogin`, which during a lockout now answers
    `unauthenticated` like an unknown address. The access-policy and
    verified-email refusals are unchanged.
  - A refused poll leaves the hand-off approved instead of spending it, so
    once the account is eligible (its address verified, say) the device's
    next poll completes without a new QR code.
  - An approved hand-off now expires at the end of its window
    (`GATEWAY_QR_LOGIN_EXPIRY_SECONDS`) like a pending one; a poll after it
    reports `expired`.

### A password-reset link works only while the account holds the address it was issued for (behaviour change)

- **A reset link is bound to the address it was mailed to (behaviour
  change).** `ConfirmPasswordReset` used to reset the password of the
  account the token named, whatever address the account held by then. Once
  the account holds another address (after `ConfirmEmailChange` or a SCIM
  write), a link mailed to the old one is refused with `unauthenticated`,
  exactly as an invalid link, and spent; request a new one. Another spelling
  of the same mailbox still resets. A reset token from `ResetUserPassword` is
  bound to the address the account held when the admin issued it.
- **Reset links issued before the upgrade stop working** for every account
  with an email address. They carry no address, so they cannot show the
  account still holds one, and are refused the same way. Users with an outstanding link request a new one; an admin
  re-issues a `ResetUserPassword` token.

### A refused hosted OAuth callback redirects to `return_to` with an error code (behaviour change)

- **A refused hosted OAuth sign-in returns to the app (behaviour change).**
  `/oauth/callback/{provider}` answered every failure with a bare `400` on the
  identity origin. Once the signed state token verifies, a refused sign-in is
  now 302-redirected to `return_to?error=<code>` (no `code` parameter):
  `email_not_verified`, `account_disabled`, `account_locked`, `access_denied`,
  `temporarily_unavailable` or `server_error` — see
  [callback errors](oauth.md#callback-errors). A page at `return_to` that
  only looks for `code` should handle `error`. A callback whose state token
  or CSRF cookie does not verify still answers `400`.

### A password sign-in into an account with no password is refused as for an unknown address (behaviour change)

- **`PasswordLogin` no longer says an account has no password (behaviour
  change).** A password sign-in into an account created through a provider or
  passwordless sign-in answered `failed_precondition` ("no password set for
  this account") without checking anything, which told any caller the account
  exists. It now gets the `unauthenticated` "invalid email or password" an
  unknown address gets, after the same password-check cost. A client that
  showed "sign in with your provider" on that error can offer the provider
  and passwordless options, and password reset, beside every
  invalid-credentials message instead. `ChangePassword` and the other
  signed-in calls still return `no password set`.

### `RequestPasswordReset` returns before the account is looked up or mailed

- **`RequestPasswordReset` no longer waits on the reset mail.** It looked up
  the account and minted and mailed its reset link before answering, so a
  request for an existing account took measurably longer than one for an
  unknown address. That work now runs off the request, as the passwordless
  code and magic-link requests already do; the answer is unchanged (always
  success), and a send failure is logged as before.

### A password sign-in during lockout is refused as for an unknown address (behaviour change)

- **`PasswordLogin` no longer says an account is locked (behaviour change).**
  After `GATEWAY_LOGIN_MAX_FAILED_ATTEMPTS` failures it answered
  `resource_exhausted` ("account temporarily locked") before checking the
  password, so anyone could confirm an address has an account by failing
  against it a few times. It now gets the `unauthenticated` "invalid email or
  password" an unknown address gets, after the same password-check cost. The
  lockout itself is unchanged: the correct password is still refused until
  `GATEWAY_LOGIN_LOCKOUT_SECONDS` pass, the `login_locked` audit event is
  still written, and a password reset still lifts it. A client that showed a
  "locked, try later" message should mention password reset beside every
  invalid-credentials message instead. Paths that check lockout after the
  credential is proven (refresh, the required password change) still return
  `account temporarily locked`.

### A refresh refused over the account's state ends its access token under `GATEWAY_REVOCATION_MODE=session`; a replayed refused refresh is audited once per window; a refresh refused over a lockout keeps its token (behaviour changes)

- **A refresh refused over the account's own state revokes its session
  (behaviour change, `GATEWAY_REVOCATION_MODE=session` only).** A refresh
  refused because the account's address is unverified (with
  `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL`) or because the account is no longer
  active (deactivated, suspended, back to invited, or failing a required
  identity verification) left the access token issued with that refresh
  token working until its natural expiry. That session is now revoked, so
  the access token is rejected at its next session check (within
  `GATEWAY_SESSION_CACHE_TTL_SECONDS` on other replicas).
  - An unverified account keeps its refresh token, which rotates into a new
    session once the address is verified, but a client can no longer call
    `SendEmailVerification` with the old access token after the refusal:
    send the user to sign in again, which is refused but mails a
    verification link.
  - A refresh refused because the account is locked out after failed
    sign-ins, or by a transient failure, does not revoke the session: a
    lockout can be triggered by anyone guessing at the password.
  - `GATEWAY_REVOCATION_MODE=ttl` (the default) is unchanged.
- **A refused refresh is audited once per window, not on every replay
  (behaviour change).** A refresh refused because the account's address is
  unverified or because it has no date of birth on file
  (`GATEWAY_AGEGATE_REQUIRE_DOB`) keeps its token, so a client could replay it
  without limit and write one `login_failure` row per replay. Each account's
  refused refresh is now recorded at most once per 10 minutes for each reason
  (`email_not_verified`, `dob_required`) on each replica; every replay is
  still refused the same way. Refused sign-ins are recorded every time.
  - The `dob_required` row now carries `gate` (`sign_in` or `refresh`), as
    `email_not_verified` does. Alerting that counts refused refreshes counts
    accounts per window, not attempts.
- **A refresh refused because the account is locked out keeps its refresh
  token (behaviour change).** The lockout was checked after the refresh token
  was consumed, so the refusal burnt the token, and the retry a client makes
  on a failed refresh was taken for refresh-token replay: every refresh token
  the account held was deleted and, under `GATEWAY_REVOCATION_MODE=session`,
  every session revoked. Anyone guessing at an account's password until it
  locked could sign it out on every device. The lockout is now checked before
  the token is consumed: the refresh is still refused with the same error,
  but the token survives, a retry is refused the same way rather than
  treated as a replay, and the token rotates normally once the lockout ends.
  - A client that discarded its session on the lockout refusal can now keep
    the refresh token and retry after the lockout instead of sending the user
    back to sign in.
  - Like the other refusals that keep the token, its `login_locked` row is
    recorded at most once per 10 minutes per account on refresh (on each
    replica); a locked-out sign-in is still recorded every time.
  - Refreshes refused because the account is deactivated, suspended, back to
    invited or failing a required identity verification are unchanged: they
    still spend the refresh token and, under `GATEWAY_REVOCATION_MODE=session`,
    end its session.

### An `email_unverified` audit event (additive)

- **A SCIM write that leaves an email unverified is audited.** A SCIM `PUT`
  or `PATCH` that moves an account to another mailbox, and so leaves its
  email unverified, now records an `email_unverified` audit entry: actor
  `system:scim`, target the account, details `source: scim` and
  `was_verified` (whether the account read verified before the write). The
  entry never carries the address. A consumer that rejects unknown audit
  event types should accept it.
- `account_merged` and `email_canonicalized` entries no longer log an
  `audit_unknown_event_type` warning when they are written.

### A proof of an address that cannot void the credentials added before it fails the sign-in; a verification link voids what was added to an account a tagged provider address claimed; a link added while the address is being proven is voided too (behaviour changes)

- **A proof of an address that cannot void the credentials added before it
  fails the sign-in (behaviour change).** When a passwordless email code or
  magic link, or a provider sign-in, first proves an account's address,
  identity voids the password, passkeys and provider links added while it
  was unproven. If the store failed while doing so, the sign-in used to
  succeed and verify the address anyway, leaving what it could not void.
  It now fails with `unavailable` and leaves the address unproven, so the
  next proof voids them; start the sign-in again.
- **The voided credentials have their own audit event.** That cleanup was
  recorded as `password_changed` (reason
  `planted_credentials_cleared_on_external_email_verification`), even when
  no password was cleared. It is now `unproven_credentials_voided`, with the
  proof `method` (`passwordless`, `oauth` or `verification_link`) and
  `password_cleared`, `passkeys_cleared` and `provider_links_cleared`; each
  voided provider link is still recorded as `identity_unlinked`. Update any alert or report that
  keyed on the old `password_changed` reason.
- **A verification link voids what was added to an account a tagged
  provider address claimed (behaviour change).** An account created, or an
  anonymous account upgraded, through a provider that asserted a `+tag`
  address outside Gmail holds the untagged address unproven, and whoever
  signed in that way may not own that mailbox. Redeeming the
  `SendEmailVerification` link for such an account now voids what was
  added while the address was unproven, as a sign-in proof does: the
  password, the passkeys and every provider link except one whose provider
  asserted the account's own address, with its sessions revoked and
  audited as `unproven_credentials_voided` with `method:
  verification_link`. The owner then signs in with an email code or link,
  or sets a password through `RequestPasswordReset`, and links the provider
  again while signed in. On any other account the verification link still
  keeps every credential: it completes the sign-up that set them. If the
  voiding cannot be done, `VerifyEmail` fails with `unavailable` and the
  link is not spent; redeem it again.
  - Provider links now record the address the provider asserted, `+tag`
    included, where sign-in and anonymous upgrade recorded it without the
    tag. `ListLinkedIdentities` shows that spelling for links made from
    now on. A link recorded before this release cannot be told apart, so an
    account it claimed keeps its credentials on a verification link; a
    sign-in proof still voids them.
- **A provider link added while the address is being proven is voided too
  (behaviour change).** A `LinkIdentity` call already in flight when an
  account's address was first proven could insert its link after the proof
  had listed the links it voids. The proof now lists them again once the
  address is marked verified, and `LinkIdentity` on an account whose
  address was unproven when the call began withdraws its link and fails
  with `unauthenticated` if the address was proven before its insert
  landed; sign in again and link the provider.

## v4.13.0 → v4.14.0 — a provider sign-in verifies only the address it asserted; a verification link proves only the address it was mailed to; a SCIM email change to another mailbox unverifies; proving an address voids provider links added before it; a tagged provider address cannot sign in to an existing account; no session or refresh for an unverified address on any path (behaviour changes); an `email_verified` access-token claim (additive)

No schema change and no migration.

- **A provider sign-in verifies an account's email only when the provider
  asserted that address (behaviour change).** Before, every OAuth sign-in
  marked the account's email verified and voided a password or passkey set
  while it was unverified, whatever address the provider asserted. Now:
  - An account found by its linked provider id whose stored address differs
    from the provider's, or that has no address (a username account), keeps
    its verified state, its password and its passkeys.
  - A new account, or an anonymous account upgraded through a provider,
    created from a `+tag` address outside Gmail (stored without the tag)
    starts unverified: a dropped tag is provably the same mailbox only at
    Gmail.
  - Consequence: `GetUser`, `LookupUsers` and webhooks report such accounts
    unverified, and with `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` the directory
    hides them. Offer them the email-verification flow
    (`SendEmailVerification`) if you gate features on a verified email.
- **A verification link proves only the address it was mailed to (behaviour
  change).** `VerifyEmail` used to mark the account's current address
  verified whatever address the link was sent to. Once the account holds
  another address (after a SCIM write, say), a link mailed to the old
  one is refused with `unauthenticated` and spent; send a new one. Another
  spelling of the same mailbox still verifies.
- **A SCIM email change to another mailbox unverifies the email (behaviour
  change).** A SCIM `PUT` or `PATCH` that changes an account's email to
  another mailbox kept the account's verified state, though nobody had
  proven the new address. The email is now unverified (`email_verified_at`
  cleared) until its owner verifies it, and the account address that spells
  the old email is released; a new one is issued at the account's first
  session after the new email is verified. A change that keeps the same
  mailbox (letter case, or Gmail dots and `+tag`) keeps it verified. SCIM
  stores an email without its `+tag`, so an account stored with a tag
  outside Gmail reads unverified after its next SCIM write too.
  - With `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` (on by default) the
    directory hides the account and its sign-ins and session refreshes are
    refused (see the next entry), until the new email is verified. A bulk
    identity-provider email or domain migration does this to every account
    it moves; plan to have those users verify.
  - The way to verify that keeps the user's credentials is
    `SendEmailVerification` and the link it mails. A passwordless email
    code or magic link, or a provider sign-in, also verifies the address,
    but as the first proof of an unverified address it voids the account's
    password and passkeys and ends its sessions.
- **`GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` now holds on every path that
  issues a session (behaviour change, flag on only).** The flag promised no
  session for an account with an unverified address, but only sign-up,
  password sign-in and the anonymous upgrade checked it. Now:
  - A passkey sign-in, a provider sign-in, a QR sign-in, or a later
    sign-in step (TOTP, required password change, date of birth) into an
    account whose address is unverified is refused with
    `failed_precondition` (`email verification required`), audited as
    `login_failure` with `reason: email_not_verified` and
    `gate: sign_in`, and sent a verification email
    (best-effort, throttled). A sign-in that itself proves the address
    (a passwordless email code or magic link, or a provider asserting the
    account's own address) still succeeds.
  - A refresh for such an account is refused the same way (audited with
    `gate: refresh`), without an email, so a session issued before the
    address became unverified (for example by a SCIM email change) cannot be
    renewed. The refusal comes before the refresh token is consumed: a
    client retrying it gets the same error rather than a replay that signs
    the account out everywhere, and the token works again once the address
    is verified through `SendEmailVerification` and its link (a passwordless
    code, magic link or provider sign-in, as the first proof, ends the
    account's sessions instead). A client that gets this error from
    `RefreshToken` should stop retrying and ask the user to verify: call
    `SendEmailVerification` while its access token is still valid (under
    `GATEWAY_REVOCATION_MODE=session` the refusal ends it), or else
    send the user to sign in again, which is refused but mails a
    verification link. Each refused refresh is one `login_failure`
    row with `gate: refresh`; exclude those from failed-sign-in alerting
    during a bulk email migration.
  - Sessions that exist at upgrade for accounts with an unverified address
    (an accepted invitation, a passkey or provider account) cannot be
    renewed: they end at their next refresh (an access token already issued
    under `GATEWAY_REVOCATION_MODE=session` lasts until its session is
    revoked). When upgrading with the flag on, expect those users to be
    asked to verify.
  - `AcceptInvitation` for an unverified invitee activates the account and
    returns the user with empty tokens, as `PasswordSignup` does, and sends
    a verification email; the invitee signs in once it is redeemed. The
    invitation token is shown to the inviting admin, so redeeming it does
    not prove the address.
  - An anonymous upgrade through a provider whose address does not carry
    to the stored one (a `+tag` outside Gmail) is held like a typed
    address: the promoted account comes back with empty tokens, a
    verification email is sent, and the anonymous session ends.
  - Username and anonymous accounts, which have no address to verify, are
    unaffected, as is every path with the flag off.
- **Proving an account's address voids provider links added before it
  (behaviour change).** When a passwordless email code or magic link, or a
  provider sign-in, first proves an account's address, identity already
  cleared the password and passkeys set while it was unproven. It now also
  deletes every provider link but the one signing in, each audited as
  `identity_unlinked` with
  `reason: planted_link_cleared_on_external_email_verification`, and revokes
  the account's sessions. A user who had linked a provider to their own
  unverified account links it again: a provider asserting the account's own
  address does so on its next sign-in, any other through `LinkIdentity`
  while signed in.
- **A tagged provider address no longer signs in to an existing account
  (behaviour change).** A provider sign-in whose address reaches an existing
  account only by dropping a `+tag` outside Gmail (`someone+x@example.com`
  for `someone@example.com`) does not prove that account's address. It is
  now refused with `unauthenticated` (audited as `login_failure` with
  `reason: provider_address_does_not_prove_account`) instead of signing in
  and linking. The account's owner links such a provider with
  `LinkIdentity` while signed in; a provider account already linked keeps
  signing in by its provider id.
- **Access tokens carry an `email_verified` claim (additive).** Every access
  token that carries an `email` now also carries `email_verified`: `true`
  only when the account's owner proved control of the mailbox in `email`
  (that address or another spelling of the same mailbox: a verification
  link, a passwordless email code or magic link, a passkey sign-up code, or
  a provider asserting that same mailbox), `false`
  otherwise. It is absent when `email` is (anonymous and username-only
  accounts). The value is read from the account at every issue, refresh
  included. With `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` on (the default) no
  session is issued for an unproven address (see the entry above), so
  `false` appears on a named account's token only with the flag off.
  Verifiers that ignore unknown claims are unaffected; one that
  gates on a proven address should require `email_verified: true` and treat
  a token without the claim, minted by an earlier release and still within
  its lifetime after the upgrade, as unproven. `pkg/jwt.Claims` gains the
  `EmailVerified` field, parsed on verify.

## v4.12.2 → v4.13.0 — sign-in stores emails in canonical form and `identity repair-emails` merges duplicate accounts (behaviour changes); an optional `iss` claim and per-project token audience

No schema change and no migration.

- **Tokens can name their issuer and their project (additive, off by
  default).** Every project of a deployment signs with the deployment's
  keys, so a signature alone does not say which project a token belongs to.
  `GATEWAY_JWT_ISSUER` adds an `iss` claim to every token identity mints, so
  a verifier can pin who minted it. `GATEWAY_JWT_PROJECT_AUDIENCE=true` adds
  the minting project's id to the token's `aud`, next to `GATEWAY_JWT_AUDIENCE`
  when that is set, so a verifier serving one project can refuse another
  project's token with a standard audience check. `aud` is always a JSON
  array and, with both set, holds two values, and a token minted without
  `GATEWAY_JWT_AUDIENCE` now carries an `aud`: a verifier must check that its
  own value is a member, not read the first entry or require a string. The
  settings isolate projects only once each verifier expects its own project
  id as the audience and pins `iss`; identity's `pkg/jwt` verifier does not
  check `iss` itself, so compare `Claims.Issuer` in your code.
- **`pkg/emailaddr` gains `Mailbox`** (the canonical form, and whether a
  mailbox is left once a `+tag` is dropped), and `SameMailbox` is false
  unless both addresses are mailboxes: two empty or tag-only addresses are no
  longer "the same mailbox".
- **A sign-in stores the account's email in canonical form (behaviour
  change).** An account stored under another spelling of its mailbox (a
  dotted Gmail address, capitals or a `+tag`, saved by a release before every
  write path canonicalized, or by SCIM before v4.9) was found only by that
  spelling: a code or password sign-in with the canonical spelling created a
  second account, and `LookupUsers` never found it. Now every token identity
  issues for such an account, at a sign-in (a provider sign-in that finds the
  account by its provider id included) or at a refresh of an older session,
  first moves the stored email to the canonical form. It keeps the email's
  verified state: the canonical form is the same mailbox, the one sign-in
  already treats it as. Two spellings are left as they are, because the
  account's proof does not carry over to the canonical form: one with no
  mailbox left once its `+tag` is dropped (`+x@example.com`), and one whose
  `+tag` outside Gmail would be dropped (some providers deliver a `+tag` to
  another mailbox). SCIM-provisioned accounts are rewritten like any other,
  as a SCIM `PUT` or `PATCH` already does. Consequences:
  - The access token's `email` claim, `GetUser` and `LookupUsers` carry the
    canonical spelling from then on. Key your records on the user id (`sub`),
    not on the email; to compare an email you stored, canonicalize it with
    `pkg/emailaddr` (below).
  - No `user.updated` webhook is emitted for the rewrite. The audit log
    records `email_canonicalized` (`source`: `sign_in`, or `session` for a
    refresh) without the address.
  - When an account merged into this one still holds the canonical spelling,
    it gives it up: its email is cleared and marked unverified.
  - When another live account holds the canonical spelling (two accounts for
    one mailbox), nothing is rewritten; each sign-in logs
    `email_canonical_form_held` (warning) with the account id, and
    `identity repair-emails` below merges the pair or tells you why not.
  - The rewrite keeps no copy of the old spelling. If you need one, list the
    accounts the query under [One email comparison rule](#one-email-comparison-rule)
    finds before upgrading.
- **`identity repair-emails` repairs the rest, once.** Accounts that never
  sign in keep their old spelling, and a sign-in never merges. Run the
  subcommand with the server's environment after upgrading. Plain
  `identity repair-emails` is a dry run: it logs one
  `identity_repair_emails_item` line per mailbox that holds a non-canonical
  spelling (account ids only, never addresses) and an
  `identity_repair_emails_done` summary. `identity repair-emails --apply`
  then does exactly what the dry run listed, in every project:
  - one account under a non-canonical spelling: its email is rewritten;
  - two active accounts of one **Gmail** mailbox, **both with a verified
    email**, neither managed by an identity provider (SCIM), exactly one
    linked to a sign-in provider (Google, Apple, …): merged into the
    provider-linked account under every rule of `MergeUsers`, audited as
    `account_merged` (`source: email_repair`, no actor), announced to the
    person with the merge notice and emitted as `user.merged`; then the
    survivor's email is rewritten;
  - anything else — an unverified account (it may not be the mailbox
    owner's), a `+tag` difference outside Gmail (it may be another person's
    mailbox), a spelling the sign-in rewrite also leaves (above), more than
    two accounts, an inactive account, both or neither provider-linked, a
    pair the merge rules refuse, or a canonical spelling held by an account
    merged into a different one — is logged with its reason and left for
    `MergeUsers`.

  Turn webhooks on first if your applications keep data under user ids: the
  run delivers the `user.merged` events it queues before it exits, even when
  it stops part-way, waits up to five minutes for them, and exits 1 if any
  is still queued or was abandoned after the retry policy's last attempt
  (`identity_repair_emails_events_undelivered`); a re-run does not re-emit
  them, so deliver those by hand. With
  webhooks off it logs `identity_repair_emails_without_webhooks`. A run that
  completes exits 0, skips included; a store failure on a mailbox exits 1
  and leaves that mailbox for the next run. Running it again lists only the
  skipped mailboxes. It replaces the manual SQL under
  [One email comparison rule](#one-email-comparison-rule). Take a database
  backup before `--apply`: a merge cannot be undone.
## v4.12.1 → v4.12.2 — the recent-sign-in window for merging is capped (behaviour change); Go 1.26.9 for the net/http and http2 advisories; `pkg/emailaddr`

No schema change and no migration.

- **`GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS` must be at most 3600.**
  A larger value let an hours-old session count as a recent sign-in, and is
  now refused at boot. A deployment that never set it, or set it within the
  range, sees no change. Lower a larger value before upgrading, or the new
  version will not start.
- **Merging relies on webhooks.** A merge retires an account, and
  applications learn about it only through the `user.merged` event: before
  turning on `GATEWAY_ACCOUNT_MERGE_ENABLED`, turn on
  `GATEWAY_WEBHOOKS_ENABLED` and subscribe every application that keeps data
  under user ids to `user.merged`; the admin `MergeUsers` announces its merges
  the same way. Identity already logs `account_merge_without_webhooks` at boot
  (since v4.12) when self-service merging is on and webhooks are off.
- **Built with Go 1.26.9 and `golang.org/x/net` v0.60.0** (with `x/crypto`
  v0.57.0, `x/sync` v0.23.0, `x/sys` v0.48.0 and `x/text` v0.42.0), which fix the
  `net/http` and http2 advisories GO-2026-6609 to GO-2026-6613 and
  GO-2026-6617. The published image carries the fix; anyone building identity
  or embedding its `pkg/` libraries should build on Go 1.26.9 or later.
- The graph `SearchNodes` query on Postgres matches usernames as well as
  emails and names (internal; no API change).

- **`pkg/emailaddr` (additive).** The canonical form is now a public
  package: `Canonicalize`, `CanonicalizeDomain` and `SameMailbox`. A service that stores emails
  it compares with identity's should key them by `emailaddr.Canonicalize`,
  from the identity version it runs against; a change to the rule will be
  announced here, since keys stored under the old rule would need
  recomputing.

## v4.12.0 → v4.12.1 — the admin user view shows usernames (fix)

No schema change and no migration.

- **`GetUser` and `ListUsers` return a username account's `username`**, and
  `ListUsers`' `search` matches usernames too. Before, an account made with
  `CreateUser` in username mode came back from both with no username and no
  email, and search could not find it.

## v4.11 → v4.12 — merging accounts, which needs a recent sign-in (`auth_time` on access tokens; native-gRPC hosts opt in with `GRPCTrustAuthTime`); a temporary password must be replaced at first sign-in; SCIM honours email accounts being off; the hosted page follows the account settings; gRPC client IPs come from the transport (behaviour changes); a per-IP budget for "username taken" answers

**Migration 0036** (SQLite 0019) adds `users.merged_into_user_id` with a
constant default (catalog-only; `lock_timeout = 10s`; on timeout confirm the
column is absent, then `identity migrate force 35` and `identity migrate`).

- **`MergeAccounts` (new, off by default: `GATEWAY_ACCOUNT_MERGE_ENABLED`)
  and the admin `MergeUsers` (new).** Merge one account of
  a person into another without deleting anything: the other account is
  retired (deactivated, with `User.merged_into_user_id` set, and never
  reactivatable), its linked providers move to the survivor (passkeys stay:
  register them again),
  which also takes its username, password and email where it has none, all
  in one transaction, and a `user.merged`
  event (carrying `merged_into_user_id`) tells applications to move data
  held under the retired id. See *Merging accounts* in the docs.
- **`MergeAccounts` requires a recent sign-in of the account that is kept**:
  one within `GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS` (new, default
  300; 0 selects it, and it cannot be turned off), read from the access
  token's new `auth_time` claim. Otherwise it answers `FAILED_PRECONDITION`
  `reauthentication_required`.
- **Access tokens a sign-in issues carry `auth_time`** (epoch seconds;
  named after OIDC's, but deliberately narrower). A refreshed token, or one
  from a QR handoff, an anonymous sign-in or a password added to an
  anonymous account, carries none. A client that signs a user in again
  before `MergeAccounts` uses that sign-in's own access token, not a
  refreshed one.
  Verifiers that ignore unknown claims see no change. **Native-gRPC hosts**
  that use `MergeAccounts` forward it as `x-authenticated-auth-time`
  metadata, after deleting any value the client sent, and set the new
  `Options.GRPCTrustAuthTime`; without it the bridge drops the key and
  merges over native gRPC are refused (see the embedding guide).
- **Webhook subscribers receive a new event type, `user.merged`.** A
  subscription with no event-type filter receives every type, so it gets
  `user.merged` too; make sure your handler ignores (or handles) types it
  does not know. A subscription that lists its types sees it only if it
  lists it.
- **SCIM `POST /Users` answers `403` when the project's
  `accounts.email_signup` is `off`**, as admin creation already did. A
  project that never set `email_signup`, or set it to `self` or `admin`,
  sees no change.
- **The hosted page (`/auth/`) now reads `accounts.email_signup` and
  `accounts.username_signup`.** It hides email sign-up unless
  `email_signup` is `self`, offers username sign-up where `UsernameSignup`
  would accept it, and takes a username at sign-in where the project has
  username accounts. A project with default settings sees no change.
- **`GATEWAY_RATE_LIMIT_USERNAME_TAKEN_PER_IP` (new, default 5).**
  `UsernameSignup` tells a caller when a username is taken; after an IP has
  been told that this many times in one rate-limit window, every
  `UsernameSignup` from it answers `RESOURCE_EXHAUSTED` until the window
  ends. Counted per replica and per exact address; users behind one shared
  NAT share it, so raise it (or set `0` to disable) where that bites.
- **Native gRPC: the client IP handlers see is the transport's.** The gRPC
  bridge used to copy an incoming `x-client-ip` metadata entry through to
  the handlers, so a gRPC caller could choose the address its rate limits,
  budgets and audit entries were keyed on. It now always sets it from the
  connection (and a trusted proxy's `x-forwarded-for`), as HTTP does, and
  drops caller-supplied `x-forwarded-for` / `x-real-ip` from what handlers
  see. **If a gateway in front of the gRPC port set `x-client-ip`**, send the
  end user's address as `x-forwarded-for` instead and list the gateway in
  `GATEWAY_TRUSTED_PROXIES`; otherwise every call is attributed to the
  gateway and shares one set of per-IP limits.
- **Match `RESOURCE_EXHAUSTED`, not the message,** for sign-up throttling:
  its text no longer mentions the identifier.

- **A temporary password must be replaced at first sign-in (behaviour
  change).** **Migration 0037** (SQLite 0020) adds
  `users.password_change_required`, a constant default (catalog-only, the
  same `lock_timeout` rule: on timeout confirm the column is absent, then
  `identity migrate force 36` and `identity migrate`). A password an admin
  issues from now on — `InviteUser` with `create_immediately`, `CreateUser`
  in username mode, `ResetUserPassword` with `generate_temp_password` —
  sets it, and `PasswordLogin` with that password answers
  `FAILED_PRECONDITION` `password_change_required` with a
  `PasswordChangeRequiredDetails` ticket instead of tokens. The client calls
  the new `CompleteRequiredPasswordChange` (unauthenticated, per-IP login
  rate limit) with the ticket, a new password and, when the detail's
  `second_factor_required` is set, the user's two-step code. A client that signs
  admin-created users in must handle the new refusal: deploy that support
  before upgrading the server. Completing the change ends the account's
  other sessions. Temporary passwords issued before the upgrade are not
  flagged.

## v4.10 → v4.11 — account addresses on the project's domain (additive); neutral built-in defaults; invitation links follow the project (behaviour change)

**Migration 0035** (SQLite 0018) adds `users.account_address` and a partial
unique index on `(project_id, account_address)`. The column has a constant
default, so adding it does not rewrite the table. The index build blocks
writes to `users`, not reads, for one scan of the table. It waits at most
10s for its lock. If it times out, version 35 is left dirty: confirm the
column is absent, then `identity migrate force 34` and `identity migrate`
again.

- **Account addresses (new, off by default).** Set `accounts.domain` in a
  project's config, or `GATEWAY_DEFAULT_EMAIL_DOMAIN` for the default
  project. Every permanent account is then issued an address on that
  domain: `<username>@<domain>` for a username account, and the email with
  `@` written as `-at-` for an email account, once its email is verified.
  Existing accounts get theirs at their next sign-in, once their email is
  verified. `User.account_address` carries it. A deployment
  that sets neither behaves exactly as before. See *Account addresses* in
  the docs.
- **Usernames may not end in `-` and eight hex digits**, the tag a clashing
  account's fallback address carries.
- **Who creates each kind of account (new; defaults keep today's
  behaviour).** `accounts.email_signup` and `accounts.username_signup`
  (default project: `GATEWAY_DEFAULT_PROJECT_EMAIL_SIGNUP` and
  `GATEWAY_DEFAULT_PROJECT_USERNAME_SIGNUP`) take `self`, `admin` or `off`.
  Email defaults to `self` and usernames to `off`, so nothing changes until
  you choose. New: `UsernameSignup`, and `CreateUser` takes `username` and
  returns `temporary_password` for a username account.
- **Sign-in and refresh follow one access rule for every account.** An
  account with an email is judged by its email, as before. A username
  account is admitted under `open` and `invite` and refused under
  `allowlist` and `closed`; a managed child is admitted under every mode.
  Before, a managed child in a non-`open` project could sign in but its
  first refresh was refused; now it refreshes too.
- **`accounts` in a project's config is now read and validated.** A stored
  config that already had an `accounts` key with a `domain` that is not a
  fully qualified name stops that project resolving until it is fixed. An
  invalid `GATEWAY_DEFAULT_EMAIL_DOMAIN` stops the server from starting.
- **Usernames may no longer contain `-at-`, start or end with `.`, contain
  `..`, or be a reserved role name** (`abuse`, `admin`, `administrator`,
  `ftp`, `hostmaster`, `info`, `mailer-daemon`, `marketing`, `news`, `noc`,
  `no-reply`, `noreply`, `postmaster`, `root`, `sales`, `security`,
  `ssl-admin`, `support`, `usenet`, `uucp`, `webmaster`, `www`). This keeps a username's address apart from the addresses
  emails derive to, and keeps every address valid. It applies to new
  managed child usernames and to renames; existing usernames are kept and
  still sign in.

- **`GATEWAY_TOTP_ISSUER` and `GATEWAY_PASSKEY_RP_NAME` default to
  `Identity`.** The built-in defaults used to name one deployment's
  product. If you never set them, new authenticator-app enrolments and new
  passkeys now show `Identity`: set both to your product's name. Existing
  enrolments and passkeys keep the name they were created with.
- **`GATEWAY_DEFAULT_EMAIL_DOMAIN` defaults to empty, and now takes
  effect.** Its built-in default named one deployment's domain, and nothing
  read it. It is now the default project's account domain (above). **If
  you set it before, the default project starts issuing account addresses
  on that domain**: unset it unless you want that.
- **Admin invitation links (`InviteUser`) follow the request's project**,
  like magic-link, email-change and tenant-invitation links: the project's
  primary auth domain, else `GATEWAY_APP_BASE_URL`, else the localhost
  development default. A configuration built in code with an empty
  `AppBaseURL` used to point them at a fixed external host. The invitation
  email names the product from the project's `branding.product_name`, else
  `GATEWAY_EMAIL_BRAND_PRODUCT_NAME`, else `GATEWAY_TOTP_ISSUER`.
- **No email is sent with a line break in its subject.** A product name
  now reaches the invitation subject, so the email layer refuses a
  multi-line subject instead of writing it into the header.

## v4.9 → v4.10 — reset and verification links can point at a sign-in hub (additive); stricter URL boot checks

No schema change and no migration. A deployment that sets nothing new sends
exactly the same emails as before.

<a id="from-v481"></a>**On v4.8.1 and using `GATEWAY_EMAIL_LINK_BASE_URL`,
`product` or `return_to`, upgrade straight to v4.10.0, not to v4.9.0.**
v4.8.1 carried the variable and the two fields below as a patch. v4.9.0 has
none of them and ignores them without an error, so its reset and
verification links go back to `/auth/…` and lose the product and redirect.
Skipping the v4.9.0 release does not skip its notes: read
[v4.8 → v4.9](#v48--v49--scim-throttling-and-audit-directory-limit-on-every-transport-wildcard-origins-one-email-comparison-rule-migration-0034)
first, including migration 0034, which rewrites `users` under an exclusive
lock.

- **`GATEWAY_EMAIL_LINK_BASE_URL`** (default empty) is where the
  password-reset and email-verification pages live. Identity does not serve
  those pages: by default the links go to `/auth/reset-password` and
  `/auth/verify-email` on the project's primary auth domain, else on
  `GATEWAY_APP_BASE_URL`. **If you serve these pages somewhere else, set the
  variable to that base URL** — for example a sign-in hub at
  `https://signin.example.com`, which serves `/reset-password` and
  `/verify-email`. The links then become `<base>/reset-password?token=…`
  and `<base>/verify-email?token=…` for every project, and take precedence
  over any project's primary auth domain. The value must be an absolute
  `https` URL (`http` only for a loopback host) with no userinfo, query or
  fragment. A path prefix is kept, and a trailing slash is ignored. Any other
  value stops the server from starting
  (`config: GATEWAY_EMAIL_LINK_BASE_URL …`). Magic-link, email-change and
  invitation links are not affected.
- **`product` and `return_to` on `RequestPasswordReset`, `PasswordSignup`
  and `SendEmailVerification`.** Both are optional. When set, they are added
  to the emailed reset or verification link, URL-encoded after the token, as
  `&product=<slug>` and `&redirect=<return_to>`, so the page can show the
  right product and send the user back where they started. `product` is
  trimmed and lower-cased and must then be 1–64 characters of `a-z`, `0-9`,
  `-` and `_`, starting with a letter or digit. `return_to` must match
  `GATEWAY_OAUTH_ALLOWED_RETURN_URLS`, the allowlist hosted OAuth and magic
  links already use; with that allowlist empty, every `return_to` is refused.
  A refused value fails the call with `INVALID_ARGUMENT` before anything is
  created or sent. `RequestPasswordReset` used to succeed for every request;
  it now returns this one error, and only for a request that sets one of the
  new fields wrongly. The check reads only the request, so the answer is the
  same for every address and reveals nothing about which accounts exist.
  Clients that send neither field see no change. The check covers only the
  links Identity sends: anyone can put `redirect` on a link by hand next to
  a token of their own, so the page must check `redirect` against its own
  allowlist before following it (see the configuration docs' "Reset and
  verification links").
- **Per-product email branding.** A product in a project's `products`
  block may carry a `branding` block with the same fields as the project's
  `branding`. It brands the reset and verification emails of a request that
  names that product in `product`, field by field over the project's
  branding, which still applies when no product is named or the product has
  no `branding`. Write it with `UpsertProjectConfig`; a malformed address
  or a non-`https` logo URL in it is refused like one in the project's
  `branding`. It needs a project resolved from the control plane (by
  credential key or auth domain) — the env-pinned default project has no
  `products` block.
- **Webhook URL errors no longer echo userinfo.** A
  `GATEWAY_WEBHOOK_SUBSCRIPTIONS` URL that fails validation is now reported
  with any userinfo redacted.
- **A URL no request could reach stops the server from starting.** A
  `GATEWAY_WEBHOOK_SUBSCRIPTIONS` URL or `GATEWAY_EMAIL_LINK_BASE_URL` with
  no host name (`https://:443`) or a port outside 1–65535 is now refused at
  boot, as is an email link base ending in a bare `#`.
- **Dependencies**: `go.opentelemetry.io/otel` v1.45.0 (GO-2026-6505).

## v4.8 → v4.9 — SCIM throttling and audit; directory limit on every transport; wildcard origins; one email comparison rule (migration 0034)

On v4.8.1 and using `GATEWAY_EMAIL_LINK_BASE_URL`, `product` or
`return_to`, skip v4.9.0 and go to v4.10.0: see
[upgrading from v4.8.1](#from-v481).

**Postgres deployments get migration 0034, which rewrites the `users` table
under an exclusive lock.** Read
[Migration 0034 rewrites `users`](#migration-0034-rewrites-users-postgres)
**before** upgrading. Every deployment gets one rule for comparing email
addresses; see
[One email comparison rule](#one-email-comparison-rule). Four further groups
of deployments see a change in behaviour:

- **`GATEWAY_SCIM_ENABLED` deployments.** Every request under `/scim/v2/` now
  counts against a per-client-IP limit, **`GATEWAY_RATE_LIMIT_SCIM_PER_IP`**
  (default 300 per `GATEWAY_RATE_LIMIT_WINDOW_SECONDS` window; `0` turns it
  off). The limit is checked before the bearer token, so it also holds a
  caller trying tokens. Over it a request gets HTTP 429 with a `Retry-After`
  header. If your IdP pushes faster than that from one address — a first full
  import is the burstiest — raise the limit before upgrading. A request with
  a missing or wrong bearer token is now logged (`scim_auth_failed`, warning)
  and audited (`scim_auth_failed`, `success=false`, with the client IP, user
  agent and a `reason` of `missing_token` or `invalid_token`; never the token)
  under `GATEWAY_SCIM_PROJECT_ID`.

  **Consider rotating `GATEWAY_SCIM_BEARER_TOKEN`.** v4.8 made the SCIM surface
  reachable, and until this release a request carrying a wrong token was
  neither throttled nor audited; only the request log recorded its 401. Check
  any request logs you retain for 401s under `/scim/v2/` before deciding, and
  rotate if you cannot rule out guessing. Generate a new token of at least 32 characters, set it in your
  IdP's SCIM connector, then restart identity with it.
- **Hosts that serve identity through `RegisterGRPC`.** `LookupUsers` is now
  rate-limited on the native gRPC surface too, drawing on the same per-IP
  budget (`GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP`) as the HTTP handler. A
  throttled call fails with `RESOURCE_EXHAUSTED` and carries the wait, in
  seconds, in its `retry-after` response metadata. The caller is the
  connection's peer address, or the first untrusted `x-forwarded-for` hop
  when the peer is in `GATEWAY_TRUSTED_PROXIES`. A host that already throttles
  `LookupUsers` in its own interceptor can keep doing so; both limits apply.
- **Deployments with a `*` inside an origin or return-URL allowlist entry**
  (`GATEWAY_ALLOWED_ORIGINS`, a project's `cors.allowed_origins`,
  `GATEWAY_OAUTH_ALLOWED_RETURN_URLS`). Such an entry is now a one-label
  wildcard pattern (below). Before, such a return-URL entry was silently
  ignored and such a CORS entry was compared literally, so it never matched.
  Now:
  - A valid pattern admits every single-label subdomain of its parent. Check
    each one before upgrading.
  - An entry that is not a valid pattern — including one whose parent is a
    public suffix, such as `https://*.co.uk`, `https://*.vercel.app`,
    `https://*.netlify.app`, `https://*.pages.dev` or `https://*.github.io`,
    or one directly under a wildcard suffix rule such as
    `https://*.compute.amazonaws.com` —
    makes the server **refuse to start** (`cors config invalid: …` /
    `GATEWAY_OAUTH_ALLOWED_RETURN_URLS invalid: …`). Scope a preview pattern
    to your own project instead: `https://*.<project>.pages.dev`.
  - A pattern whose parent ends in a numeric label (`https://*.0.0.1`) or
    whose port is outside 1–65535 is refused the same way. A zero-padded
    port is read as the number (`:0443` means 443).
  - A **project** whose stored `cors.allowed_origins` fails these rules keeps
    serving — native login, SCIM, sessions and admin writes are unaffected —
    but its **whole per-project CORS list is dropped**: browser requests from
    its origins get no CORS grant unless `GATEWAY_ALLOWED_ORIGINS` admits
    them, and each resolution logs `project_cors_config_invalid_failing_closed`
    with the project id. This also covers malformed non-wildcard entries (a
    path, no scheme, `null`, an empty string, userinfo, an upper-case scheme,
    a trailing `?`) that the admin API used to accept; before this release
    such a project answered **503** on every request instead. The admin
    API's whole-config write (`UpsertProjectConfig`) now refuses any such
    entry. Find affected projects before upgrading (Postgres):

    ```sql
    SELECT p.id, o.entry
    FROM projects p,
         jsonb_array_elements_text(
           CASE WHEN jsonb_typeof(p.config_json -> 'cors' -> 'allowed_origins') = 'array'
                THEN p.config_json -> 'cors' -> 'allowed_origins' ELSE '[]'::jsonb END
         ) AS o(entry)
    WHERE o.entry LIKE '%*%'
       OR o.entry !~ '^https?://[^/?#@[:space:]\\]+$';
    ```

    Every row is an entry to review: a `*` entry must be a valid pattern
    under a parent you control, and any other row is malformed. Replace the
    project's config with `UpsertProjectConfig` to fix it.
- **Deployments with a malformed exact `GATEWAY_OAUTH_ALLOWED_RETURN_URLS`
  entry** (no `*`; not an absolute http(s) URL, or carrying a query or
  fragment). Such an entry still admits nothing and still does not stop the
  server, but it is now logged at startup as `oauth_allowed_return_url_ignored`.
  If the list holds no usable entry at all, the hosted OAuth routes are no
  longer registered (404, logged as `oauth_hosted_flow_disabled`) instead of
  answering every `return_to` with 400, and magic-link sign-in is off.

Also changed:

- **`Retry-After` follows the window.** Every per-IP limit's 429 now carries
  `Retry-After` equal to `GATEWAY_RATE_LIMIT_WINDOW_SECONDS` (rounded up to a
  whole second) instead of a fixed `60`. Deployments on the default 60-second
  window see no difference.
- **`GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP` is parsed like the other limits.**
  A value that is not an integer, or `0`, now leaves the default (120) in
  force instead of failing the boot; a negative value still fails it. The
  limit still cannot be switched off.
- **Boot log.** Startup logs `directory_lookup_enabled` (with the effective
  per-IP limit, window and verified-email rule) or `directory_lookup_disabled`,
  as it already does for SCIM.
- **New audit event:** `scim_auth_failed`.
- **One-label wildcard origins.** The three allowlists above accept
  `https://*.previews.example.app`, for per-branch preview deployments: the
  `*` matches exactly one DNS label under the fixed parent, `https` only, on
  a fixed port. Return-URL patterns keep the path-prefix rule
  (`https://*.previews.example.app/auth`). CORS echoes the concrete request
  `Origin`, never the pattern. Startup logs patterns next to the exact entries
  (`origin_patterns`, `allowed_return_url_patterns`). A pattern admits every
  host under its parent, so use one only for a parent whose every subdomain
  you control; parents on the public suffix list are refused. See
  [Wildcard origin patterns](../docs-site/src/pages/docs/installation/configuration.astro).
- **Stricter `GATEWAY_ALLOWED_ORIGINS` parsing.** An entry with a trailing
  empty query (`https://app.example.app?`) is now refused at startup, like
  one with a query.
- **`return_to` with a backslash is refused.** Browsers read `\` as `/` in
  an http(s) URL, so `https://app.example.app/auth/..\x` passed a `/auth`
  entry and then landed outside it. A hosted-OAuth or magic-link `return_to`
  containing a backslash is now rejected like any other disallowed one.
- **`Vary: Origin`** is sent on every response that passes through the CORS
  middleware, so a shared cache never serves one origin's CORS headers to
  another.

### Migration 0034 rewrites `users` (Postgres)

**What it does.** It adds `users.email_fold`, a stored generated column
`lower(email COLLATE "C")`: the address with its ASCII letters lowered and
every other character kept. It replaces the unique index
`users_project_email_partial_uidx` (on the locale's `lower(email)`) with
`users_project_email_fold_uidx` on `(project_id, email_fold) WHERE email <> ''`,
and `tenant_invitations_open_email_uidx` with
`tenant_invitations_open_email_fold_uidx`. It also rewrites each *pending*
tenant invitation with an all-ASCII address in the canonical form the
service now stores (see below). Where several pending invitations of a
tenant name one mailbox, it first revokes all but the newest and then
renames the newest, so it resolves those collisions itself. Pending
invitations with a non-ASCII address keep their spelling. Email lookups, the `ListUsers` and
SCIM email filters and the admin user query compare `email_fold` with `=`.
Under `FORCE ROW LEVEL SECURITY` only such a leakproof comparison can use the
index. The old `lower(email)` comparison read every row of the project on
every lookup.

**How it is applied.** Run `identity migrate` **before any replica of the new
version serves traffic**: the new version queries `users.email_fold`, and
until 0034 has run every email lookup fails with
`column "email_fold" does not exist`. The alternative is
`GATEWAY_POSTGRES_AUTO_MIGRATE`, which applies it when the first new replica
boots, before that replica serves. The SQLite driver needs no migration: its
`lower()` already folds ASCII only.

**Locking and sizing.** Adding a stored generated column rewrites the whole
`users` table under an `ACCESS EXCLUSIVE` lock. The unique index is then
built in the same transaction. Sign-in, token refresh, SCIM and every other
read or write of `users` waits until both finish, for a time that grows with
the table. Estimate it by timing the migration on a restored copy of
production, or at least check the table's size:

```sql
SELECT pg_size_pretty(pg_total_relation_size('users'));
```

**Do not rely on auto-migrate for a large `users` table.** Under auto-migrate
the rewrite runs inside the booting replica, and a startup or liveness probe
that gives up first restarts the container, killing the rewrite part-way
(the transaction rolls back and the version is left dirty; see below). Run
`identity migrate` as a separate job in a maintenance window instead, or at
least give the first new replica a startup probe longer than the rewrite
takes. The migration sets
`lock_timeout = '10s'`. That bounds only the wait to *acquire* the lock:
queued behind a long-running transaction, the `ALTER` would otherwise stall
every later query on `users`. The timeout does not bound the rewrite itself.
If it fires, the migration fails; see
[If 0034 fails](#if-0034-fails-the-version-is-left-dirty).

Every statement is guarded with `IF [NOT] EXISTS`, so you can shorten the
exclusive window by applying the pieces yourself, as a role that owns the
tables:

```sql
-- 1. In the window: the rewrite (ACCESS EXCLUSIVE for its duration).
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_fold TEXT COLLATE "C"
    GENERATED ALWAYS AS (lower(email COLLATE "C")) STORED;
-- 2. Afterwards, without blocking writes (not inside a transaction):
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_project_email_fold_uidx
    ON users (project_id, email_fold) WHERE email <> '';
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS tenant_invitations_open_email_fold_uidx
    ON tenant_invitations (project_id, tenant_id, lower(email COLLATE "C"))
    WHERE status = 'pending';
-- 3. Then `identity migrate`: it rewrites the pending invitations and drops
--    the two old indexes, skipping what exists.
```

**Pre-flight: no two rows may collide under the new indexes.** Addresses equal
under the ASCII fold were already equal under the old `lower()` in every
locale that lowers ASCII letters to ASCII. A Turkic locale does not (`I`
lowers to a dotless `ı`), so a colliding pair can exist there. If one does,
the index build fails and so does the migration
([If 0034 fails](#if-0034-fails-the-version-is-left-dirty)). `users` has
`FORCE ROW LEVEL SECURITY`, so run this as a role with `BYPASSRLS` or as a
superuser. `SET row_security = off` makes any other role fail instead of
reporting an empty result:

```sql
SET row_security = off;
SELECT project_id, lower(email COLLATE "C") AS email_fold, array_agg(id) AS ids
FROM users WHERE email <> ''
GROUP BY 1, 2 HAVING count(*) > 1;
```

Resolve any rows this returns (merge the accounts, or change one address)
before upgrading. Pending tenant invitations need no pre-flight: the
migration revokes all but the newest invitation per canonical mailbox before
it builds their index.

**Rolling back.** The down migration restores the locale `lower()` indexes and
drops `users.email_fold`. It does not undo the invitation rewrite: pending
invitations keep their canonical addresses, and the ones it revoked stay
revoked. It fails if accounts or open invitations created after the upgrade differ only in
the case of a non-ASCII letter (`é` and `É`) and the database locale folds
them. Its SQL then rolls back, leaving 0034 in place, but the runner records
version **33** as dirty (it marks the version a migration moves to). Clear
that with `identity migrate force 34`, which is the version the schema is
really at. Find such rows
before migrating down, as a `BYPASSRLS` role:

```sql
SET row_security = off;
SELECT project_id, lower(email) AS email_lower, array_agg(id ORDER BY created_at_ms) AS ids
FROM users WHERE email <> ''
GROUP BY 1, 2 HAVING count(*) > 1;
```

Resolve them before migrating down.

#### If 0034 fails, the version is left dirty

When the lock timeout fires or the index build fails, the migration's SQL
rolls back as one transaction and changes nothing. The migration runner
still records schema version 34 as *dirty*. Every later `identity migrate`,
and every boot with `GATEWAY_POSTGRES_AUTO_MIGRATE`, then refuses to run, and
replicas that auto-migrate fail to boot until it is cleared. The error says
which version to record ("record version 33"), and `identity migrate` logs
the command that records it (`record_version_with`). To recover:

1. Confirm the migration did not apply. The column is absent unless you
   added it by hand:

   ```sql
   SELECT count(*) FROM information_schema.columns
   WHERE table_name = 'users' AND column_name = 'email_fold';  -- 0
   SELECT version, dirty FROM schema_migrations;               -- 34, true
   ```

2. Remove the cause (end the long-running transaction, or resolve the
   collisions the pre-flight query lists).
3. Run `identity migrate force 33`, which records version 33, clears the flag
   and runs nothing. Then run `identity migrate`, which applies 0034 again.

Because every statement in 0034 is guarded with `IF [NOT] EXISTS`, forcing 33
and re-running is also right when you added the column or the new indexes by
hand: the re-run skips what exists and finishes the rest. Any failed migration
leaves the same dirty state, and the refusal names the version to record for a
failed apply and for a failed rollback. If it says the dirty version is newer
than this build, a newer identity release migrated the database: recover with
that release, never with this one.

#### `identity migrate` refuses other arguments

`identity migrate` now accepts no argument except
`force [--override] <version>`.
Anything else — a flag such as `--verbose`, a stray word — exits with status 2
instead of being ignored. Check any migrate Job or script that passes extra
`args` before upgrading, or the step will fail.

### One email comparison rule

The service canonicalizes every address it is given before any store sees it.
Canonicalizing trims the address, lower-cases it, drops a `+tag`, drops Gmail
dots and punycodes an internationalized domain. Sign-up and sign-in already
did this. This release applies it to SCIM, `LookupUsers`, tenant invitations,
admin `InviteUser` and email change as well. The stores then compare what they are
given under one rule: ASCII letters fold, every other character must match
exactly. Before this release Postgres compared by the database locale's
`lower()`, while SQLite and the memory driver compared by ASCII case, so the
same addresses could match on one deployment and not on another.

- **Accounts stored in a non-canonical form stop matching.** Lookups,
  `LookupUsers` and the admin `InviteUser` duplicate check all compare the
  canonical form of the address they are given with the stored address under
  the ASCII fold. An account whose stored address is not canonical is
  therefore found only by its own spelling (up to ASCII case), and not at all
  by `LookupUsers`, which canonicalizes. Sign-up and sign-in always stored
  canonical addresses. Earlier releases did not canonicalize in:
  - SCIM, which stored the address as the IdP sent it (capitals, `+tag`,
    Gmail dots);
  - email change and admin `InviteUser`, which stored it lower-cased but kept
    a `+tag` or Gmail dots.

  On a Postgres database whose locale folds non-ASCII letters (for example
  `en_US.UTF-8`), a stored `Élodie@corp.com` also used to match
  `élodie@corp.com` and no longer does. List every account whose stored
  address differs from its canonical form, as a `BYPASSRLS` role. The query
  computes the canonical form the way the service does, except that it does
  not punycode an internationalized domain; list those separately with
  `WHERE email ~ '@.*[^!-~]'`.

  ```sql
  SET row_security = off;
  WITH parts AS (
      SELECT project_id, id, email,
             substring(lower(email) FROM '^(.*)@') AS local_part,
             regexp_replace(substring(lower(email) FROM '@([^@]*)$'), '\.$', '') AS raw_domain
      FROM users WHERE email <> ''
  ), domains AS (
      SELECT *, CASE WHEN raw_domain = 'googlemail.com' THEN 'gmail.com' ELSE raw_domain END AS domain
      FROM parts
  )
  SELECT project_id, id, email,
         CASE WHEN domain = 'gmail.com' THEN replace(split_part(local_part, '+', 1), '.', '')
              ELSE split_part(local_part, '+', 1)
         END || '@' || domain AS canonical_email
  FROM domains
  WHERE email <> CASE WHEN domain = 'gmail.com' THEN replace(split_part(local_part, '+', 1), '.', '')
                      ELSE split_part(local_part, '+', 1)
                 END || '@' || domain
  ORDER BY project_id, canonical_email;
  ```

  Fixing them:
  - Re-sync a SCIM-provisioned account from your IdP (a SCIM `PUT` or `PATCH`
    of the user); that stores the canonical form.
  - Two rows of one project that share a `canonical_email` are two accounts
    for one mailbox. Decide which one to keep before changing either.
  - Every other row can be rewritten in place after the upgrade, as a
    `BYPASSRLS` role. There is no API that sets an account's address to
    another spelling of the same mailbox, because email change refuses it.
    The statement below skips any row whose canonical form another account in
    the project already holds, or that shares it with another listed row.
    It records no audit event.

  ```sql
  SET row_security = off;
  WITH parts AS (
      SELECT project_id, id, email,
             substring(lower(email) FROM '^(.*)@') AS local_part,
             regexp_replace(substring(lower(email) FROM '@([^@]*)$'), '\.$', '') AS raw_domain
      FROM users WHERE email <> '' AND email !~ '@.*[^!-~]'
  ), domains AS (
      SELECT *, CASE WHEN raw_domain = 'googlemail.com' THEN 'gmail.com' ELSE raw_domain END AS domain
      FROM parts
  ), canonical AS (
      SELECT project_id, id, email,
             CASE WHEN domain = 'gmail.com' THEN replace(split_part(local_part, '+', 1), '.', '')
                  ELSE split_part(local_part, '+', 1)
             END || '@' || domain AS canonical_email
      FROM domains
  ), fixable AS (
      SELECT c.* FROM canonical c
      WHERE c.email <> c.canonical_email
        AND (SELECT count(*) FROM canonical o
             WHERE o.project_id = c.project_id AND o.canonical_email = c.canonical_email) = 1
  )
  UPDATE users u
  SET email = f.canonical_email,
      updated_at_ms = (extract(epoch FROM clock_timestamp()) * 1000)::bigint
  FROM fixable f
  WHERE u.id = f.id;
  ```

- **SCIM.** `userName` and `emails` are stored in canonical form, so a
  provisioned account is the one sign-in finds, and a later self-sign-up with
  the same mailbox is refused as a duplicate instead of creating a second
  account outside SCIM deprovisioning. Responses carry the canonical address
  as `userName`, which can differ from what your IdP sent. The `userName eq` /
  `emails eq` filter canonicalizes its value, so an IdP searching by its own
  spelling still finds the user. An account provisioned by an earlier release
  (stored as the IdP spelled it) is still found by that spelling, so an IdP
  that filters before it creates does not create a second account. The next
  `PUT` or `PATCH` of that account stores the canonical form.
- **`LookupUsers`.** Each requested address is canonicalized exactly as
  sign-in canonicalizes it, so the lookup finds the account sign-in with that
  address would. Addresses that canonicalize to the same address produce one
  entry. The entry's `email` is the address on file, which can differ from
  the requested spelling in case, a `+tag` or Gmail dots, so each entry now
  also carries **`requested_emails`** (`requestedEmails` in JSON): every
  address you sent that found it, each distinct spelling once. Pair results
  with requests by that field, not by `email`. The field is additive; older
  clients ignore it.
- **`LookupUsers` error order.** The batch is now validated before the
  directory key is looked up. A request with a missing key, or one not shaped
  `<public id>.<secret>`, is still `UNAUTHENTICATED`. A request with a
  well-formed but wrong key and a malformed batch (empty, more than 100
  addresses, a blank or over-320-byte address) now gets `INVALID_ARGUMENT`
  instead of `UNAUTHENTICATED`.
- **Tenant invitations** are stored in canonical form. Accepting one compares
  the caller's address and the invited address in canonical form, so a `+tag`
  variant of the invited mailbox may accept, and an address differing in a
  non-ASCII letter may not (`PERMISSION_DENIED`). A new invitation revokes the pending one for the same mailbox, and
  concurrent invitations to one mailbox leave one pending instead of failing.
  That holds for every invitation created from this release on, and for the
  pending all-ASCII ones 0034 canonicalized. A pending invitation with a
  non-ASCII address stored before this release keeps its spelling: if that
  spelling is not canonical (a `+tag`, a Gmail variant), a new invitation to
  the same mailbox leaves it pending beside the new one until it expires or
  is revoked.
- **Admin `InviteUser`** stores the invited address in canonical form, and
  refuses it as a duplicate when an account already holds that canonical
  form. An account stored in a non-canonical form (see above) is not
  recognised by that check.
- **Addresses that are nothing but a `+tag`** (`+x@corp.com`) pass the
  address format check but have no mailbox left once canonical. Every path
  that stores or looks up an account's address now refuses them: sign-up and
  sign-in (`INVALID_ARGUMENT`), passkey sign-up, the anonymous upgrade, admin
  `InviteUser`, email change, tenant invitations, SCIM (`invalidValue`) and
  the first-admin bootstrap. OAuth sign-in refuses such a provider address as
  unauthenticated. Passwordless requests and password resets still answer as
  before but send nothing, and `LookupUsers` returns no entry for them.
- **Email change** stores the new address in canonical form, and refuses one
  whose canonical form equals the current address, for example
  `me+x@corp.com` for `me@corp.com`, because sign-in already resolves it to
  the same account.

## v4.7 → v4.8 — directory lookup for services (additive); session-mode and SCIM fixes (behaviour changes)

This release adds a read-only lookup RPC and the credential kind that
authorizes it. It also fixes two defects, and those fixes change behaviour for
two groups of deployments:

- deployments running `GATEWAY_REVOCATION_MODE=session` with more than one
  project serving traffic — read
  [Session revocation mode](#session-revocation-mode-binds-each-request-to-its-project)
  **before** upgrading;
- deployments with `GATEWAY_SCIM_ENABLED` set.

Every other deployment sees only the additions.

### Additions

- **Directory reader credentials.** Mint one with the existing
  `AdminCreateProjectCredential` (`X-Admin-Secret`),
  `kind: "directory_reader"`. The response's `raw_key`
  (`dk_<public>.<secret>`) is shown once; keep `credential_id`.
- **`LookupUsers`.** Send `{ emails: [...] }` (1–100 addresses, each at most
  320 bytes) with the raw key in the `X-Directory-Key` header. The response
  holds `{id, email, name, avatar_url, email_verified}` for each distinct
  address that names an **active** account in the credential's project.
  Matching is exact, ignoring case, and addresses that differ only in case
  count once. Omitted addresses leave no gap, so match entries to your request
  by `email`, not by position. While `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` is
  on (the default), accounts whose email is unverified are not returned.
  Otherwise whoever signed up with an address first would be returned as its
  owner. With the setting off they are returned with `email_verified: false`.
  The key authorizes this RPC and no other. It reads only the project it was
  minted for, whatever the request's `Host` or `X-Project-Key`, and it is not
  itself a project key. Call it from server-side code only: the header is not
  CORS-allowed.
- **`AdminRevokeProjectCredential { project_id, credential_id }`**
  (`X-Admin-Secret`). It revokes credentials of every kind, is idempotent,
  and returns `NOT_FOUND` for a credential the project does not own. A revoked
  directory key is refused on its next lookup. A revoked publishable, secret
  or mTLS key keeps selecting its project until each replica's
  project-resolution cache expires it, which takes up to
  `GATEWAY_PROJECT_RESOLUTION_CACHE_TTL_SECONDS` (default 30 s).
- **Migration 0033** (Postgres only, like every project credential): **run
  `identity migrate`** or set `GATEWAY_POSTGRES_AUTO_MIGRATE`. It widens the
  `project_credentials.kind` constraint. Its down migration deletes any
  directory credentials, because the narrower constraint cannot hold them. On
  the memory and SQLite drivers `LookupUsers` returns `UNIMPLEMENTED`.
- **`GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP`** (default 120 per
  `GATEWAY_RATE_LIMIT_WINDOW_SECONDS` window) caps `LookupUsers` per client
  IP. For a service behind one egress address, that is a cap for the whole
  service. It must be a positive integer: zero, negative or malformed fails
  the boot, and a `Config` built in code with the field left zero gets the
  default. A throttled call gets HTTP 429 with `Retry-After: 60`, which
  Connect clients report as `UNAVAILABLE`. The limit is enforced by the HTTP
  handler only; a host serving identity through `RegisterGRPC` must apply its
  own.
- **Audit events**: `directory_lookup` (actor `credential:<id>`, counts only,
  never addresses), `project_credential_created` and
  `project_credential_revoked`. Minting was not audited before. All three are
  written in the credential's project.
- **Dependencies**: `google.golang.org/grpc` v1.83.2 (GO-2026-6443) and
  `golang.org/x/net` v0.58.0.

### Behaviour changes

#### Session revocation mode binds each request to its project

Under `GATEWAY_REVOCATION_MODE=session`, the repository that clears the
session cache on revoke could not be bound to a request's project. Every
request — sign-up, sign-in, profile, admin, SCIM, identity verification — read
and wrote the default project (`GATEWAY_DEFAULT_PROJECT_ID`), whatever project
its `Host` or `X-Project-Key` resolved to. An account created through another
project was stored under the default project, together with its sessions,
refresh tokens and sign-in credentials. v4.8 binds every request to the
project it resolved to, and the session cache reads a session in that project.
Nothing moves the rows already written.

**Am I affected?** Only if both hold on the version you are upgrading from:

1. `GATEWAY_REVOCATION_MODE=session`, and
2. requests resolved to a project other than the default one, by an
   auth-domain `Host` or an `X-Project-Key`.

TTL mode (the default) and single-project deployments are not affected.

**What happens at upgrade.** For each account created through a non-default
project:

1. **Its user is signed out.** Its sessions are stored in the default project.
   The session check now looks in the account's own project, finds nothing and
   refuses the access token.
2. **Signing in on that project finds no account.** Password sign-in fails as
   it does for an unknown address. A method that creates an account on first
   use (OAuth, passwordless email) creates a new one.
3. **Signing up again mints a new `sub`.** Anything downstream keyed on the
   old id no longer matches, and the old account stays in the default project.

**Finding the affected accounts.** The misplaced rows carry the default
project's id, and nothing on them records the project the request was for. On
their own they cannot be told apart from genuine default-project accounts. The
audit trail can tell some of them apart: audit events were always written in
the project the request resolved to, including under session mode. Run this
against the database **before** upgrading, with your default project's id.

`users` and `audit_events` have `FORCE ROW LEVEL SECURITY` keyed on
`app.current_project_id` (migration 0016), so under the application role — which
must not have `BYPASSRLS` (`docs/postgres-rls.md`) — the query silently returns
no rows and reads as an all-clear. Run it as a role with `BYPASSRLS` or as a
superuser. The `SET row_security = off` line makes a role without `BYPASSRLS`
fail with an error instead of returning an empty result:

```sql
SET row_security = off;
SELECT u.id, u.email, a.project_id AS used_through, count(*) AS events
FROM users u
JOIN audit_events a ON a.actor = u.id AND a.project_id <> u.project_id
WHERE u.project_id = '<GATEWAY_DEFAULT_PROJECT_ID>'
GROUP BY u.id, u.email, a.project_id
ORDER BY u.email, a.project_id;
```

Read the result as follows:

- **One `used_through` project, and no events of its own in the default
  project**: the account was created through that project and belongs there.
- **Events in more than one project**: the account was used through several.
  The data does not say which project it belongs to.
- **Accounts with no surviving audit event** — retention
  (`GATEWAY_AUDIT_RETENTION_DAYS`, default 730) removed them, or they were
  never written — do not appear at all. Nothing distinguishes them from
  genuine default-project accounts.

**What to do.**

- If the query (run as described above, without an error) returns no rows,
  no account with a surviving audit trail is
  misplaced; upgrade normally. An account whose events are gone can still be
  misplaced, and its user will find it missing as described above.
- If it returns rows, **hold the upgrade** until you have chosen, for each
  account, one of two paths. identity ships no tool for either.
  - **Let the user sign up again** on their project after the upgrade. This
    creates a new `sub`. Re-key anything downstream on the email address, then
    delete the stale default-project account.
  - **Move the account before upgrading.** With the server stopped, in one
    transaction and as a role with `BYPASSRLS` (under row-level security an
    `UPDATE` of another project's rows changes zero rows without an error),
    set `project_id` to the target project on the account's `users` row and on
    every row that references the account in the other data-plane tables —
    every table migration `0016_enable_rls_data_plane.up.sql` and later
    migrations put under `FORCE ROW LEVEL SECURITY` that carries a user id
    (`SELECT relname FROM pg_class WHERE relforcerowsecurity` lists them).
    Check each `UPDATE`'s row count. The move fails on the per-project unique email index
    where the target project already has an account at that address. Rehearse
    it on a copy of the database first.

  Either way, users of the affected projects must sign in again.

#### SCIM is a live write surface

The inbound SCIM server (`/scim/v2/*`) authenticates with its own bearer
token, but the JWT middleware ran first and refused that token as an invalid
access token. Every SCIM request therefore failed with `401 unauthenticated`
in a served deployment, and the public SAML metadata document
(`/saml/metadata`) was refused the same way. Both are now exempt from JWT
enforcement; SCIM still requires `GATEWAY_SCIM_BEARER_TOKEN` on every request.

**If `GATEWAY_SCIM_ENABLED` is set, SCIM starts working at upgrade.** Any
client holding `GATEWAY_SCIM_BEARER_TOKEN` can then list, create, replace,
patch and delete users in `GATEWAY_SCIM_PROJECT_ID`. This holds even if no
client ever worked against it before. Before upgrading, confirm that the
variable is set only where you intend it, and that only your provisioning
client holds the token.

## v4.6 → v4.7 — the deny layer holds at every door

Follow-up to v4.6.0, from the review of the deny layer. Four behaviour changes,
all corrective; nothing to configure.

**QR login is now gated by the access policy.** `PollQrLogin` mints an
independent session for the scanning device and consulted no access policy, so
a project that tightened its rules kept issuing sessions through QR until every
pre-existing approval expired. The approval only proves the approver was
admitted at approval time, and the session issued at completion outlives it, so
the check runs where the session is actually minted. A user the project now
refuses cannot complete a QR login, including one approved before the change.

**Password-reset mail is suppressed for refused addresses.** It was still sent
to accounts the project would not authenticate — mail the project pays for,
restoring an account that cannot log in, and confirming the address to whoever
received it. The refusal is silent, so the RPC stays enumeration-safe.

**A denied refresh no longer consumes the refresh token.** The access check ran
after the token was consumed, so tightening a policy for an existing population
sent SDK retries into replay detection: every refresh token deleted, sessions
revoked, and `refresh_token_replay_detected` in the audit log for what was a
routine config change. The refusal now happens before the token is spent, so it
is clean and retryable. If you deferred enabling `block_public_email_domains`
because of that, this is the release to do it on.

**Domain entries that could never match are now rejected — check your stored
configs BEFORE upgrading.** A `blocked_domains` or `allowed_domains` value that
canonicalization cannot resolve to a bare domain — a wildcard, a leading or
doubled dot, a scheme or a path — is now refused instead of being stored as a
rule that silently matches nothing. Wildcards are the common case, since
matching is exact-domain.

This is validated on READ, not only on write: the project resolver parses each
project's stored `config_json` on resolution, and a parse failure makes it
refuse that project. **A project whose `access` block already carries such an
entry stops resolving entirely once you upgrade — every request to it fails,
not just its next config write.** Audit your projects' `access.allowed_domains`
and `access.blocked_domains` for entries that are not bare domain names and fix
them before rolling out. The entries were enforcing nothing either way, so
removing them changes no policy that was actually in effect.

## v4.5 → v4.6 — work-email-only projects (additive)

A project's `access` block gains a **deny layer** that subtracts from whatever
`access.mode` admits: `block_public_email_domains` (the "work email only"
switch), `blocked_domains`, and `exempt_emails`. All three are additive and
default off, so a project that sets none of them keeps exactly the access its
mode already granted. The env-configured default project gets the same policy
via `GATEWAY_DEFAULT_PROJECT_BLOCK_PUBLIC_EMAIL_DOMAINS`,
`GATEWAY_DEFAULT_PROJECT_BLOCKED_EMAIL_DOMAINS` and
`GATEWAY_DEFAULT_PROJECT_EXEMPT_EMAILS`.

Two things to know before switching it on:

**It gates login, not just signup.** Turning on `block_public_email_domains`
stops authenticating accounts already registered on consumer domains, not just
new ones. That is deliberate — gating only signup leaves the restriction
permanently half-applied — but it means enabling it on a live project logs
those users out at their next authentication. List anyone who must keep their
existing address in `exempt_emails` **in the same config write**.

**Email change is now gated by the access policy.** This is a fix, not
just a new feature: `RequestEmailChange` and `ConfirmEmailChange` previously
consulted no access policy, so on any restricted project a user could move
their account to an address the project refuses — an `allowlist` project's
member could walk to an unlisted domain. Both now enforce the policy (as a
login, so `invite` projects still permit it), and redemption re-checks because
a change token outlives the request. If you relied on unrestricted email change
on an allowlist or invite project, that door is closed.

**A trailing dot in a configured domain now matches.** `canonicalizeDomain`
strips a trailing FQDN dot, so an existing `allowed_domains` entry written as
`corp.example.` previously matched nothing and now admits everyone at
`corp.example`. That widens an allowlist, so check your `access` blocks for
entries with a trailing dot before upgrading. The same fix is what makes
`blocked_domains` entries reliable.

**The deny layer needs a mode that admits someone.** Setting
`GATEWAY_DEFAULT_PROJECT_BLOCK_PUBLIC_EMAIL_DOMAINS` (or the blocked/exempt
variables) while `GATEWAY_DEFAULT_PROJECT_ACCESS_MODE` is left at its default
`closed` fails the boot: a deny layer subtracts from what the mode admits, and
on a mode that admits nobody it can never fire. Set the access mode to `open`,
`allowlist` or `invite` in the same change.

## v4.4 → v4.5 — guardian listings are paged (additive)

`ListManagedChildren` and `GetGuardians` gain `limit` (default 50, max 200)
and an opaque `cursor`, and their responses gain `next_cursor`. The fields are
additive, but the default is a real change: a client that ignores them gets
the first 50 rather than everything. That is the point — neither listing was
bounded before, and neither was the query behind it.

Walk the pages with `next_cursor` (empty on the last page) if you need the
full set.

The summary-only responses and the omission of aged-out accounts are NOT new
here — both shipped in v4.3.0 with the managed-minor epic. See that release's
notes if you are upgrading across it.

## v4.2 → v4.3 — managed minor accounts (additive)

The managed-minor epic: guardian edges, parent-created child accounts, a
guardian-authorized management surface, per-jurisdiction age thresholds, and
date-of-birth collection on every signup path. Every proto change is additive
and nothing changes with the age gate off, no `jurisdictions` block, and
`GATEWAY_AGEGATE_REQUIRE_DOB` unset. Six migrations apply with
`identity migrate`.

**Both guardian listings return summaries, not full records.**
`ListManagedChildren` and `GetGuardians` carry id, username, display name,
avatar, role, status, market, age band and is_minor. Email, recovery email,
phone number, date of birth and login state are reachable only through
`GetManagedChildProfile`, which requires a step-up re-authentication — the same
bar that already applied to reading one child. `GetGuardians` is trimmed for
the same reason in the other direction: it hands one guardian the records of
their co-guardians. `ListManagedChildren` additionally omits accounts that have
aged past the adult threshold; the edge survives as consent history, but every
management RPC already refuses such an account.

If your client renders a child's email or phone from a listing, switch it to
`GetManagedChildProfile` and collect the step-up password.

### Required-DOB completion step (behavior change if `GATEWAY_AGEGATE_REQUIRE_DOB` is already on)

Extends what `GATEWAY_AGEGATE_REQUIRE_DOB` covers. Previously it bound only
`PasswordSignup`; every other session-issuing path (OAuth, hosted-OAuth
redeem, native mobile OAuth, passwordless code and magic link, passkey
signup and login, TOTP second factor, QR poll, invitation acceptance, token
refresh) created or activated accounts with `date_of_birth_ms = 0` —
adult-classified by default, a complete child-protection bypass. With the
flag on, those paths now refuse token issuance for a dob-less account at
the shared chokepoint and return `FAILED_PRECONDITION` with the stable
`dob_required` message token and a `DOBRequiredDetails` error detail
carrying a 10-minute **completion ticket**. The client submits the date of
birth with the new unauthenticated `SubmitDateOfBirth` RPC; a TEEN/ADULT
result completes the sign-in with tokens, a CHILD-band result lands in
`USER_STATUS_PENDING_PARENTAL_CONSENT` with none.

**Wire additions are additive**: the `SubmitDateOfBirth` RPC, its
request/response messages, and the `DOBRequiredDetails` error-detail
message. Access tokens gain an optional `purpose` claim (absent on every
existing token).

**If you verify identity's JWTs yourself, you must reject purpose tokens.**
A completion ticket is signed with the same key, carries the same `aud`, and
is handed to an *unauthenticated* caller inside an error detail — the only
thing separating it from a session token is the `purpose` claim. Inside
identity the rule is enforced in the shared verifier (`jwt.VerifyAccessToken`
refuses any token with a non-empty `purpose`; the redeeming flow uses
`jwt.VerifyPurposeToken`), so the HTTP middleware, the native-gRPC surface,
and anything else on that path are covered. **Outside** identity — an
embedding host's own gRPC interceptor, an API gateway, or a downstream
resource server validating through the published JWKS — you own the check:
reject any token whose `purpose` claim is set. See `docs/embedding.md`.

**Boot-time invariant.** `GATEWAY_AGEGATE_REQUIRE_DOB=true` now requires
`GATEWAY_AGEGATE_ENABLED=true` and the server refuses to boot otherwise.
Enforcement short-circuits when the gate is off, so the pair used to boot
clean and enforce nothing while claiming the opposite.

**Nothing changes unless you enable the flag.** With
`GATEWAY_AGEGATE_REQUIRE_DOB` unset, every path behaves exactly as before.

Two operator-visible consequences of turning it on:

- **Pre-existing accounts without a DOB hit the completion step at their
  next login or refresh.** `RefreshToken` included — a long-lived session
  stops rotating until the user submits a date of birth. That is the flag
  working; brief client teams on the `dob_required` handling before
  enabling. The refusal is deliberately non-destructive: the presented
  refresh token is NOT consumed, so a client that retries it gets the same
  refusal rather than tripping replay detection (which would sign the user
  out on every device).
- **Anonymous sessions are unaffected** (they never carry a DOB; the
  product `minimum_age_band` gate remains their age guardrail), and
  admin-created accounts (`CreateUser`) simply meet the step at first
  sign-in, since creation mints no tokens.

### Guardian edges (additive)

Adds the guardian edge: the authorization fact that one account
(`guardian_user_id`) manages another (`child_user_id`), stored in a new
project-scoped `guardian_edges` table.

**Wire additions are additive** — two new RPCs: `ListManagedChildren`
(self-only: the guardian is always the session user; the request carries no
user id field) and `GetGuardians` (callable by a guardian of the child or a
project admin, with an account-agnostic `PERMISSION_DENIED` for everyone
else). Two new audit events: `guardian_edge_created` (on consent grant) and
`guardian_edge_removed` (on consent revocation).

**Migrations** (postgres 0031, sqlite 0016), applied with
`identity migrate`, create the `guardian_edges` table and **backfill one edge
per active parental consent whose adult and child both still exist**, with the
consent's grant instant as the edge's creation time. Existing active consents
gain edges automatically; revoked consents and consents referencing a deleted
account are deliberately skipped (the consent record outlives account
deletion; the edge must not).

**Size the migration window.** On PostgreSQL the backfill has to suspend row-
level security on `users` and `parental_consents` (the migrate connection sets
no `app.current_project_id`, so a forced RLS read would silently backfill zero
rows). Those `ALTER TABLE` statements take `ACCESS EXCLUSIVE`, and the pgx
driver runs the migration in one transaction — so reads and writes of `users`
block for the length of the backfill. Migration 0032 then builds the username
unique index non-concurrently, blocking writes again. Both are brief on a
small `users`/`parental_consents` table and worth scheduling on a large one.

One behavior note: `RevokeParentalConsent` now also removes the revoking
adult's guardian edge, and the child is re-gated to
`PENDING_PARENTAL_CONSENT` only when **no active consent remains** for it.
Under the current single-active-consent model that is exactly the previous
behavior; the rule is structured for concurrent multi-guardian consent.

### Parent-creates-child managed accounts (additive)

Adds `CreateManagedChildAccount`: one authenticated call from an adult
creates a working child account, born `USER_STATUS_ACTIVE` under the
caller's guardianship (it never passes through
`USER_STATUS_PENDING_PARENTAL_CONSENT`), with the guardian edge and a
`ConsentRecord` committed in the same transaction. The consent bar is
`GrantParentalConsent`'s, unchanged: a strong verified factor on the adult's
account **and** a step-up password re-entry, with the guardian derived from
the session.

**Wire additions are additive**: the `CreateManagedChildAccount` RPC and its
messages, `User.username` (field 28), and the
`managed_child_account_created` audit event. The child is identified by a
parent-chosen username rather than an email; the credential is either a
parent-set password or a passkey **enrolment ticket** the child's device
redeems through `BeginPasskeyRegistration` / `CompletePasskeyRegistration`
within 15 minutes (those two RPCs now accept an `enrolment_token` for a
session-less child device; presenting both a session and a ticket is
`INVALID_ARGUMENT`).

**Migrations** (postgres 0032, sqlite 0017), applied with `identity migrate`,
add `username TEXT NOT NULL DEFAULT ''` to `users` plus a **partial** unique
index on `(project_id, username) WHERE username <> ''`, so existing
email-identified accounts (all of which have an empty username) are
unaffected.

Two things to know before enabling the flow:

- **The project access mode does not gate it.** This is not self-signup: an
  active adult in the project may create children under `invite` and
  `closed` as well as `open`. A minor caller, an inactive caller, or a date
  of birth that classifies as ADULT is rejected.
- **Username-identified accounts sign in with `PasswordLogin`** using the
  username in place of the email. If your client validates that the login
  identifier looks like an email address, relax it before rolling out child
  accounts.
- **`PasswordLogin`'s response code changed for identifiers with no `@`,
  unconditionally.** Such a value is now a username candidate, so an unknown
  one gets the uniform `UNAUTHENTICATED` invalid-credentials refusal instead
  of the old `INVALID_ARGUMENT` "malformed email" — the same answer an unknown
  email gets, so the endpoint discloses neither which identifier form was
  tried nor whether the account exists. An *empty* identifier is still
  `INVALID_ARGUMENT`, and a malformed address that does contain `@` still
  fails email validation. A client branching on `INVALID_ARGUMENT` to render
  a "not a valid email" hint must move that check client-side.
- **The verified-email gate does not apply to accounts with no email.**
  `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` (default on) is scoped to accounts
  that actually have an address; a managed child has none to verify, so the
  parent-set password works on a stock deployment.
- **A parent needs a password.** Step-up re-authentication is a password
  re-entry, so an adult who signed up through OAuth or passkey-only and has
  no password set cannot create or manage a child account. Inherited from
  the `GrantParentalConsent` bar (#448) and unchanged here; if your product
  onboards parents through social login only, give them a password before
  rolling out managed children.

### Parental account management (additive)

Adds the guardian-authorized management surface over a child account:
`GetManagedChildProfile`, `SetManagedChildPassword`,
`SetManagedChildUsername`, `RevokeManagedChildSessions`,
`DeactivateManagedChildAccount`, `ReactivateManagedChildAccount`, and
`DeleteManagedChildAccount`. Parents can now run their child's account
without the child's credentials and without an admin credential — a
requirement under COPPA, the UK Children's Code, and India's DPDP Rules 2025.

**Wire additions are additive**: seven RPCs and their request/response
messages, plus seven audit events (`guardian_child_profile_viewed`,
`guardian_child_password_set`, `guardian_child_username_changed`,
`guardian_child_sessions_revoked`, `guardian_child_deactivated`,
`guardian_child_reactivated`, `guardian_child_deleted`). No migrations, no
new configuration.

Every one of the RPCs is gated on **both** an active guardian edge from the
session user to the child **and** a `step_up_password` re-entry on the call
itself — holding a valid session is never enough. A caller without an edge
receives an account-agnostic `PERMISSION_DENIED` that does not disclose
whether the child account exists.

Three behaviors worth briefing client teams on:

- **Rights lapse when the child ages out.** A guardian edge to a user who has
  passed the adult threshold that applies to them stops conferring management
  rights (`FAILED_PRECONDITION`, evaluated per call, so it takes effect on the
  birthday). The now-adult account's own sessions are deliberately left
  running. With age-gating off no band can be derived and the edge alone
  authorizes, so gate-off deployments see no change.
- **Revoking consent ends management immediately.** `RevokeParentalConsent`
  deletes the edge, and the next management call from that adult is refused —
  no cached authorization, no grace period.
- **Deletion is immediate and irreversible.** `DeleteManagedChildAccount`
  runs the same hard-delete cascade as the admin `DeleteUser` RPC (not the
  30-day self-service grace window). The `ConsentRecord` and the audit trail
  survive the erasure, per the retention posture consent records already had.

**One response-shape fix ships with this.**
`RevokeParentalConsentResponse.child_status` previously always reported
`USER_STATUS_PENDING_PARENTAL_CONSENT`. It now reports the status the child
account was actually left in — which differs only when another guardian's
consent remains active, in which case the child correctly stays
`USER_STATUS_ACTIVE`.

### Per-jurisdiction age thresholds (additive)

Adds per-market age thresholds: a project's `config_json` gains a
`jurisdictions` block (`default` + `thresholds`, each entry a
`child_max_age`/`adult_age` pair), and accounts gain a **market** that
selects which pair their age band derives from (resolution: stored market →
project default → strictest configured ceiling → the env
`GATEWAY_AGEGATE_*` pair).

**Nothing changes unless you configure it.** A project with no
`jurisdictions` block classifies exactly as before. The wire additions are
additive (`User.market` field 27, `ConsentRecord.market` field 12,
`PasswordSignupRequest.market` field 6, and the new authenticated
self-service `SetAccountMarket` RPC, audited as `account_market_changed`),
and `buf breaking` stays clean against the previous release.

**Migrations** (postgres 0030, sqlite 0015), applied with
`identity migrate`, add `market TEXT NOT NULL DEFAULT ''` to both `users`
and `parental_consents`. Both are metadata-only on PostgreSQL (constant
default, no table rewrite); existing rows read as "no market on file" and
keep their current classification.

One behavior note: when a project DOES configure `jurisdictions`,
`SetAccountMarket` (and signup with a `market`) rejects a code the project
has not declared, and an account whose new market moves it into the child
band without active parental consent is re-gated to
`PENDING_PARENTAL_CONSENT` with its sessions revoked immediately.

## v4.1 → v4.2 — product-agnostic defaults (one behavior change)

v4.2 removes every consumer-specific value that had accreted in the repo:
product names, project slugs, domains, and operator addresses are deploy-time
`GATEWAY_*` config, never server literals.

**One behavior change.** The default for `GATEWAY_DEFAULT_PRODUCT` — the
product slug attributed to a request with no `X-Product` header — changes
from a consumer-specific slug to `"default"`. If you never set the variable,
your untagged (legacy-header) clients were previously stamped with that old
slug; after upgrade they are stamped `"default"`, which matches no entry in
your project's `products` policy. Because an absent slug imposes no age
restriction, **legacy clients would silently stop receiving age-gate
enforcement**.

**Action required before rollout** if you rely on the default (i.e. you have
never set `GATEWAY_DEFAULT_PRODUCT`): set it explicitly to your primary app's
slug — the same slug your `config_json` `products` block keys on. If you
already set the variable, nothing changes.

## v4.0 → v4.1 — anonymous identity (additive)

v4.1 adds anonymous sign-in: credential-less accounts with a stable id that
can later gain a credential without changing it (see
[ADR-0013](./adr/0013-anonymous-identity.md) and the
[docs-site page](../docs-site/src/pages/docs/auth/anonymous.astro)).

**Nothing changes unless you turn it on.** The feature defaults off, the
new RPCs return `UNIMPLEMENTED` until a project enables it, the wire
additions are additive (`User.is_anonymous` field 26; two new RPCs), and
the `anonymous` JWT claim is emitted only for anonymous accounts, so
tokens for identified users are byte-identical to v4.0.

**Migrations** (postgres 0028, sqlite 0013), applied with
`identity migrate`, add `users.is_anonymous` and **rebuild the per-project
email unique index as a partial index** over non-empty addresses — every
anonymous account carries an empty email, so a total index would make the
second one a duplicate-key error. Uniqueness still binds, case-insensitively,
for every user that has an address.

> On a large `users` table the index builds take a SHARE lock (blocks
> writes, allows reads) for their duration, and **two** of the three new
> indexes build over every existing row: the partial email unique index and
> `users_project_created_id_nonanon_idx` (its `WHERE NOT is_anonymous`
> predicate is true for all pre-existing rows). Their predicate columns do
> not exist pre-migration, so neither can be pre-built directly — instead,
> pre-add the columns (metadata-only on PostgreSQL 11+, matching the
> migration's own DDL so its `IF NOT EXISTS` clauses no-op), then pre-build
> both heavy indexes concurrently, outside a transaction:
>
> ```sql
> ALTER TABLE users ADD COLUMN IF NOT EXISTS is_anonymous BOOLEAN NOT NULL DEFAULT FALSE;
> ALTER TABLE users ADD COLUMN IF NOT EXISTS anonymous_last_seen_ms BIGINT NOT NULL DEFAULT 0;
> CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_project_email_partial_uidx
>     ON users (project_id, lower(email)) WHERE email <> '';
> CREATE INDEX CONCURRENTLY IF NOT EXISTS users_project_created_id_nonanon_idx
>     ON users (project_id, created_at_ms, id) WHERE NOT is_anonymous;
> ```
>
> The third index — the sweep's `users_project_anonymous_last_seen_idx` —
> needs no pre-build: its `WHERE is_anonymous` predicate is false for every
> pre-existing row, so it builds empty in constant time.

**To enable it**, per deployment (default project) or per project in
`config_json`:

| Variable | Default | Notes |
| --- | --- | --- |
| `GATEWAY_ANONYMOUS_ENABLED` | `false` | turns on `SignInAnonymously`. **Turning it back off is destructive — see the warning below.** |
| `GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE` | `false` | gates it on the assurance layer; **boot fails** if set while `GATEWAY_ASSURANCE_ENABLED=false` |
| `GATEWAY_ANONYMOUS_RETENTION_DAYS` | `30`, raised automatically to exceed `GATEWAY_REFRESH_EXPIRY_SECONDS` when left unset (logged once at boot as `anonymous_retention_raised`) | days of inactivity before reaping; an **explicitly set** window that does not exceed the refresh lifetime **fails boot**; `0` disables the sweep. Deployment-wide, and the sweep reaches the **boot-default project only** — see below |

Two things to know before enabling:

1. **Sign-in is independent of `access.mode`; upgrading is not.** A project
   running `mode: closed` still hands out anonymous sessions — but
   `UpgradeAnonymousAccount` is enforced with signup semantics and returns
   `PERMISSION_DENIED` under `closed` (the default),
   `invite`, or an off-list `allowlist`. Setting only the
   `GATEWAY_ANONYMOUS_*` variables therefore gives you working sign-in and an
   upgrade path that always fails; open the project for the upgrade half to
   work. Control anonymous traffic with assurance and rate limits, not the
   access mode.
2. **The password upgrade returns no session by default.** With
   `GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL` on (the default),
   `UpgradeAnonymousAccount`'s password arm promotes the account, sends a
   verification email, revokes the anonymous session, and returns **empty**
   `accessToken`/`refreshToken` — `OK`, not an error. Clients must branch on
   an empty token rather than discarding their pair expecting replacements.
   The OAuth arm returns a new pair, because the provider verified the
   address.
3. **Age-gated (COPPA) deployments: the password upgrade is refused.** With
   `GATEWAY_AGEGATE_ENABLED=true` and `GATEWAY_AGEGATE_REQUIRE_DOB=true`,
   `UpgradeAnonymousAccount`'s password arm returns `INVALID_ARGUMENT` —
   the request cannot carry a date of birth, and admitting it would mint an
   account that skips the parental-consent flow `PasswordSignup` enforces.
   Anonymous sessions also **fail closed at product age gates**: a product
   with a `minimum_age_band` refuses them (their age is unknowable), while
   products with no minimum stay open to them. On the refresh path that
   refusal is evaluated **before** the presented refresh token is consumed,
   so a product that gains a minimum mid-session refuses future rotations
   without burning the account's only credential — removing the minimum
   restores the sessions. Collecting a DOB on the
   upgrade is a planned addition (ADR-0013 "Not shipped").
4. **Downstream services must check the `anonymous` claim** before granting
   anything that assumes a verified human. An anonymous `sub` is cheap to
   mint, and `email` is empty rather than absent-because-unverified, so code
   that only tests "is there a sub?" will treat a farmed account as a user.

> **⚠️ Disabling anonymous sign-in destroys existing anonymous accounts.**
>
> `GATEWAY_ANONYMOUS_ENABLED=false` is not a pause. The moment it flips:
>
> 1. `RefreshToken` returns `PERMISSION_DENIED` for every existing anonymous
>    user. A refresh token is that account's **only** credential, so those
>    sessions are immediately unrecoverable.
> 2. Their activity clock stops, because it only advances on a successful
>    refresh — so every one of them goes idle *by construction*.
> 3. The retention sweep runs **independently of the enable flag** (it is
>    gated only on `GATEWAY_ANONYMOUS_RETENTION_DAYS`), so one retention
>    window later — 30 days at defaults — it hard-deletes them and every
>    cascaded row.
>
> The users who lose data are precisely the active ones. Before turning the
> feature off, do one of:
>
> - set `GATEWAY_ANONYMOUS_RETENTION_DAYS=0` first, which disables the sweep
>   and leaves the rows in place (they stay unreachable, but recoverable if
>   you re-enable); or
> - drive users through `UpgradeAnonymousAccount` while the feature is still
>   on, so they hold a real credential before the switch flips.

**The retention sweep covers the boot-default project only.** A
control-plane deployment that enables anonymous sign-in on other projects
must reap those rows itself; otherwise they accumulate indefinitely from an
unauthenticated endpoint.

**Rollback** (`0028.down` / `0013.down`) **deletes anonymous users.** They
cannot be represented in the pre-0028 schema and hold no credential to sign
back in with, so the deletion is the honest outcome rather than a
half-applied rollback.

**Identity verification is hardened alongside this feature, whether or not
anonymous sign-in is enabled.** `BeginIdentityVerification` now refuses
anonymous callers (`FAILED_PRECONDITION` — every admitted call opens a paid
provider session against an account the retention sweep can still delete)
and carries a per-IP quota, `GATEWAY_RATE_LIMIT_IDV_PER_IP` (default `5`
per rate-limit window). Deployments that legitimately begin more than five
verifications per IP per window — e.g. behind a shared corporate NAT —
should raise it.

## v3.x → v4.0 — CAPTCHA becomes the client-assurance layer (breaking)

v4.0 replaces the inline-CAPTCHA design with the client-assurance layer
(App Attest / Play Integrity / Turnstile / reCAPTCHA behind one short-lived
assurance token — see
[ADR-0012](./adr/0012-client-assurance-layer.md) and the
[docs-site page](../docs-site/src/pages/docs/auth/assurance.astro)).
The new surface defaults off, so a deployment that never enabled CAPTCHA
gains no behaviour — **but read the environment section below before
pulling the image.** Every removed `GATEWAY_CAPTCHA_*` variable must be
DELETED from your environment, not merely set to `false`: the server
refuses to boot while any of them is *present*, whatever its value.

That check is deliberate. The rename would otherwise fail OPEN — a v3
operator who set `GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN=true` and pulled
v4 would boot clean with zero enforcement on six auth endpoints and no
signal. Failing closed is the only safe direction, but it means a
forgotten `GATEWAY_CAPTCHA_ENABLED=false` left in a compose file, a Helm
values template, or an ECS task definition will crash-loop the v4 image.
The error names every offending variable and its replacement.

**Wire (clients):** the `captcha_token` request field is removed from
`PasswordSignup`, `PasswordLogin`, `RequestPasswordReset`,
`RequestEmailLoginCode`, `RequestMagicLink`, and `BeginPasskeySignup`
(field numbers reserved). A web client now exchanges its captcha solution
first — `IssueAssuranceToken {platform:"web", webToken:…}` — and attaches
the returned token as the `X-Assurance-Token` header on the gated call.
The storage migrations (postgres 0027, sqlite 0012) are ordinary additive
migrations applied with `identity migrate`.

**Environment:** rename / replace. **Unset the left-hand column** — the
server refuses to boot while any of these is present, even set to `false`
or the empty string:

| v3.x — must be UNSET | v4.0 |
| --- | --- |
| `GATEWAY_CAPTCHA_ENABLED` | `GATEWAY_ASSURANCE_ENABLED` |
| `GATEWAY_CAPTCHA_PROVIDER` | `GATEWAY_ASSURANCE_WEB_PROVIDER` |
| `GATEWAY_CAPTCHA_TURNSTILE_SECRET` / `_SITE_KEY` | `GATEWAY_ASSURANCE_TURNSTILE_SECRET` / `_SITE_KEY` |
| `GATEWAY_CAPTCHA_RECAPTCHA_SECRET` / `_SCORE_THRESHOLD` | `GATEWAY_ASSURANCE_RECAPTCHA_SECRET` / `_SCORE_THRESHOLD` |
| `GATEWAY_CAPTCHA_ENFORCE_*` (6 toggles) | `GATEWAY_ASSURANCE_ENFORCE_*` (same six, same defaults) |

New (all optional): `GATEWAY_ASSURANCE_IOS_TEAM_ID` / `_IOS_BUNDLE_ID` /
`_IOS_ENV`, `GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME` /
`_ANDROID_CERT_SHA256_DIGESTS` / `_ANDROID_SA_KEY_JSON`,
`GATEWAY_ASSURANCE_TOKEN_TTL_SECONDS`,
`GATEWAY_ASSURANCE_CHALLENGE_TTL_SECONDS`,
`GATEWAY_ASSURANCE_DEVICE_RETENTION_DAYS` (default 90 — how long an
attested device survives after its last refresh; 0 keeps them forever),
`GATEWAY_ASSURANCE_WEB_TOKEN_TTL_SECONDS` (default 300 — the web arm's
own, shorter token lifetime), `GATEWAY_RATE_LIMIT_ASSURANCE_PER_IP`;
plus `GATEWAY_ASSURANCE_ALLOW_PROJECT_ONLY` — optional in general, but
**required** when you enable assurance with no env-level arm (every app
identity in per-project `config_json`), since the server otherwise
refuses to boot; per-project app identities go
in `config_json` `assurance`, authored with the operator RPC
`AdminSetProjectAssurance` (it takes the Play service-account key in
plaintext and encrypts it server-side under `GATEWAY_PROJECT_SECRETS_KEY`,
mirroring `AdminSetProjectOAuthProvider`), and read back with
`AdminGetProjectAssurance` — the only way to confirm an encrypted key
survived a rotation.

**Native gRPC embedders:** the three assurance RPCs are bridged onto
`RegisterGRPC` alongside the existing ones, so a host that enables any
`GATEWAY_ASSURANCE_ENFORCE_*` toggle can still obtain a token from the
same surface (the v3 CAPTCHA solution used to ride inside the request
message; it is now the `X-Assurance-Token` metadata key).

**Embedders:** `Options.CaptchaVerifier` is now
`Options.AssuranceWebVerifier`; the handler constructor no longer takes a
verifier (it is wired into the auth service). The public `pkg/captcha`
package is gone — it moved to `pkg/assurance` with a shape-identical
`Verifier` interface, so a custom verifier only needs its import swapped.

**Token verifiers:** `pkg/jwt.VerifyAccessToken` now rejects a token with
no `sub` claim. Every access token this server has ever minted carries
one, so this affects only callers that hand it non-access tokens; it is
what keeps an assurance token (deliberately subject-less) from ever
authenticating as a user.

---

## TL;DR

Upgrading from any **pre-v1.0** release to **v1.0** is a **breaking schema
reset**. All pre-v1.0 releases are deprecated. There is no in-place data
migration in this release.

- **Greenfield / no data you must keep:** do a **fresh install** of v1.0
  against an empty database. This is the supported and recommended path.
- **You ran a pre-v1.0 build with data you must keep:** there is **no
  first-party automated data migration**. No production deployment ran the
  legacy model, so no backfill is built or maintained. If you genuinely have
  pre-v1.0 data with rows, you must migrate it manually against a backup or
  copy; you are on your own.

Within the v1.x line, upgrades are ordinary additive migrations applied with
`identity migrate`; this guide is specifically about the pre-v1.0 → v1.0 jump.

## Why it is a reset

v1.0 is the Project / Tenant / Domain redesign. It inverts the storage
cardinality of the datastore, so the leading key of every data-plane table
changes. See [ADR-0002 — Project is the isolation shard](./adr/0002-project-is-the-isolation-shard.md)
for the decision, and [`docs/IDENTITY.md`](./IDENTITY.md) plus the other ADRs
under [`docs/adr/`](./adr/) for the full model.

### What changed in the model

| Pre-v1.0 | v1.0 |
|---|---|
| `tenant_id` is the physical shard **and** the leading key of every data-plane table. | **`project_id`** is the leading key. The **Project** is the isolation shard; it references a control-plane `projects` row. |
| `mode = single \| multi` boot flag forks the deployment; in `multi` each org-shard is its own `tenant_id`. | **`mode` removed.** One code path resolves the **Project** per request (from an `X-Project-Key` credential or the `Host` header), then the **Tenant** from the user's email domain. |
| **Organization** / **OrganizationMembership** model `OrganizationSignup`. | **Organizations removed.** Multitenancy is modelled by **Projects** (the shard) containing **Tenants** auto-formed from verified email domains. |
| A tenant string is both the company and the shard (1:1, same string). | Three distinct concepts: **storage scope** (physical shard), **Project** (control-plane isolation entity, 1 per storage scope), **Tenant** (data-plane company, many per Project). |

### What changed in config

The `mode` knob and its companions are gone. Remove these env vars if you set
them:

- `GATEWAY_IDENTITY_MODE`
- `GATEWAY_TENANT_HOST_BASE_DOMAIN`
- `GATEWAY_TENANT_RESOLUTION_SOURCES`

v1.0 adds the control-plane default project. In a clean install these default
to distinct values — the project **id** (`GATEWAY_DEFAULT_PROJECT_ID`, default
`default`) is intentionally **not** equal to the storage scope
(`GATEWAY_DEFAULT_TENANT_ID`, default `local`), per ADR-0002:

- `GATEWAY_DEFAULT_PROJECT_ID` — id of the default control-plane Project.
- `GATEWAY_DEFAULT_TENANT_ID` — the physical storage scope (shard) the default
  Project maps onto.

### New required config: `GATEWAY_PROJECT_SECRETS_KEY` (postgres)

Per-project OAuth providers (each Project configures its own Google/Microsoft/
Apple/OIDC providers, Firebase-style) store provider secrets **encrypted at
rest**. The encryption key is supplied via `GATEWAY_PROJECT_SECRETS_KEY`, a
**base64-encoded 32-byte** key.

**This is a breaking change for postgres deployments:** when
`GATEWAY_REPO_DRIVER=postgres` (the default), boot now **fails fast** unless
`GATEWAY_PROJECT_SECRETS_KEY` is set. Generate one and set it **before**
upgrading:

```sh
openssl rand -base64 32
```

Drivers without a control plane (`sqlite`, `memory`) pin every request to the
default project and draw OAuth providers from the `GATEWAY_OAUTH_*` env vars, so
they do **not** require the key. Rotating or losing the key invalidates every
per-project provider secret already stored (they must be re-encrypted).

### Removed: `GATEWAY_NATIVE_OAUTH_*_AUDIENCES_BY_PRODUCT`

Native mobile sign-in accepted-audience configuration is now **per-project**,
carried in a project's `config_json` under
`oauth.<provider>.native_audiences` (an array of accepted `aud` values). This
replaces the per-product stopgap env vars shipped the prior week:

- `GATEWAY_NATIVE_OAUTH_GOOGLE_AUDIENCES_BY_PRODUCT` — **removed**
- `GATEWAY_NATIVE_OAUTH_APPLE_AUDIENCES_BY_PRODUCT` — **removed**

**Migrate:** move each `product=aud1 aud2` entry to the corresponding project's
`config_json` (`oauth.google.native_audiences` / `oauth.apple.native_audiences`
/ the new `oauth.microsoft.native_audiences`). The plain
`GATEWAY_NATIVE_OAUTH_{GOOGLE,APPLE,MICROSOFT}_AUDIENCES` env vars are **kept**
as the **default project's** seed (a non-default project never inherits them),
and `GATEWAY_NATIVE_OAUTH_PRODUCT_PROJECTS` (product → project resolution) is
**kept**. This release also adds **native Microsoft** login (mirrors the hosted
verifier: issuer derived from the token's `tid`, `email → preferred_username →
upn` coalescing, and a **verbatim** nonce — unlike Apple's hashed nonce). It is
breaking, but the `*_BY_PRODUCT` vars shipped only the prior week.

> **⚠️ Do not silently disable native login.** `GATEWAY_NATIVE_OAUTH_ENABLED`
> auto-defaults to `true` only when at least one of the **plain**
> `GATEWAY_NATIVE_OAUTH_{GOOGLE,APPLE,MICROSOFT}_AUDIENCES` env vars is set — it
> no longer considers the removed `*_BY_PRODUCT` vars. If you migrate by moving
> audiences into `config_json` **and** clearing the plain env vars, the flag
> auto-defaults to **`false`** and `NativeOAuthLogin` returns
> `FailedPrecondition`. Such deployments **must set
> `GATEWAY_NATIVE_OAUTH_ENABLED=true` explicitly.**

> **🔒 Security — Microsoft nOAuth hardening (behavior change, hosted + native).**
> Microsoft sign-in defaults to **multi-tenant**: the expected issuer is derived
> from the token's own `tid`, so **any** Azure AD tenant — including an
> attacker-controlled one — can mint a valid token bearing an arbitrary `email`.
> Combined with email-based account federation this is an
> [nOAuth](https://www.descope.com/blog/post/noauth)-class account-takeover
> vector: an attacker presents a token carrying a **victim's email** and takes
> over the victim's account.
>
> This release **closes the vector by default** — hosted (`pkg/oauth/microsoft.go`)
> and native (`pkg/oauth/native.go`) alike. A Microsoft email is now trusted as
> verified (the precondition for federation) **only** when **one** of:
>
> - the issuing tenant is **pinned** — a single-tenant `tenant_id`
>   (`GATEWAY_MICROSOFT_TENANT_ID` for the default project, or
>   `oauth.microsoft.tenant_id` per project), OR the token's `tid` matches a new
>   **tenant allow-list** (`GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS`,
>   comma-separated, for the default project; `oauth.microsoft.allowed_tenants`
>   per project); OR
> - the token carries **`xms_edov == true`** (Microsoft's email-domain-owner-verified
>   claim, accepted as a JSON bool or the string `"true"`).
>
> A non-standard `verified_email == true` is **not** trusted on its own (an
> attacker tenant can set it as easily as the email), though an explicit
> `verified_email == false` is still rejected. Otherwise the email is treated as
> unverified and the login is **rejected** with `ErrEmailNotVerified` (surfaced as
> `Unauthenticated`) — matching the existing Google/Apple unverified-email
> handling, so **no** silent merge into an existing account is possible. Pinning a
> tenant also now **enforces** `tid` equality during verification (previously
> `tenant_id` only chose the authorize endpoint), so a single-tenant deployment
> rejects other tenants' tokens.
>
> **Tenant identifiers must be directory GUIDs.** Azure always stamps the token's
> `tid` as a directory (tenant) GUID, and the runtime pin compares against it
> (case-insensitively), so a value that can never equal a `tid` is **rejected by
> config validation** rather than silently failing every login. Where that
> rejection surfaces depends on where the value lives:
>
> - **env** (`GATEWAY_MICROSOFT_TENANT_ID` / `GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS`)
>   — fails fast at **boot** (`Config.Validate`);
> - **per-project `config_json`** (`oauth.microsoft.*`) — rejected at **admin
>   write time** for new values, but a value **already stored** from before this
>   release is validated on the **per-request project-resolution path**, so it
>   fails at request time and (until re-pinned) takes down that project's whole
>   resolution — not just Microsoft. There is no boot scan, so audit stored
>   configs before upgrading. The fields:
>
> - `allowed_tenants` (env `GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS` /
>   `oauth.microsoft.allowed_tenants`) — every entry must be a **GUID**;
> - `tenant_id` (env `GATEWAY_MICROSOFT_TENANT_ID` / `oauth.microsoft.tenant_id`) —
>   a **GUID**, a **meta** value (`common`/`organizations`/`consumers`, meaning "no
>   pin — multi-tenant"), or empty.
>
> When both `tenant_id` and `allowed_tenants` are set they form a **union**: a
> `tid` is accepted if it equals `tenant_id` OR is a member of `allowed_tenants`.
> A verified-domain string (e.g. `contoso.onmicrosoft.com`) is invalid in either.
> (Note the pre-existing env-var prefix divergence: `GATEWAY_MICROSOFT_TENANT_ID`
> vs `GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS`; the former is kept as-is to avoid a
> breaking rename.)
>
> **`xms_edov` is opt-in on the Azure side.** Azure does not emit it by default —
> add it as an optional ID-token claim on the app registration (Token
> configuration → optional claim → `xms_edov`) if you want to rely on it instead
> of pinning a tenant.
>
> **Action required:**
> - _Multi-tenant deployments that relied on blindly-trusted email_ — pin your
>   tenant(s) via `tenant_id` / `allowed_tenants` (GUIDs), or enable `xms_edov`,
>   or those logins are now rejected.
> - _Single-tenant deployments pinned by a **verified domain**_ — this is a
>   **breaking change**: re-pin `tenant_id` (or `GATEWAY_MICROSOFT_TENANT_ID`) to
>   your directory **GUID** before upgrading. An env domain-form value fails fast
>   at boot; a domain-form value **already stored** in a project's `config_json`
>   fails at request-time project resolution (no boot signal) and disables that
>   whole project until corrected — so audit and re-pin stored per-project
>   Microsoft configs first. Previously a domain-form pin silently rejected every
>   Microsoft login at runtime.

### Schema migrations involved

The model change lands across three Postgres migrations
(`internal/repo/postgres/migrations/`):

- **0013** — additive: creates the control-plane tables (`projects`,
  `project_credentials`, `project_auth_domains`, `platform_admins`) and the new
  data-plane governance tables (`tenants`, `domains`, `login_policies`,
  `tenant_memberships`, `tenant_invitations`).
- **0014** — drops the legacy `organizations` / `organization_members` tables.
- **0015** — renames each kept data-plane table's leading `tenant_id` column to
  `project_id`, re-scopes its indexes, and adds a `FOREIGN KEY` to
  `projects(id)`.

v1.0 then adds one more migration:

- **0016** — enables Postgres row-level security on the data-plane tables as
  defense-in-depth, scoped to `project_id` (`0016_enable_rls_data_plane`).

## Recommended path: fresh install

For a greenfield deployment, or any deployment without legacy data you must
keep:

1. Point v1.0 at an **empty** database.
2. Apply the schema:

   ```sh
   identity migrate          # applies all pending migrations (0001..0016)
   ```

   (Or run `migrate ... up` against `internal/repo/postgres/migrations` from
   your deploy pipeline; the binary does not auto-migrate on boot by default.)
3. Set v1.0 config (drop the removed `mode` vars; the default project id and
   storage scope default to `default` / `local`).
4. Start the service.
5. **Before opening the service to public traffic, bootstrap the first platform
   admin.** `CreateFirstPlatformAdmin` is a one-time, trust-on-first-use RPC
   that stays open only while `platform_admins` is empty, so a fresh,
   internet-exposed deployment has a window in which an anonymous caller could
   win the first-admin race. Create the first admin over a private network
   first, and/or set `GATEWAY_ADMIN_API_SECRET` (which then also gates the
   bootstrap on the `X-Admin-Secret` header) or
   `GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP=true` (to close the RPC entirely — the
   first admin is then created by a direct `platform_admins` insert, or by
   toggling the flag off just long enough to bootstrap and back on; no
   first-party seed CLI or migration ships for this).

SQLite backends are likewise a fresh start — the SQLite schema is the v1.0
Project-keyed shape; there is no legacy data to carry forward.

## Legacy Postgres data

There is **no first-party automated data migration** from the pre-v1.0 model to
v1.0. No production deployment ran the legacy model, so no backfill is built,
shipped, or maintained.

If you genuinely have a pre-v1.0 Postgres database with rows you must keep,
migrating it is your responsibility. Work against a backup or a copy, never the
live database. The migration is not trivial: migration 0015 renames each
data-plane table's leading `tenant_id` column to `project_id` **in place** and
attaches a `project_id → projects(id)` foreign key, so before 0015 runs you
must have created a control-plane `projects` row for **every** distinct legacy
`tenant_id` present in **any** of the ~30 FK'd data-plane tables — otherwise
0015's foreign key aborts the migration. There is no supported script for this,
and you are on your own.
