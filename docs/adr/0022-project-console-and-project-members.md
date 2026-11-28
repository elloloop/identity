# ADR-0022 — Project console and project members

## Status

Accepted (2026-11-28). Off by default: a server turns the console on with
`GATEWAY_CONSOLE_ENABLED` (postgres only), and lets console accounts create
projects with `GATEWAY_CONSOLE_SELF_SERVICE_PROJECTS_ENABLED`.

It amends ADR-0002: a Project is still created by the operator, and may now
also be created by a signed-in console account where the server allows it.
The operator's admin-secret RPCs are unchanged.

## Context

A Project is the isolation shard (ADR-0002) and carries everything that
decides how its users authenticate: its access mode, whether it has tenants,
individual accounts or both, its child-account and age rules, its browser
origins. Until now all of it was authored one way: the operator, holding the
deployment's single admin secret, calls `AdminCreateProject` and
`UpsertProjectConfig`.

That fits one team running one product. It does not fit a deployment that
serves several products or customers, where the person who owns a project is
not the person who operates the server. Giving that person the admin secret
gives them every project. There was also no page to do any of it from: the
config was a JSON blob written by hand.

`platform_admins` (migration 0013) and `CreateFirstPlatformAdmin` hold
operator accounts, but nothing signs them in, and an operator account is the
wrong thing to hand a project's owner for the same reason the secret is.

## Decision

A project has **members**, and a member manages it through a **console** the
server serves, with their own account and no admin secret.

- **Console accounts are accounts of the default project.** The console does
  not get a second sign-in system: a console account signs in with `Login`
  and everything behind it (lockout, two-step, passkeys, recovery, sessions,
  revocation) as any account of the deployment's own project does. Who may
  have one is that project's access policy. A request must resolve to the
  default project for the console RPCs to accept its token, which is also
  what keeps an account of some other project, whose ids the default project
  knows nothing of, from being read as a console account.
- **Membership is a control-plane row.** `project_members (project_id,
  user_id, role)`, role `owner` or `admin`, is the only thing that authorizes
  a console call on a project. A project the caller is not a member of is
  refused exactly as one that does not exist.
- **Who may be a member.** The rule for owning a tenant (`judgeTenantOwner`):
  an active, permanent person with a verified email. A project's settings
  decide who can sign in to it, so an agent, an anonymous account, an
  unverified one, or an account a tenant manages has no business holding
  them.
- **Creating a project.** `CreateProject` creates the project, its creator's
  owner membership and one publishable credential in one transaction, so a
  project never exists without an owner or without the key an application
  selects it by. It is its own storage scope. An account owns at most
  `GATEWAY_CONSOLE_MAX_PROJECTS_PER_ACCOUNT` projects (10 by default),
  counted and spent under one lock. It is a second switch because a project
  is a shard: opening creation to everyone who can sign up to the default
  project is the operator's decision, not a consequence of having a console.
- **A new project admits nobody.** It is created with an empty config, and an
  unset access mode denies all authentication (`ProjectAccessConfig`). The
  owner chooses a mode before anyone can sign up. No default is picked for
  them.
- **Members edit an allow-listed part of the config.**
  `GetProjectSettings` and `UpdateProjectSettings` read and write only the
  sections in `memberEditableSettings`: `access`, `age_gate`, `anonymous`,
  `cors`, `guardian`, `jurisdictions`, `login`, `recovery_emails`, `tenants`,
  and in `accounts` the fields `email_signup` and `username_signup`. It is an
  allow list, so a config section added later is closed to members until
  someone decides it is theirs. What stays the operator's, and why:
  - `oauth`: provider secrets, and the hub-sharing switch that lends a
    project the deployment's own OAuth clients (ADR-0011).
  - `accounts.domain`: it makes the server issue, and mail, addresses on a
    domain nobody has proven the project controls.
  - `branding`, `email_delivery`, `phone`: what the deployment's mail and
    message senders put their name to.
  - `passkey`, `assurance`, `products`: app and relying-party identities an
    operator vouches for.
- **Keys are matched exactly.** `encoding/json` reads keys without regard to
  case, so `"OAuth"` and `accounts."Domain"` are refused, not folded onto the
  name the parser would read them as, and a write removes every other
  spelling of the section or field it sets.
- **A member is shown the parsed config, not the stored text.** For the same
  reason, a stored `"Access"`, or an `"access"."Mode"`, governs sign-in as
  surely as the canonical spelling. `GetProjectSettings` therefore reads
  through `ParseProjectConfig` and returns the editable sections under their
  canonical names, so what a member sees is exactly what is in force,
  whatever an operator's blob looks like. A field at its default is absent.
  A write that would merge into `accounts` when the stored config spells
  that section more than one way is refused (`ErrProjectConfigAmbiguous`):
  the parser reads the operator's fields from every spelling, in an order
  the merge cannot reproduce.
- **Creation is budgeted per address as well as per account.**
  `CreateProject` spends a per-IP budget the size of the sign-up budget
  (`GATEWAY_RATE_LIMIT_SIGNUP_PER_IP`), as `CreateTenant` does: the
  per-account limit bounds what one account owns, and this bounds one
  address making accounts to get around it.
- **One rule for a valid config.** A member's merged config passes the checks
  an operator's `UpsertProjectConfig` does (`validateProjectConfigJSON`,
  `checkNewHostKeys`) before it is stored.
- **A write names the version it read.** `UpdateProjectSettings` is one
  compare-and-swap on `expected_version` and answers ABORTED when the config
  has moved. The operator path's retry loop is not used: it would re-apply a
  member's sections over a config they have not seen.
- **Changes are fenced like an admin's.** `CreateProject` and
  `UpdateProjectSettings` outlast the session that made them, so a session a
  recovery hold binds is refused (`refuseHeldSession`), as it is for
  `AdminService`'s changes.
- **Audit.** `project_created` (a refusal for the limit included) and
  `project_settings_updated`, with the console account as actor and the
  names of the sections changed, never their values. They land under the
  default project, where the actor lives.
- **The page.** `/console/` is one embedded document with a per-request CSP
  nonce and no external assets, served only on a request that resolved to
  the default project. It keeps tokens in memory only.

## Consequences

- A deployment that turns the console on makes its default project's
  accounts candidates for project membership. The default project's access
  mode therefore also decides who can reach the console; with self-service
  projects on and that mode `open`, anyone can create a project.
- Deleting a console account deletes its memberships (the foreign key
  cascades). A project whose only owner is deleted has no member: it keeps
  running, and the operator manages it with the admin secret. Nothing yet
  lets an operator appoint a new owner; see Later.
- Rolling back past schema 71 drops the memberships and leaves the projects
  the console created, reachable by the operator only.
- A member cannot read the operator's sections at all, so the console shows
  an incomplete picture of a project an operator has also configured.
- The console reads and writes a section as this server's parser knows it.
  A key the parser does not know is not shown and is not kept when a member
  saves that section, so during a rollout that adds a field to an editable
  section, a member saving it through a replica on the old version drops
  the new field.
- `platform_admins` stays what it was: a bootstrap record with no sign-in.
  This ADR does not build its login; an operator who wants a page uses a
  console account with the projects they are a member of.

## Later

- Adding and removing members (`admin`), transferring ownership, and an
  operator call that appoints an owner for a project that has lost its own.
- Member-facing forms for what has dedicated operator RPCs today: OAuth
  providers, auth domains, further credentials, tenants.
- Renaming, suspending and deleting a project from the console.
