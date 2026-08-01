# ADR-0013 — Anonymous identity (credential-less accounts, upgradeable in place)

## Status

Accepted (2026-08-01).

Phase 2 of the program ADR-0012 opened. ADR-0012 shipped the assurance layer
and scoped anonymous identity explicitly out, to be designed on its own "with
assurance available to gate its creation". This is that design.

Depends on ADR-0002 (Project is the isolation shard). Extends the per-project
`config_json` surface (ADR-0010 pattern) with an `anonymous` block.

## Context

The customer request behind ADR-0012 wanted one thing that the assurance layer
deliberately does not provide: a **subject**. Assurance answers *"is this a
genuine app on genuine hardware?"* and carries no `sub` by construction. It
cannot be the thing a rate limiter, a saved-items list, or a purchase is keyed
on, because it identifies a client, not an account.

Firebase answers that with **Anonymous Authentication**: `signInAnonymously()`
creates a real user with a stable UID, no credential, and `isAnonymous: true`;
`linkWithCredential()` later attaches a real credential **preserving the UID**.
The two features compose — App Check gates *who may call*, anonymous auth
decides *who they are* — which is exactly the split ADR-0012 adopted.

The alternative we rejected is the one the customer originally asked for: mint
an identity-shaped token from a device attestation. ADR-0012 gives the reason —
every RPC behind a Bearer treats a valid access token as a human. Anonymous
identity solves the same problem correctly, by creating an account that really
exists and is really that thin.

## Decision

### An anonymous user is a user row, not a parallel table

`users.is_anonymous`, no email, no password hash, no provider identity, no
passkey. It can own data, be referenced by foreign keys, and carry a role,
because downstream services should not need a second code path for it.

The consequence that forced a schema change: **the per-project email unique
index had to become PARTIAL** (`WHERE email <> ''`). Anonymous users all carry
`''`, so the total index made the *second* anonymous sign-in a duplicate-key
error. The predicate mirrors `users_project_external_id_uidx` (migration 0021):
the constraint holds exactly where the value is meaningful. Uniqueness still
binds, case-insensitively, for every user that has an address.

### Availability is its own switch, INDEPENDENT of the access mode

`anonymous.enabled` per project (`GATEWAY_ANONYMOUS_ENABLED` for the default
project), default OFF.

It is deliberately orthogonal to `access.mode`. The access mode governs which
**email-identified humans** may sign up, log in, and accept invitations; an
anonymous session is a different question. A project running `mode: closed` —
admitting no new identified users at all — may still hand out anonymous
sessions. This is Firebase-exact: anonymous auth is its own provider toggle
and does not even fire the blocking functions that gate identified sign-ups.

This is not a loophole in default-DENY, because the switch is itself
default-OFF and orthogonal in both directions: a wide-open `mode: open` project
does not get anonymous sign-in either.

The orthogonality has a non-obvious second half. The refresh path re-enforces
the access mode on every rotation, so that a de-allowlisted user stops minting
tokens rather than coasting on a live refresh token. An anonymous user has no
email, so running them through that guard judges them as the *empty address* —
denied under every mode except `open`. Anonymous sessions would then die at
their first refresh on any allowlist/invite/closed project, and since a refresh
token is the account's only credential, unrecoverably. Anonymous users are
therefore exempted from that guard and re-checked against the anonymous switch
instead, which keeps the switch a real kill switch rather than a creation gate.

### Abuse is controlled by assurance, not by the access mode

`SignInAnonymously` is unauthenticated by nature — there is nothing to
authenticate — which makes it the cheapest account-creation surface the server
has. `GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE` puts the ADR-0012 layer in front of
it, so a caller must prove it is a genuine app on genuine hardware (or a
human-passed web client) before it may mint an account. There is also a per-IP
quota on the signup budget. Boot fails if assurance is demanded while the
assurance layer is off, rather than denying 100% of sign-ins with no way to
obtain a token.

### Upgrade preserves the id

`UpgradeAnonymousAccount` attaches a credential to the **calling** account and
clears `is_anonymous`, keeping the id. The account comes from the access token
and there is no `user_id` field, so one account can never upgrade another.

Two credentials ship: email+password, and OAuth (the server performs the code
exchange itself, reusing `LinkIdentity` whole). The token pair is reissued,
because the caller's existing access token still asserts `anonymous: true` and
every downstream service would keep believing it until it expired.

Firebase's `credential-already-in-use` is matched, and like Firebase we **do
not merge** the two accounts: merging silently destroys one account's data, and
choosing which one survives is the application's decision, not the server's.
A second upgrade is refused (`FAILED_PRECONDITION`) — it would silently rebind
an identified account to a different credential.

### Retention is its own window and its own sweep step

`GATEWAY_ANONYMOUS_RETENTION_DAYS`, default 30 (matching Firebase's anonymous
auto-cleanup), measured from last activity, per-project overridable.

It is deliberately **not** the shared expiry cutoff the other sweeps use. That
cutoff is `now - grace` (default 60s) applied to a row's own `expires_at_ms`,
and a user row has no expiry; sharing it would delete every anonymous account
about a minute after its last refresh. This is not hypothetical — the attested
device sweep shipped with exactly that bug during ADR-0012 and had to be
corrected.

Refresh stamps the activity clock. An anonymous account has no login event, so
refresh is its only recurring sign of life; without the stamp the timestamp
never advances and every anonymous user is deleted exactly one retention window
after creation however actively it is being used. Boot fails if the window does
not exceed the refresh-token lifetime, since reaping a user whose refresh token
is still live destroys a session the client still holds.

### The token carries an `anonymous` claim

Emitted only when true, so tokens for identified users are byte-identical to
before. Downstream services **must** read it before granting anything that
assumes a verified human: an anonymous `sub` is cheap to mint, and `email` is
empty rather than absent-because-unverified.

## Consequences

- **A refresh token is the whole account.** There is no credential to recover
  with; losing the token loses the account, by design. Clients must persist it
  as durably as they would a session. This is the same contract Firebase's
  anonymous auth has, and the reason retention is measured from activity
  rather than creation.
- **Anonymous accounts are cheap by construction**, which is the point and the
  risk. A deployment that enables them without `REQUIRE_ASSURANCE` or a
  meaningful per-IP quota has an unbounded row-insert primitive. The defaults
  (feature off; quota on when it is turned on) fail safe, but an operator can
  still configure this badly.
- **Attestation still does not prove a human** (ADR-0012). Anonymous identity
  plus assurance raises the cost of farming accounts; it does not eliminate it.
- **The partial email index is a schema change to a hot table.** The rebuild
  takes a brief SHARE lock (blocks writes, allows reads). A deployment with a
  large `users` table should pre-build the replacement with
  `CREATE INDEX CONCURRENTLY` and let the `IF NOT EXISTS` clauses no-op.
- **The down migration deletes anonymous users.** They cannot be represented in
  the pre-0028 schema — they share the empty email the restored total index
  forbids more than one of — and they hold no credential to sign back in with,
  so the deletion is the honest outcome rather than a half-applied rollback.
- **Not shipped:** anonymous-to-anonymous merge, passkey and phone as upgrade
  credentials, and a per-project cap on live anonymous accounts. Each is
  additive; none changes the shape above.
