# ADR-0017: Owner-managed durable agent machine access

## Status

Accepted; disabled by default. This is an issuer capability, not a claim that
any particular application's engine, machine policy or permissions are enabled.

## Context

A supervised native agent must continue after its owner's browser session ends.
The consent-bound browser flow in ADR-0016 intentionally cannot provide that:
its grants expire with the source human session. Persisting its refresh token
would preserve the wrong authority boundary and response-loss rotation hazards.

## Decision

Add an explicit, independently disabled `GATEWAY_AGENT_MACHINE_ENABLED` feature,
requiring the existing delegated issuer. A native client must additionally opt
into `agent_machine` in its reviewed registry grant types. This is a typed RPC
capability; it is not an additional `/oauth/token` grant or OAuth discovery claim.
Existing authorization-code clients keep their bounded session semantics.

A recently signed-in owning human registers one machine connection against exact
registered resource/product/scope bounds. Omitted selection means all current
and future owned agents; an explicit selection can choose none, a subset, or
all with exclusions. Application activation, team membership, IAM, repository
permissions and execution leases remain separate, narrower requirements. A
machine connection grants no repository or application role by itself.

Before registration the native application atomically persists a fresh request
ID and a locally generated Ed25519 engine key pair outside every agent workspace.
The signed-in owner registers only its public key, encoded as 64 lowercase hex
characters. Identity never receives a private key. Identical registration retries
recover the original/current record; changed input with the same ID conflicts.
Source SID and time are audit provenance and may change between authenticated
retries. Revoked registrations stay revoked. A lost response never justifies
silently registering a new machine ID or replacing its key.

The engine key authenticates orchestration only: paginated discovery of selected
active owned agents, public-key enrollment for those agents, and resource-bound
machine introspection. Each agent on each machine has a separate locally generated
Ed25519 pair. `RegisterAgentMachineAgentKey` creates one durable delegation binding
the agent's public key; exact repeats recover that delegation, changed keys
conflict, and a revoked child is never replaced automatically. Keys cannot be
shared between agents on a machine or with its engine key.

`CreateAgentMachineChallenge` returns the exact UTF-8 message to sign. It includes
a versioned domain, configured issuer, project, machine, agent, operation, request
binding, random nonce and expiry. A challenge lasts 60 seconds, binds enrollment
to its public key and roster proofs to their offset, and is consumed atomically
only after valid signature verification. All three stores persist at most 128
pending challenges per machine, reclaim expired entries and enforce project
isolation. Consumption survives issuer restart and permits one winner across
replicas. Invalid signatures do not consume a valid challenge. HTTP and native
gRPC share request limits and rate budgets.

Only the registered agent key can authenticate `ExchangeAgentMachineCredential`.
It returns the existing separately attributed short-lived `at+jwt` profile: agent
`sub`, responsible owner `act.sub`, project, one resource, exact scopes, client,
delegation and session. The engine key cannot exchange for an agent token. There
is no rotating refresh family. After response loss the caller requests a fresh
challenge and recovers the same delegation; it never replays a consumed proof or
changes a key. All private keys stay outside coding sessions, prompts, task files,
URLs, logs and source control. Only the relevant agent's short-lived access token
enters its service boundary. This is a typed application authentication protocol,
not a claim of OAuth client-assertion or DPoP wire compatibility.

The source human signing out, expiring or having refresh data cleaned up does
not revoke this new kind. Machine and child grants have no scheduled expiry.
Resources still introspect every access token, checking current owner/agent
status, ownership, client revision, machine selection, revocation and product
policy. Ownership loss, account security changes, agent deactivation, client
changes, guardian loss and project/governance changes terminally invalidate
relevant authority. Restoring old state never revives it. Policy unavailability
fails closed. Existing browser grants continue to revoke on human signout.

A resource authenticates with its dedicated project/resource verification
credential before calling `IntrospectAgentMachine` on every machine-control
request. Active results contain only that resource's machine metadata and owner
binding. This lets an application enforce machine policy and resolve the
reporting roster without a human bearer. Inactive proofs and unavailable
verification both refuse control access; resources must not cache admission.

Owner management RPCs list, select and revoke machines without exposing private material. Selection is revision-fenced and requires recent human sign-in.
Removing an already connected agent revokes that child permanently. Returning
to default-all cannot recreate it. Explicit replacement uses a newly authorized
machine connection; it never changes a terminal grant back to active. Machine
revocation cascades to every child. A native client must respect returned revoked
state and stop rather than silently replacing the connection.

All three drivers share validation and transitions. Registration, exchange,
selection and revocation lock current authority before machine/child rows. Child
identity is unique per machine/agent even under concurrent exchange. Durable
records are excluded from ordinary expired-browser-grant cleanup; retaining
revocation tombstones prevents cleanup from becoming an authorization reset.

## Verification

Service tests cover authority separation, selection CAS, input bounds and
refusal of browser-code/refresh operations on durable children. Shared memory,
SQLite and PostgreSQL conformance covers concurrency, registration recovery,
restart, project isolation, human logout, terminal invalidation and retention.
Real HTTP tests exercise registration, engine-versus-agent key separation,
concurrent challenge replay, future agent enrollment after human signout,
agent-versus-human JWT separation, introspection after human logout, management
ownership, selection/revocation, safe retries, feature opt-in and transport size
bounds. Native gRPC forwards the same handlers and retains its existing verified
metadata trust options; enabling a bridge does not trust caller-supplied identity.

## Consequences

Application engines must implement secure local persistence, machine-policy
admission, default-all reconciliation, agent isolation and current application
permissions before enabling this in production. A version check is not execution
proof. Existing expiring machine approvals are not automatically converted to
permanent authority by enabling an issuer feature. Operators must explicitly
migrate their application policy and verify real reads, writes and revocation.
