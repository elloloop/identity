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
ID and 32 cryptographically random bytes in its protected credential store,
outside every agent workspace. The wire credential is canonical unpadded
base64url. Only SHA-256 of the canonical 43-character base64url credential string is
registered and stored by Identity. The
caller retains the credential; the issuer never returns or recovers it. An
identical registration retry returns the original/current record; changed input
with the same ID conflicts. Source SID and time are audit provenance and may
change between identical authenticated retries. Revoked registrations stay
revoked. A lost response never justifies silently registering a new ID.

The machine credential authenticates unattended exchange and paginated listing
of selected active owned agent accounts. It is not a human session or an agent
access token. Exchange creates one durable child delegation per machine/agent
and returns the existing distinct, short-lived `at+jwt` profile: agent `sub`,
responsible owner `act.sub`, project, one resource, exact scopes, client,
delegation and session. There is no rotating refresh family. Repeating exchange
is safe after a lost response; the parent credential does not change. The
orchestrator alone holds it and passes only the relevant agent's short-lived
access token into that agent's service boundary. It must not appear in coding
prompts, agent files, URLs, logs or source control.

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

Owner management RPCs list, select and revoke machines without exposing hashes
or credentials. Selection is revision-fenced and requires recent human sign-in.
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
Real HTTP tests exercise registration, unattributed credential exchange,
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
