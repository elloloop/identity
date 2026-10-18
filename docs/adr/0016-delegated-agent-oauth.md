# ADR-0016: Consent-bound native delegated agent access

## Status

Accepted; disabled by default pending an operator's complete local integration check.

## Context

An owned non-human account cannot sign in. A native application needs a bounded
way to act as that agent while the responsible human remains identifiable and
able to withdraw access. A client registration alone grants no authority.

## Decision

Use the pinned `github.com/zitadel/oidc/v3` v3.51.6 protocol engine with its
supported `op.Server` adapter. It parses standard OAuth endpoints; this server
implements only authorization code with S256, refresh rotation, introspection
and refresh-token revocation. Its legacy ID-token-producing server is not used.
Protocol requests are bounded to 64 KiB before project resolution parses a
form. Compact access JWTs are bounded to 32 KiB, sufficient for the maximum
registered resource/scope bounds and a 2048-byte issuer. `openid` requests are
explicitly refused even if a registry record contains that scope.
The dependency supplies a maintained typed protocol implementation rather than
a homegrown OAuth wire layer. Its provider library name does not enable OIDC:
there are no ID tokens, userinfo, implicit grants or `openid` scope.

A registered native public client requests one exact resource and a subset of
its recorded scopes, with a product policy binding. An active permanent human
with a live durable session and a sign-in within five minutes reviews those
bounds and explicitly selects an owned active agent. The hosted consent page
uses ordinary sign-in, including configured TOTP and CAPTCHA. It never accepts
a bearer in the URL. A decision is compare-and-swap and terminal. The redirect
returns the original state plus issuer and a single-use code valid for one
minute. Only its digest is persisted. S256 redemption binds the exact client,
redirect, resource and verifier. A wrong proof does not consume the code.

The distinct `at+jwt` RS256 profile identifies the agent in `sub`, its human
owner in `act.sub`, one audience, project, client, immutable grant, delegated
session, scopes, issue/expiry and token ID. Human and purpose-token verifiers
reject this profile. File, AWS KMS and test signers implement it explicitly.
No private human role or email is copied. Access JWTs last five minutes by
default, at most fifteen. Consent defaults to one day, at most thirty, and is
also capped by the original human session's global and tenant policy bounds.
A grant does not refresh its source human session or extend its idle policy.
Legacy ordinary human JWTs remain accepted on ordinary endpoints; only this
new consent flow requires an explicit normal reauthentication when SID is absent.

Resources authenticate using a dedicated project/resource credential and call
introspection on every request, including after local signature validation.
Introspection fails closed on unavailable authority, and checks current agent
ownership/status, permanent human status, durable human SID, client revision,
project and registered product access/age policy. Credentials are configured as
SHA-256 digests; the resource retains the original high-entropy secret. A public
native client ID is never an introspection credential, and no directory key is
implicitly reused. There is no generic token mint endpoint.

Memory, PostgreSQL and SQLite use the same pure aggregate transition. SQL locks
and transactions make consent, code consumption and refresh rotation atomic;
read-only PostgreSQL admission uses shared locks. Replay of a consumed refresh
credential commits terminal grant revocation even while returning invalid_grant.
Credential/identity changes, human signout, guardian loss, agent transfer or
reactivation, client revision and project changes cannot revive an old grant.
On the PostgreSQL governance plane, sensitive tenant/domain/login-policy changes
conservatively require fresh consent across that project, including policy
restoration. Absent policy remains distinct from a failed policy lookup; the
latter refuses delegated access. Ordinary human login retains its documented
project-default behavior on governance lookup failure.
Database triggers fence security state even if a later session-cache invalidation
fails. Observed external product-policy refusal terminally revokes the grant.
Retention deletes expired aggregate and refresh data in bounded sweeper batches.

## Durable unattended machines

ADR-0017 defines a separately enabled owner-managed machine capability using
short-lived tokens with durable, revocable machine authority. It does not change
this browser flow's human-session bounds or its refresh rotation semantics.

## Consequences

Operators must enable session revocation, choose an HTTPS issuer origin without
a path, query, fragment or trailing slash, configure resource credentials,
register exact native bounds and finish the real example journey before enabling
this feature. A resource must distinguish an inactive
token from an unavailable introspection server; neither permits a request.
Resources can still impose narrower application permissions than consent.
Any client revision, including a name edit, requires fresh consent. There is
no transparent restoration after ownership or authority loss.

PostgreSQL migration 0041 and SQLite migration 0024 add grants and hashed refresh
families. Rollback destroys delegated access state; export audit evidence first.
Custom signers implement `jwt.DelegatedSigner` only to enable this profile;
ordinary signer implementations and ordinary human sign-in remain unchanged.

## References

- [OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [Native applications and loopback redirects](https://www.rfc-editor.org/rfc/rfc8252.html)
- [Resource indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [JWT access token profile](https://www.rfc-editor.org/rfc/rfc9068.html)
- [Authenticated token introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [Authorization server metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [Issuer identification](https://www.rfc-editor.org/rfc/rfc9207.html)
