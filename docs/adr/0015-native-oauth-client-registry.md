# ADR-0015: Explicit native public OAuth client registrations

## Decision

Provide a project-scoped native public-client registry as the first complete
management capability of the authorization-server design. It is separate from
upstream social-login providers and from delegated grants. Public client IDs are
random identifiers, never credentials. No secret is created or accepted.

An active, permanent human administrator in the request's project can create,
read, list and replace a registration. Authorization rereads the stored user;
request bodies and token role claims cannot select an administrator. Each client
records a display name, exact redirects, per-resource scope bounds, permitted
`authorization_code` and optional `refresh_token`, and a disabled flag.

HTTPS redirects match exactly. HTTP redirects are limited to literal 127.0.0.1
or [::1], with only the port allowed to change under RFC 8252. The host, encoded
path and query remain exact. Private-use schemes and localhost DNS redirects
are not supported by this slice. Resources are explicit absolute HTTPS URIs or
URNs without fragments. Scope tokens follow RFC 6749 syntax and are bounds,
not application permissions. There is no wildcard or resource inference.

All drivers enforce the same bounded writes, pagination, copy isolation and
compare-and-swap update. IDs, kind and creation time are immutable. Every update
increments the revision, including disable and re-enable. PostgreSQL adds RLS
as defense in depth; all queries carry the project predicate. Deleting a project
removes its registrations. There is no client-delete API: disabled records retain
identity for future audit and delegation references.

## Relationship to delegation

A registration permits an OAuth request to be considered; it does not approve
one. Future grants must persist their separately approved resource/scope/subject
binding and client revision. Issuance and introspection must reject disabled or
revision-mismatched clients, so widening a registration cannot expand existing
consent and re-enabling cannot resurrect old grants. A fresh consent is required
following any registration revision. This conservative rule also applies to a
name-only edit.

## Not implemented here

Authorization endpoints, S256 challenge handling, authenticated consent, codes,
refresh families, delegated access-token profiles, introspection, revocation,
confidential clients and dynamic registration remain separate protocol work.
Registration RPCs do not advertise, activate or substitute for any of those flows.
The intended protocol engine remains the reviewed library in issue #543. Agent
subject binding follows #594; full token exchange is not a prerequisite.

## References

- https://www.rfc-editor.org/rfc/rfc8252#section-7.3
- https://www.rfc-editor.org/rfc/rfc8707#section-2
- https://www.rfc-editor.org/rfc/rfc6749#section-3.3
