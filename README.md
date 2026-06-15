# Identity

Authentication and user-management service. Deploys as a single container; pulls a pinned image, points at a datastore (Postgres or EntDB), exposes Connect-RPC over HTTP/JSON.

Treat this like [tenant-shard-db](https://github.com/elloloop/tenant-shard-db): one image, deployed once per product, fully isolated user pools.

> ## v1.0 breaking changes
>
> v1.0 is the Project/Tenant/Domain redesign. Upgrading from a pre-v1.0
> deployment is a **breaking schema reset — there is no in-place data
> migration in this release** (a legacy-data migration script and Postgres
> row-level-security hardening are tracked v1.1 follow-ups). What changed:
>
> - **`OrganizationSignup` removed**, along with the `Organization` /
>   `OrganizationMembership` tables. Multitenancy is now modelled by
>   **Projects** (the isolation shard) with **Tenants** auto-formed from
>   verified email domains inside a project.
> - **`mode=single | multi` removed**, together with its env vars
>   (`GATEWAY_IDENTITY_MODE`, `GATEWAY_TENANT_HOST_BASE_DOMAIN`,
>   `GATEWAY_TENANT_RESOLUTION_SOURCES`). One code path now resolves the
>   project per request (from an `X-Project-Key` credential or the `Host`
>   header), then the tenant from the user's email domain.
> - **Data-plane storage re-keyed `tenant_id` → `project_id`** (ADR-0002).
> - **`TenantAdmin` / `RepositoryForTenant` embedding options removed**;
>   embedders inject `Repo`+`DB` and the per-project repository is resolved
>   internally.
>
> See [`docs/IDENTITY.md`](./docs/IDENTITY.md) and the ADRs under
> [`docs/adr/`](./docs/adr/) for the model in full.

## What it provides

- **Email + password** signup, login, change, reset, lockout
- **Passkeys (WebAuthn)** registration and login
- **TOTP (2FA)** setup, verify, recovery codes
- **QR cross-device login**
- **OAuth login** (Google, Microsoft — server consumes pre-verified ID tokens from frontend SDKs)
- **Sessions** with revoke and sign-out-everywhere
- **JWT issuance** with key rotation, plus `/.well-known/jwks.json` for downstream services
- **User and Group CRUD**, group membership data
- **Audit log** of auth events
- **Email and phone verification** flows

Identity authenticates users, issues JWTs, and assigns coarse roles
(`admin` / `member` / `guest`). It stores groups and memberships, but it
does not enforce per-group or per-resource ACLs. Calling applications are
responsible for authorization decisions built on that data.

## Storage

Identity persists to Postgres (the recommended backend, which carries the Project/Tenant/Domain control plane) or to [EntDB](https://github.com/elloloop/tenant-shard-db). For EntDB, identity targets the **v2.x line** of the server image and Go SDK — the entdb backend uses ADR-031 self-describing writes, attaching identity's schema (every `(entdb.node)`/`(entdb.edge)` message in `proto/identity/schema/schema.proto`) on the first `ExecuteAtomic` per tenant. The server enforces field types, single- and composite-unique constraints, and required-fields against that schema atomically.

The service reserves type IDs `1–99` in the EntDB schema. Source of truth is `proto/identity/schema/schema.proto`; current allocations:

| type_id | Node | Notes |
|---|---|---|
| 1 | User | `email` is unique |
| 2 | WorkingGroup | identity's group |
| 5 | RefreshToken | `token_hash` is unique |
| 19 | PasswordResetToken | `token_hash` is unique |
| 20 | PasskeyCredential | `credential_id` is unique |
| 21 | PasskeyChallenge | one-time per ceremony |
| 22 | QrLoginSession | `session_id` is unique |
| 23 | TotpCredential | per-user TOTP secret |
| 24 | RecoveryCode | `code_hash` is unique |
| 25 | LoginChallenge | `challenge_id` is unique |
| 26 | AuditEvent | append-only |
| 27 | UserInvitation | `token_hash`, `email` unique |
| 28 | AdminHelpRequest | |
| 29 | EmailVerificationToken | `token_hash` is unique |
| 30 | EmailChangeToken | `token_hash` is unique |
| 31 | OAuthIdentity | `(provider, provider_user_id)` is **composite unique** |
| 32 | IdentityVerification | `verification_id` is unique |
| 35 | Session | `sid` is unique |
| 36 | OAuthOneTimeCode | hosted-OAuth handover; `code_hash` unique |
| 37 | EmailLoginCode | passwordless OTP; `email` unique |
| 38 | MagicLinkToken | passwordless magic link; `token_hash` unique |
| 39 | PhoneVerificationCode | SMS OTP; per-user |

Type IDs `33` and `34` (formerly `Organization` / `OrganizationMembership`)
are retired and unallocated — organizations were dropped in v1.0. Project,
Tenant, Domain, and membership state live in the Postgres control plane and
per-project data plane, not in the EntDB type registry above.

Other services consuming the same EntDB instance must use type IDs `100+` to avoid collisions.

## Configuration

All config is via environment variables. See `internal/config/config.go` for the full list. Most-tweaked:

| Var | Purpose |
|---|---|
| `GATEWAY_ENTDB_ADDRESS` | EntDB endpoint (e.g. `entdb:50051`) |
| `GATEWAY_DEFAULT_TENANT_ID` | Storage scope ID (the physical shard) the default project maps onto |
| `GATEWAY_DEFAULT_PROJECT_ID` | ID of the control-plane Project seeded on boot and used to pin zero-config requests (default `default`) |
| `GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS` | Comma-separated serving hostnames seeded (verified) onto the default project; the first is primary. Lets the `Host` header resolve to the default project |
| `GATEWAY_ADMIN_API_SECRET` | Shared secret authenticating the control-plane admin RPCs (`AdminCreateProject`, …). Empty (default) disables them |
| `GATEWAY_PUBLIC_EMAIL_DOMAINS` | Extra consumer/public email domains never auto-formed into a tenant (adds to the built-in gmail/outlook/… set) |
| `GATEWAY_JWT_SIGNER` | JWT signer backend: `file` (default) or `kms_aws` |
| `GATEWAY_JWT_KEYS_FILE` | Path to the file-backed signer's keys file (see [docs/key-rotation.md](./docs/key-rotation.md)) |
| `GATEWAY_JWT_KMS_KEYS` | AWS KMS signer: CSV of `kid=arn` entries |
| `GATEWAY_PASSKEY_RP_ID` | Passkey relying party ID — must match your domain |
| `GATEWAY_PASSKEY_ORIGIN` | Allowed origin for passkey ceremonies |
| `GATEWAY_TOTP_ISSUER` | Name shown in user authenticator apps |
| `GATEWAY_DEFAULT_EMAIL_DOMAIN` | Default email domain for new accounts |
| `GATEWAY_ALLOWED_ORIGINS` | CORS origins |
| `GATEWAY_AUTH_ALLOW_LOCAL` | Set `false` in prod to disable username/password if you only want OAuth |

## Deployment

Pull the image and run alongside an EntDB v2.x instance:

```bash
# 1. Run EntDB v2.x first
docker run -d --name entdb -p 50051:50051 \
  ghcr.io/elloloop/tenant-shard-db:2.5.0

# 2. Run identity pointing at it
docker run -p 80:80 -p 9090:9090 \
  -e GATEWAY_ENTDB_ADDRESS=entdb:50051 \
  -e GATEWAY_DEFAULT_TENANT_ID=my-product \
  -e GATEWAY_PASSKEY_RP_ID=my-product.com \
  -e GATEWAY_PASSKEY_ORIGIN=https://my-product.com \
  -e GATEWAY_TOTP_ISSUER="My Product" \
  ghcr.io/elloloop/identity:0.1.0
```

Or use `docker-compose.yml` at the repo root — it wires both services together with persistent volumes and a `wait-for-entdb` healthcheck.

### Postgres backend (alternative)

Postgres is the recommended datastore for the Project/Tenant/Domain
control plane (it is the only driver with a control plane; the entdb and
memory drivers pin every request to the default project). Select it with
`GATEWAY_REPO_DRIVER=postgres`:

```bash
docker run -p 80:80 -p 9090:9090 \
  -e GATEWAY_REPO_DRIVER=postgres \
  -e GATEWAY_POSTGRES_DSN='postgres://identity:password@db:5432/identity?sslmode=disable' \
  -e GATEWAY_DEFAULT_TENANT_ID=my-product \
  ghcr.io/elloloop/identity:0.1.0
```

The conformance suite asserts both backends behave identically across every Repository method — same uniqueness/ordering/error-translation semantics. Postgres is the recommended backend for the Project/Tenant/Domain control plane; the entdb and memory drivers run the per-project data plane pinned to the default project (no control-plane project registry).

## Releasing

Push a `v*` tag — `.github/workflows/release.yml` builds and pushes a multi-arch image to `ghcr.io/elloloop/identity:<version>`.

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Local development

```bash
go build ./...
go test ./...
```
