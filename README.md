# Identity

Authentication and user-management service. Deploys as a single container; pulls a pinned image, points at a Postgres datastore, exposes Connect-RPC over HTTP/JSON.

Treat this like [tenant-shard-db](https://github.com/elloloop/tenant-shard-db): one image, deployed once per product, fully isolated user pools.

> ## v1.0 breaking changes
>
> v1.0 is the Project/Tenant/Domain redesign. Upgrading from a pre-v1.0
> deployment is a **breaking schema reset — there is no in-place data
> migration in this release**; a fresh install is the supported path. See
> [`docs/UPGRADE.md`](./docs/UPGRADE.md) for the full upgrade guide. Postgres
> row-level-security defense-in-depth ships in v1.0 (migration
> `0016_enable_rls_data_plane`). What changed:
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
- **OAuth login** (Google, Microsoft, GitHub, Apple — server-owned authorization-code exchange)
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

Identity persists to **Postgres** — the primary datastore, which carries
the Project/Tenant/Domain control plane. An in-memory driver
(`GATEWAY_REPO_DRIVER=memory`) is available for local development and tests.
Both drivers implement the same graph-shaped repository contract and are
held to one [conformance suite](internal/repo/conformance) (identical
uniqueness/ordering/error-translation semantics across every method).

The service models its data as a small set of graph node types, addressed
by stable numeric `type_id`. The relational drivers map these onto tables;
the service layer treats node IDs as opaque strings. Current allocations:

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
Tenant, Domain, and membership state live in dedicated Postgres tables in
the control plane and per-project data plane, not in the node-type registry
above.

## Configuration

All config is via environment variables. See `internal/config/config.go` for the full list. Most-tweaked:

| Var | Purpose |
|---|---|
| `GATEWAY_REPO_DRIVER` | Persistence backend: `postgres` (default), `sqlite`, or `memory` (local dev / tests) |
| `GATEWAY_POSTGRES_DSN` | Postgres connection string (required for the `postgres` driver) |
| `GATEWAY_SQLITE_PATH` | SQLite database file path (when `GATEWAY_REPO_DRIVER=sqlite`). Required — set it to `:memory:` explicitly for an ephemeral in-process database; there is no implicit default. File-backed databases open in WAL mode (`synchronous=NORMAL`) so concurrent reads don't serialize behind writes |
| `GATEWAY_SQLITE_MAX_CONNS` | Connection-pool size for a file-backed SQLite database (default `4`). Ignored for `:memory:`, which is pinned to a single connection |
| `GATEWAY_DEFAULT_TENANT_ID` | Storage scope ID (the physical shard) the default project maps onto |
| `GATEWAY_DEFAULT_PROJECT_ID` | ID of the control-plane Project seeded on boot and used to pin zero-config requests (default `default`) |
| `GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS` | Comma-separated serving hostnames seeded (verified) onto the default project; the first is primary. Lets the `Host` header resolve to the default project |
| `GATEWAY_REQUIRE_VERIFIED_AUTH_DOMAIN` | When `true` (default), a project's primary auth-domain (which drives branded link URLs / cookie domains) must be DNS-verified — an unverified `is_primary` custom host is ignored. Set `false` to let an unverified primary host drive branded links |
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

Pull the image and run it alongside a Postgres instance. Postgres carries
the Project/Tenant/Domain control plane; the `memory` driver pins every
request to the default project (no control-plane project registry), so it
suits local dev and tests rather than production.

```bash
# 1. Run Postgres first
docker run -d --name identity-db -p 5432:5432 \
  -e POSTGRES_USER=identity -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=identity \
  postgres:16.13-alpine3.23

# 2. Run identity pointing at it (apply migrations once, then serve)
docker run -p 80:80 -p 9090:9090 \
  -e GATEWAY_REPO_DRIVER=postgres \
  -e GATEWAY_POSTGRES_DSN='postgres://identity:password@identity-db:5432/identity?sslmode=disable' \
  -e GATEWAY_POSTGRES_AUTO_MIGRATE=true \
  -e GATEWAY_DEFAULT_TENANT_ID=my-product \
  -e GATEWAY_PROJECT_SECRETS_KEY="$(openssl rand -base64 32)" \
  -e GATEWAY_PASSKEY_RP_ID=my-product.com \
  -e GATEWAY_PASSKEY_ORIGIN=https://my-product.com \
  -e GATEWAY_TOTP_ISSUER="My Product" \
  ghcr.io/elloloop/identity:1.5.0
```

> **Upgrade note (breaking):** the postgres backend now **requires**
> `GATEWAY_PROJECT_SECRETS_KEY` (a base64-encoded 32-byte key, e.g.
> `openssl rand -base64 32`). It encrypts per-project OAuth provider secrets at
> rest; boot fails fast without it. Set it before upgrading an existing postgres
> deployment. Drivers without a control plane (`sqlite`, `memory`) do not need it.

In production, run migrations out-of-band as a separate step
(`identity migrate`) rather than relying on `GATEWAY_POSTGRES_AUTO_MIGRATE`
on a rolling deploy. Or use `docker-compose.yml` at the repo root — it
wires identity to Postgres with a persistent volume and a health-gated
`depends_on`.

### SQLite backend (lightweight / embedded)

For embedded, single-node, and development deployments, identity ships a
**pure-Go SQLite** driver ([modernc.org/sqlite](https://modernc.org/sqlite),
no cgo — cross-compiles cleanly). It runs the per-project data plane in a
single file (or fully in-process) with no external service. Like the
memory driver it is single-project (pinned to the default project — the
Project/Tenant/Domain control plane is Postgres-only); unlike it the SQLite
driver persists to durable SQL. Select it with `GATEWAY_REPO_DRIVER=sqlite`:

```bash
docker run -p 80:80 -p 9090:9090 \
  -e GATEWAY_REPO_DRIVER=sqlite \
  -e GATEWAY_SQLITE_PATH=/data/identity.db \
  -e GATEWAY_DEFAULT_TENANT_ID=my-product \
  -v identity-data:/data \
  ghcr.io/elloloop/identity:1.5.0
```

Set `GATEWAY_SQLITE_PATH=:memory:` for an ephemeral in-process database
(tests / throwaway dev). The SQLite driver passes the same conformance
suite as Postgres and memory — identical uniqueness, ordering, and
`ErrNotFound`/`ErrAlreadyExists`/`ErrInvalidArgument` semantics. There is no
Row-Level Security on SQLite (that stays Postgres-only defense-in-depth); the
mandatory `WHERE project_id = $1` repo boundary is the backend-agnostic
isolation.

Backend tiers at a glance:

| Driver | `GATEWAY_REPO_DRIVER` | Use case | Control plane |
| --- | --- | --- | --- |
| Postgres | `postgres` | Production, multi-node | Yes (Project/Tenant/Domain) |
| SQLite | `sqlite` | Single-file embedded, single-node, dev | No (single-project) |
| memory | `memory` | Tests, smoke | No (single-project) |

## Releasing

Push a `v*` tag — `.github/workflows/release.yml` builds and pushes a multi-arch image to `ghcr.io/elloloop/identity:<version>`.

```bash
git tag v1.5.0
git push origin v1.5.0
```

## Local development

```bash
go build ./...
go test ./...
```
