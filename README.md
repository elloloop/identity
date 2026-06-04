# Identity

Authentication and user-management service. Deploys as a single container; pulls a pinned image, points at an EntDB instance, exposes Connect-RPC over HTTP/JSON.

Treat this like [tenant-shard-db](https://github.com/elloloop/tenant-shard-db): one image, deployed once per product, fully isolated user pools.

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

All persistent state lives in [EntDB](https://github.com/elloloop/tenant-shard-db). Identity targets the **v2.x line** of the server image and Go SDK — the entdb backend uses ADR-031 self-describing writes, attaching identity's schema (every `(entdb.node)`/`(entdb.edge)` message in `proto/identity/schema/schema.proto`) on the first `ExecuteAtomic` per tenant. The server enforces field types, single- and composite-unique constraints, and required-fields against that schema atomically.

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
| 32 | IdentityVerificationRecord | `verification_id` is unique |
| 33 | Organization | `slug` is unique (`mode=multi`) |
| 34 | OrganizationMembership | (`mode=multi`) |
| 35 | Session | `sid` is unique |
| 36 | OAuthOneTimeCode | hosted-OAuth handover; `code_hash` unique |

Other services consuming the same EntDB instance must use type IDs `100+` to avoid collisions.

## Configuration

All config is via environment variables. See `internal/config/config.go` for the full list. Most-tweaked:

| Var | Purpose |
|---|---|
| `GATEWAY_ENTDB_ADDRESS` | EntDB endpoint (e.g. `entdb:50051`) |
| `GATEWAY_IDENTITY_MODE` | Tenancy shape: `single` (default, one tenant per deployment) or `multi` (one tenant per customer org) |
| `GATEWAY_DEFAULT_TENANT_ID` | Tenant ID for this deployment (required in `single`; the system tenant in `multi`) |
| `GATEWAY_TENANT_RESOLUTION_SOURCES` | `multi` only: ordered per-request resolution sources, `host`/`jwt` (default `host,jwt`) |
| `GATEWAY_TENANT_HOST_BASE_DOMAIN` | `multi` only: base domain whose subdomain is the tenant slug (required when `host` is a source) |
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

If you don't want to run EntDB, identity also has a postgres backend (`GATEWAY_BACKEND=postgres`):

```bash
docker run -p 80:80 -p 9090:9090 \
  -e GATEWAY_BACKEND=postgres \
  -e GATEWAY_TEST_POSTGRES_DSN='postgres://identity:password@db:5432/identity?sslmode=disable' \
  -e GATEWAY_DEFAULT_TENANT_ID=my-product \
  ghcr.io/elloloop/identity:0.1.0
```

The conformance suite asserts both backends behave identically across every Repository method — same uniqueness/ordering/error-translation semantics. The entdb backend is the recommended path for multi-tenant deployments because it gives strong per-tenant data isolation natively.

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
