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

All persistent state lives in [EntDB](https://github.com/elloloop/tenant-shard-db). The service reserves type IDs `1–99` in the EntDB schema:

| type_id | Node |
|---|---|
| 1 | User |
| 2 | Group |
| 5 | RefreshToken |
| 6 | Passkey |
| 7 | TOTPSecret |
| 8 | AuditEvent |

Other services consuming the same EntDB instance must use type IDs `100+` to avoid collisions.

## Configuration

All config is via environment variables. See `internal/config/config.go` for the full list. Most-tweaked:

| Var | Purpose |
|---|---|
| `GATEWAY_ENTDB_ADDRESS` | EntDB endpoint (e.g. `entdb:50051`) |
| `GATEWAY_DEFAULT_TENANT_ID` | Tenant ID for this deployment (each product = its own tenant) |
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

Pull the image and run alongside an EntDB instance:

```bash
docker run -p 80:80 -p 9090:9090 \
  -e GATEWAY_ENTDB_ADDRESS=entdb:50051 \
  -e GATEWAY_DEFAULT_TENANT_ID=my-product \
  -e GATEWAY_PASSKEY_RP_ID=my-product.com \
  -e GATEWAY_PASSKEY_ORIGIN=https://my-product.com \
  -e GATEWAY_TOTP_ISSUER="My Product" \
  ghcr.io/elloloop/identity:0.1.0
```

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
