# Multi-Replica Auth-State Audit

> **Historical record.** This is a point-in-time analysis of the
> **pre-v1.0 EntDB / tenant-shard-db** design. That backend no longer
> exists: the current backends are **postgres / sqlite / memory** (the
> embedded tier is `internal/repo/sqlite/`). The findings below are kept as
> a historical record and are not maintained against the current code.

Date: 2026-05-06

Scope:

- `/Users/arun/projects/identity/cmd/identity/main.go`
- `/Users/arun/projects/identity/internal/service/**`
- `/Users/arun/projects/identity/internal/repo/**`
- `/Users/arun/projects/identity/pkg/oauth/**`
- `/Users/arun/projects/identity/pkg/audit/**`

## Conclusion

Most security-critical auth state already lives in the repository layer, not in process memory. That includes failed-login lockout state, passkey challenges, TOTP setup and login challenges, QR login sessions, password-reset tokens, email-verification tokens, and OAuth identity linkage.

The remaining process-local data falls into two categories:

1. Immutable-at-boot configuration and cryptographic material.
2. Harmless caches that do not act as the source of truth for authentication.

That means the service is structurally capable of running behind multiple replicas as long as every replica points at the same repository and is deployed with the same configuration. One repo-backed concurrency gap still needs follow-up work:

1. EntDB refresh-token consumption is not yet atomic across replicas: follow-up issue `#24`.

QR login session consumption (`#14`) now uses a repository-level
compare-and-set transition (`ConsumeQrLoginSession`) implemented on
every backend, so the approved→consumed step is the serialization
point for token issuance.

The one deliberate non-reloadable area is the self-serve password toggles: `GATEWAY_PASSWORD_SIGNUP_ENABLED` and `GATEWAY_PASSWORD_RESET_ENABLED` are read once at process start and therefore require a rolling restart to change consistently across replicas.

## State Inventory

| State or input | Verdict | Evidence | Notes |
| --- | --- | --- | --- |
| User records | Repo-backed and shared | `internal/service/auth_login.go:93-120`, `internal/repo/postgres/user.go:66-153`, `internal/repo/entdb/repo.go:80-183` | Includes status, role, recovery email, `email_verified`, `failed_login_count`, and `locked_until`. |
| Failed-login lockout | Repo-backed and shared | `internal/service/auth.go:123-125`, `internal/repo/postgres/user.go:238-278`, `internal/repo/entdb/repo.go:288-327`, `internal/repo/entdb/repo.go:475-481` | Lockout counters and expiry are persisted, not process-local. |
| Refresh tokens | Repo-backed and shared | `internal/service/auth.go:127-148`, `internal/repo/postgres/refresh_token.go:15-140`, `internal/repo/entdb/repo.go:507-607` | Session state lives in durable refresh-token rows; access tokens remain stateless JWTs. |
| Refresh replay detection | Repo-backed, but EntDB follow-up needed | `internal/service/auth.go:743-796`, `internal/repo/postgres/refresh_token.go:119-140`, `internal/repo/entdb/repo.go:535-547` | Postgres is atomic today. EntDB still does read-then-update and needs follow-up issue `#24`. |
| OAuth callback state | Replica-safe signed token, not a process cache | `internal/service/auth_login.go:372-417`, `internal/service/auth_login.go:469-487`, `pkg/oauth/state.go:24-143` | `BeginOAuthLogin` signs provider, redirect URI, state, and PKCE verifier into a short-lived token. |
| OIDC JWKS cache | In-process cache, harmless | `pkg/oauth/jwks.go:14-98` | Per-replica cache only. Verification invalidates and refetches on key-miss rotation paths. |
| QR login sessions | Repo-backed and shared (atomic consume) | `internal/service/auth_qr.go`, `internal/repo/postgres/qr_login.go`, `internal/repo/entdb/repo.go` | Session rows are durable. `PollQrLogin` runs an atomic approved→consumed transition through `ConsumeQrLoginSession` before token issuance — Postgres uses `UPDATE … WHERE status = 'approved'`, EntDB uses the SDK's `Plan.UpdateIf` CAS primitive. |
| Passkey challenges | Repo-backed and shared | `internal/service/auth_passkey.go:45-55`, `internal/service/auth_passkey.go:74-90`, `internal/repo/postgres/passkey.go:154-194`, `internal/repo/entdb/repo.go:717-779` | Registration and login challenges are stored durably instead of in memory. |
| Passkey credentials and counters | Repo-backed and shared | `internal/service/auth_passkey.go:101-117`, `internal/repo/postgres/passkey.go:11-152`, `internal/repo/entdb/repo.go:609-715` | Credentials and sign counters are durable and replica-visible. |
| TOTP setup-in-progress | Repo-backed and shared | `internal/service/auth_totp.go:27-55`, `internal/service/auth_totp.go:80-118`, `internal/repo/postgres/totp.go:11-74`, `internal/repo/entdb/repo.go:867-955` | Enrollment state is stored as a durable credential row plus recovery-code rows. |
| TOTP login challenges | Repo-backed and shared | `internal/service/auth.go:625-702`, `internal/repo/postgres/login_challenge.go:11-63`, `internal/repo/entdb/repo.go:957-1051` | Password-first TOTP flow uses stored login challenges, not process-local sessions. |
| Recovery codes | Repo-backed and shared | `internal/service/auth_totp.go:63-66`, `internal/repo/postgres/recovery_code.go:11-88`, `internal/repo/entdb/repo.go:957-1051` | Codes are stored hashed and marked used in the repository. |
| Password-reset tokens | Repo-backed and shared | `internal/service/auth_email.go:63-132`, `internal/service/auth_email.go:154-182`, `internal/repo/postgres/password_reset.go:23-83`, `internal/repo/entdb/repo.go:1176-1247` | Unknown-email requests stay silent, but real reset state is durable. |
| Email-verification tokens | Repo-backed and shared | `internal/service/auth_email.go:233-276`, `internal/service/auth_email.go:279-306`, `internal/repo/postgres/email_verification.go:23-83`, `internal/repo/entdb/repo.go:1249-1320` | Verification state is durable and shared. |
| Email-change tokens | Repo-backed and shared | `internal/service/auth_email_change.go:83-140`, `internal/service/auth_email_change.go:172-207`, `internal/repo/postgres/email_change.go:23-83`, `internal/repo/entdb/repo.go:1322-1399` | Primary-email rotation is durable and not replica-local. |
| Rate limiters (per-IP, per-email) | No auth-flow limiter exists today | `internal/connect/handler_auth.go:77-120`, `internal/service/auth_login.go:68-171`, `internal/service/auth_email.go:63-132` | No signup/login/reset rate-limiter state exists in repo or process today. Signup throttling follow-up: issue `#16`. |
| JWT signing key ring | Process memory, loaded at boot | `internal/app/app.go:54-84`, `pkg/jwt/keyring.go:13-83` | Safe only if every replica receives the same key ring before serving traffic. |
| TOTP encryption key | Process memory, loaded at boot | `internal/app/app.go:99-111`, `internal/service/auth_totp.go:41-44` | Must be identical on every replica or TOTP secrets become unreadable across instances. |
| WebAuthn RP config | Process memory, loaded at boot | `internal/app/app.go:86-97`, `pkg/passkeys/webauthn.go:24-61` | `RPID`, RP name, and origin must be identical across replicas. |
| OAuth client config | Process memory, loaded at boot | `internal/app/oauth.go:8-67` | Client IDs, secrets, redirect URIs, and tenant settings are deployment inputs, not shared mutable state. |
| Password signup/reset toggles | Process memory, loaded at boot | `internal/connect/handler_auth.go:81-83`, `internal/service/auth_email.go:64-67`, `docs-site/src/pages/docs/operations/password-toggle-rollout.astro` | Deployment-scoped flags. Changing them requires a rolling restart. |
| Dummy bcrypt hash for timing equalization | Process memory, harmless | `internal/service/auth_login.go:18-47`, `internal/service/auth_login.go:255-260` | Used only to equalize the unknown-user password path. |
| Memory repo driver | Process memory only | `internal/repo/memory/repo.go` | Dev-only backend. Not valid for multi-replica or durable environments. |

## Findings

### 1. No security decision state is currently owned by one replica

The auth flows that would be dangerous if stored in memory are already repo-backed:

- password lockout
- refresh-token rows and replay metadata
- passkey registration and login challenges
- TOTP setup, recovery codes, and second-factor challenges
- QR login pending or approved sessions
- email verification and password-reset tokens

This is the right ownership model. A replica can crash between steps without losing the system's view of whether a challenge, token, or lockout is valid.

What remains is one repository-level serialization gap, not a state-ownership mistake:

- EntDB refresh-token consume still needs an atomic compare-and-set: issue `#24`

QR-login consume (issue `#14`) was closed by the
`Repository.ConsumeQrLoginSession` compare-and-set primitive — Postgres
gates the `UPDATE` on `WHERE status = 'approved'` and inspects
rows-affected, EntDB uses the SDK's `Plan.UpdateIf` precondition, and
memory holds the mutex across check+write. `PollQrLogin` runs the CAS
before issuing tokens, so two replicas observing the same approved
session resolve to exactly one token-minting winner.

### 2. The self-serve password toggles are deployment config, not live feature flags

`config.Load()` reads `GATEWAY_PASSWORD_SIGNUP_ENABLED` and `GATEWAY_PASSWORD_RESET_ENABLED` once during process startup, and the resulting `cfg` is passed into the application graph. There is no SIGHUP path, admin RPC, or repo-backed toggle model today.

That is acceptable as long as it is treated as a deployment-time decision rather than a runtime switch. Operators must assume mixed behavior during a rollout until the last old replica has drained.

### 3. Replica consistency depends on identical boot-time secrets and identity config

Multi-replica correctness still depends on consistent rollout of:

- JWT signing keys
- TOTP encryption key
- passkey RP configuration
- OAuth provider credentials
- default tenant ID
- password self-serve toggles

These values are not mutable state, but they are authentication inputs. A rollout that leaves replicas on mismatched values can produce split-brain auth behavior even when the repository is shared correctly.

### 4. The in-memory repository remains single-process only

`internal/repo/memory` stores the full auth model in Go maps behind a mutex. That is fine for tests and local development, but it is not a real deployment backend and should never be used for replica-bearing environments.

### 5. One multi-replica follow-up remains outside the state-ownership question

- EntDB refresh-token rotation still reads the row and then writes `consumed_at` in a second step. That needs a true atomic consume primitive so two replicas cannot both win a refresh race. Follow-up issue: `#24`.

## Decision Recorded For Issue #11

Identity will keep `GATEWAY_PASSWORD_SIGNUP_ENABLED` and `GATEWAY_PASSWORD_RESET_ENABLED` as boot-time deployment toggles for now.

Rejected for this change:

- hot reload via `SIGHUP`
- ad hoc admin endpoint reload
- repo-backed mutable feature flags

Reason:

- the current shape has one clear source of truth per replica at boot
- repo-backed mutable toggles are a different product surface, not just an operator convenience
- partial hot reload would create another consistency model to test across every auth flow

Operator consequence:

- update the deployment environment
- perform a rolling restart
- verify the new behavior once all old replicas are drained

The corresponding runbook lives at `/Users/arun/projects/identity/docs-site/src/pages/docs/operations/password-toggle-rollout.astro`.

## Staging Gap

This audit is complete as a checked-in review of state ownership, but it does not replace an end-to-end multi-replica environment test. The refresh-token cross-replica regression test and any QR-session race fix belong in code and integration coverage, not in this document.
