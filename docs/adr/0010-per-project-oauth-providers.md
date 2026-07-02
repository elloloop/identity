# ADR-0010 — Per-project OAuth providers (the Firebase-project model)

## Status

Accepted (2026-07-02).

Depends on ADR-0002 (Project is the isolation shard) and ADR-0003 (global user
pool per project). Extends the per-project configuration surface already carried
in a project's `config_json` (branding, passkey RP-ID, CORS, login defaults) to
the hosted OAuth login flow.

## Context

OAuth provider credentials were **global**: `internal/app/oauth.go`
`buildOAuthRegistry` built one Google/Microsoft/GitHub/Apple/OIDC `Exchanger` at
boot from the `GATEWAY_OAUTH_*` environment variables, and the hosted login flow
(`BeginOAuthLogin`, `OAuthLogin`, `auth_oauth_hosted.go`) resolved providers from
that single registry.

Post ADR-0002 the **Project** is the isolation container (the Firebase-project
equivalent). A global OAuth registry breaks that isolation: every project shared
one deployment-wide set of providers, so one product's Google client necessarily
served another product in the same deployment. A project could not enable Google
for itself without enabling it for all, and could not use its own client id.

## Decision

Each **project** configures its **own** OAuth providers, exactly like enabling
providers in a Firebase project's Auth console. A project knows nothing about
another project's providers.

1. **Storage.** Providers live under an `"oauth"` object in the project's
   `config_json` (the same blob that already carries branding/passkey/CORS/login),
   per provider — `google`, `microsoft`, `apple`, `oidc`. No new table. The
   typed view is `service.ProjectOAuthConfig`, parsed alongside the other
   `config_json` fields and carried on `ResolvedProject` / `ProjectScope`.

2. **Secrets at rest.** Provider secrets (`client_secret_enc`, Apple
   `private_key_enc`) are stored **encrypted** with AES-256-GCM via the shared
   `pkg/secretcrypto` primitive, using a server key supplied as
   `GATEWAY_PROJECT_SECRETS_KEY` (base64, 32 bytes). The key is **required when
   the postgres control plane is enabled** (`config.Validate`), because only
   postgres can store a non-default project's credentials; drivers without a
   control plane pin every request to the default project and need no key. The
   struct holds the ciphertext; it is decrypted only when an `Exchanger` is
   built.

3. **The env vars become the default project's providers.** `GATEWAY_OAUTH_*`
   still builds a registry at boot, but that registry is now **only** the default
   project's provider set. Existing single-project deployments keep working
   unchanged.

4. **Precedence (isolation-correct).** For provider `P` and the request's
   project:
   - if the project's `config_json.oauth.P` is present → use it (decrypt secret);
   - else if the project **is** the default project (`cfg.DefaultProjectID`) or
     the request is unscoped → build `P` from the env registry (today's
     behaviour);
   - else — a non-default project with no config for `P` → `P` is **unavailable**
     for that project (the same "unknown provider" error an unregistered provider
     already returns). A non-default project **never** falls back to the env
     providers; doing so would leak the default project's providers.

5. **Resolution + caching.** `service.OAuthResolver` returns the `*oauth.Exchanger`
   for `(project, provider)`, building lazily and caching keyed by
   `(projectID, provider, configHash)` so a config change (including a rotated
   secret) rebuilds while steady state reuses the JWKS/discovery cache. The
   default project's env-built exchangers are entries in this cache path too. The
   resolver replaces the global-registry lookups in `BeginOAuthLogin`,
   `OAuthLogin`, and the hosted callback; default-project behaviour is unchanged.

## Consequences

- **Positive.** Project isolation now covers OAuth: two products on one
  deployment each enable their own providers with their own client ids, and one
  can use Google while another cannot — like Firebase. No shared global provider
  set beyond the default project's env config.
- **Positive.** Secrets are encrypted at rest with one audited primitive
  (`pkg/secretcrypto`), reused by TOTP secret storage, so the crypto lives in one
  place.
- **Neutral.** GitHub is not part of the per-project schema; it remains an
  env-only provider available to the default project. Per-project GitHub and the
  admin RPC to author `config_json.oauth` are follow-ups.
- **Negative / operational.** Postgres deployments must set
  `GATEWAY_PROJECT_SECRETS_KEY`; boot fails fast without it. Losing/rotating the
  key invalidates every stored provider secret (they must be re-encrypted).
- **Scope.** Generic per-project OIDC is discovery-based (issuer or
  discovery_url), mirroring the env OIDC provider; there are no per-endpoint
  overrides, to avoid dead config knobs the exchanger ignores.
- **Follow-ups.** The native mobile flow and native Microsoft (PR B), and an
  admin management RPC to author a project's OAuth providers (PR C).
