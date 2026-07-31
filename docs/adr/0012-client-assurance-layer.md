# ADR-0012 — Client assurance layer (attestation as its own token)

## Status

Accepted (2026-07-30).

Depends on ADR-0002 (Project is the isolation shard). Extends the per-project
`config_json` surface (ADR-0010 pattern) with an `assurance` block. Supersedes
the inline-CAPTCHA design (`captcha_token` request fields +
`GATEWAY_CAPTCHA_*`), which is removed.

## Context

A downstream customer asked for an "anonymous device identity" flow: verify a
mobile client's hardware via Apple App Attest / Google Play Integrity, then
issue "a standard token indistinguishable from a user token" so their gateway
could gate a public content API against bot scraping.

Two problems with the request as specified:

1. **Attestation is not identity.** App Attest and Play Integrity prove *"a
   genuine, unmodified build of this app on genuine, uncompromised hardware"*.
   They say nothing about who — or whether anyone — is signed in. Freezing
   that fact into an identity-shaped token conflates two orthogonal axes.
2. **An indistinguishable token is a privilege-confusion bug.** Every RPC
   behind a Bearer treats a valid access token as a human (`GetCurrentUser`,
   `UpdateProfile`, `DeleteMyAccount`, role-gated admin surfaces). A
   device-minted token in the same shape would be accepted there.

We already carried one client-assurance mechanism — CAPTCHA (Turnstile /
reCAPTCHA v3) — wired inline into six auth RPCs via a `captcha_token` request
field, its verified outcome discarded after the check. That is the same
*category* of signal (an assurance fact about the client) with a bespoke,
web-only transport.

Firebase's architecture separates these cleanly: **App Check** (attestation,
own token, own header, per-backend enforcement, reCAPTCHA as its web provider)
is independent of **Authentication** (identity, anonymous or otherwise). We
adopt that split.

## Decision

1. **Assurance is a separate token, not claims on the identity token.**
   Verified evidence (App Attest attestation, Play Integrity verdict, captcha
   solution) is exchanged for a short-lived **assurance token**: a JWT signed
   by the deployment's existing JWKS, marked `aud=assurance`, carrying `amr`
   (which provider passed), the minting project, optionally the attested
   device id — and **no subject**. Clients transport it in the
   `X-Assurance-Token` header. The two token species are disjoint in both
   directions: assurance verification requires the assurance audience, and
   access-token verification now rejects sub-less tokens.

2. **One abstraction, four providers.** `pkg/assurance` owns the concept:
   Turnstile and reCAPTCHA v3 (web, the absorbed `pkg/captcha`), Apple App
   Attest (`pkg/assurance/appattest` — full server-side verification against
   Apple's pinned root CA, nonce binding, key-id and App ID checks, assertion
   counters), and Play Integrity (`pkg/assurance/playintegrity` — server-side
   `decodeIntegrityToken` with a hand-rolled RFC 7523 service-account
   exchange on the existing jwx dependency).

3. **Three RPCs.** `CreateAssuranceChallenge` (one-shot nonce, ios/android),
   `IssueAssuranceToken` (evidence → token; iOS registers the attested device
   key + counter in the new `attested_devices` storage), and
   `RefreshAssuranceToken` (iOS App Attest assertion over a fresh challenge;
   the hardware counter CAS is the replay protection — no stored bearer
   refresh secret). Android refresh re-runs `IssueAssuranceToken`: Play
   Integrity has no persistent key, and the periodic re-verdict is the
   equivalent guarantee.

4. **Enforcement replaces inline captcha.** The six previously captcha-gated
   RPCs require a valid assurance token (per-endpoint
   `GATEWAY_ASSURANCE_ENFORCE_*` toggles under the global
   `GATEWAY_ASSURANCE_ENABLED`). The `captcha_token` fields are removed
   (numbers reserved); web clients perform the same exchange mobile clients
   do. Downstream services can require the token on their own APIs by
   validating against this deployment's JWKS — audience `assurance` — which
   is the customer's gateway story.

5. **Per-project app identity.** Which app a project accepts attestations
   from (`team_id`/`bundle_id`, `package_name`/cert digests/encrypted
   service-account key) lives in the project's `config_json` `assurance`
   block, following ADR-0010's shape including `secretcrypto` encryption
   under `GATEWAY_PROJECT_SECRETS_KEY` and an `AdminSetProjectAssurance`
   RPC that takes the key in plaintext and encrypts it server-side (an
   operator must never reimplement the at-rest format); a project's own
   block wins on any request that RESOLVES that project, and the
   `GATEWAY_ASSURANCE_*` env identity covers both the project that
   configures none and the zero-config default-project pin (which carries
   no `config_json` at all). Web captcha stays deployment-global —
   its secret authenticates our server to the captcha provider, not one app
   to us.

6. **Orthogonal to access policy.** Assurance authenticates the *client*;
   the per-project access mode (open/allowlist/invite/closed) governs which
   *users* may authenticate. An assurance token grants no account and touches
   no access-mode chokepoint.

## Consequences

- Attestation raises the cost of scraping; it does not prove a human. A
  farmed genuine device passes. The durable value is a stable,
  expensive-to-farm identifier (the attested device) that downstream
  rate-limiting can key on; that enforcement is the consumer's half.
- Breaking release: `captcha_token` fields and `GATEWAY_CAPTCHA_*` are gone
  (see UPGRADE.md). Web clients gain one extra round-trip (the exchange),
  matching App Check's shape. Removed variables are detected at boot and
  fail closed, so the rename cannot silently disable enforcement.
- **The web arm trades a per-request captcha for a reusable token.** Under
  the old design every gated call carried a fresh captcha solution; now one
  solve buys a token reusable until it expires. That is inherent to the App
  Check shape (and is what removes a provider round-trip from the auth hot
  path), but it is a real reduction in per-request assurance: a bot pays one
  solve and replays for the token's lifetime. Mitigations shipped: the web arm has
  its OWN lifetime (`GATEWAY_ASSURANCE_WEB_TOKEN_TTL_SECONDS`, default 5
  minutes) so it can be shortened without also shortening the
  hardware-attested arms, both TTLs are hard-capped at 24h, and all three
  assurance RPCs carry a per-IP rate limit. Single-use (`jti` + redemption
  store) and IP binding remain candidate follow-ups.
- Attested devices are retained on a staleness sweep, not forever: a
  reinstall or key regeneration mints a NEW key id, so an attestation row
  is otherwise permanent and the table only ever grows. The sweeper reaps
  rows whose `last_used_at_ms` predates the retention window (backed by a
  `(project_id, last_used_at_ms)` index); a reaped device simply
  re-attests on its next refresh, which costs one round-trip and no user
  interaction. The window is its own knob
  (`GATEWAY_ASSURANCE_DEVICE_RETENTION_DAYS`, default 90) with its own
  sweep step, deliberately NOT the shared expiry cutoff: that cutoff is
  slack past a row's own `expires_at_ms`, and a device row has no expiry.
  Config validation requires the window to exceed the token TTL.
- Genuine Apple attestations cannot be minted in CI. The verifier accepts
  injectable trust roots, and `appattesttest` mints spec-shaped attestation
  objects from a synthetic CA with per-check corruption knobs; the DER/CBOR
  is hand-built so the generator cannot share a bug with the parser.
- **Anonymous identity is explicitly out of scope here** (phase 2): a
  Firebase-style anonymous *user* (stable UID, linkable, preserved on
  upgrade, per-project toggle orthogonal to access mode even when `closed`)
  is an identity-layer feature to be designed on its own, with assurance
  available to gate its creation.
