# ADR-0011 — Opt-in hub OAuth provider sharing (the Auth0-tenant model)

## Status

Accepted (2026-07-18).

Amends ADR-0010 (Per-project OAuth providers): precedence rule 4's "a
non-default project **never** falls back to the env providers" becomes "…never,
**unless** the deployment explicitly opts into hub sharing". ADR-0010's
storage, secrets, and caching decisions are unchanged.

## Context

ADR-0010 made OAuth providers strictly per-project: a non-default project with
no `config_json.oauth` entry for provider P cannot use P at all. That forces
every project to register its own provider client (its own Google client id
and its own auth-domain redirect URI in GCP) even when one operator runs
hundreds of their own apps as projects on a single deployment.

The industry-standard alternative is the brokered-IdP model — Auth0 configures
**one** Google social connection per tenant and every application shares it;
Firebase auto-provisions the equivalent. The identity server is the OAuth
client toward the provider; projects trust identity, never the provider
directly. Downstream deployers asked for exactly this: route hosted OAuth for
any project through the central hub (`/oauth/start` on the default project's
host, carrying a `project_key` parameter), reusing the hub's single client id
and single registered redirect URI, while identity mints the user and session
in the routed project.

Strict isolation is still the right default: on a deployment whose projects
belong to **different** operators, a shared client would show one operator's
consent-screen branding for another operator's app and grant provider scopes
to a client the project owner does not control.

## Decision

1. **A deployment-level opt-in flag.** `GATEWAY_OAUTH_HUB_SHARING` (bool,
   default `false`). When false, ADR-0010's strict isolation is unchanged.
   It is env-only — the decision belongs to the deployment operator, who is
   the only party able to assert that every project shares the hub's trust
   domain.

2. **The flag relaxes exactly one rule, inside the resolver.**
   `service.OAuthResolver` (`available` / `exchangerFor`) treats the default
   registry as a fallback for non-default projects when the flag is set. No
   call site forks on the flag; the isolation decision keeps a single home.
   A project's own `config_json.oauth.P` still always wins — including a
   configured-but-broken P, which stays unavailable rather than silently
   borrowing the hub's.

3. **Project routing rides the OAuth `state`.** The hub start URL carries
   `?project_key=`; the project middleware resolves it exactly like the
   `X-Project-Key` header (an unknown key is rejected, never downgraded to
   the default project). `BeginHostedOAuth` prefixes the plaintext key onto
   the signed hosted state token (`<key>:<token>` — the token is a JWS
   compact serialization and never contains `:`, so the last `:` is always
   the boundary; `pkg/oauth.JoinProjectKeyState` / `SplitProjectKeyState`
   are the only code that reads or writes this format). The callback
   middleware re-scopes from the prefix; `CompleteHostedOAuth` then verifies
   the signed `project_id` claim against the resolved scope, so a tampered
   prefix cannot re-route a flow.

4. **Bounded, urlencoded-only parameter extraction.** The middleware caps a
   hosted-OAuth POST body at the same 1 MiB the callback handler enforces
   and parses only `application/x-www-form-urlencoded` bodies (Apple's
   `form_post`); the multipart parser is never invoked on this
   unauthenticated surface.

## Consequences

- **Positive.** One provider client and one registered redirect URI serve
  every project of a single-operator deployment — the Firebase/Auth0
  operational model — while users, one-time codes, and sessions stay strictly
  project-scoped (per-project user pools are untouched).
- **Positive.** Isolation-by-default is preserved for multi-operator
  deployments; the borrow is unreachable without the explicit env opt-in.
- **Negative / accepted.** With sharing on, every hub-routed project shows
  the hub client's consent-screen branding, and provider grants accrue to the
  shared client. This is inherent to the model and the reason the flag is
  deployment-level and off by default.
- **Neutral.** The plaintext `project_key` in the state is the project's
  publishable credential key, already visible client-side wherever the header
  flow is used; the provider sees it in `state` as it sees any state value.
- **Scope.** Sharing applies wherever the resolver resolves providers (hosted
  and headless flows) — the headless flow additionally requires the caller's
  redirect URI to be registered on the shared client, which remains the
  operator's choice to configure.
