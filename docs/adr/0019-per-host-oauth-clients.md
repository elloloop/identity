# ADR-0019 — Per-host OAuth clients within one project

## Status

Accepted (2026-10-30).

Amends ADR-0010 (Per-project OAuth providers) and ADR-0011 (Opt-in hub OAuth
provider sharing): within the provider their precedence selects, a project may
now name a different client for a given callback host. Which provider applies,
and whether one applies at all, is unchanged.

## Context

A provider's consent screen names the application its client is registered
as. ADR-0010 gives a project one client per provider, so every host the
project is served on shows the same name. That is wrong when one project
serves several products on their own auth hosts — `auth.acme.example` and
`auth.widgets.example` sharing one account pool, say: a user signing in to
the second is asked to trust the first.

Giving the second product its own project would brand its screens correctly,
but a project is the account pool (ADR-0003), so its existing users would be
split from their accounts. The products need one pool and a client per host.

## Decision

1. **Storage.** A project's `config_json.oauth` gains a `hosts` object: for
   each callback host, the providers whose client differs there.

   ```json
   "oauth": {
     "google": { "client_id": "base", "client_secret_enc": "…" },
     "hosts": {
       "auth.widgets.example": {
         "google": { "client_id": "widgets", "client_secret_enc": "…" },
         "apple":  { "client_id": "example.widgets.web" }
       }
     }
   }
   ```

   An override holds a client identity and nothing else: `client_id`, and for
   every provider but Apple a `client_secret_enc`, encrypted like any other
   provider secret (ADR-0010 §2). A host key is a lower-case DNS name with no
   scheme, port or path.

2. **The key is the host of the flow's callback URL.** A provider client is
   registered with a list of callback URLs, so the host a callback lands on is
   what decides which client may complete it. For the hosted flow that is the
   public host the sign-in page and `/oauth/start` are served on (the redirect
   URI is built from the request's origin). For the headless flow it is the
   host of the app's own `redirect_uri`.

   The start and the callback select the same client by construction: the
   callback resolves its provider from the redirect URI signed into the state
   token, not from the host the callback request reached, and the provider
   itself refuses a code exchanged for a redirect URI or client it was not
   issued to.

3. **An override swaps the client of the base, nothing else.** The base is the
   provider ADR-0010/0011's precedence yields for the project: its own
   `config_json.oauth.P` (rule 1), the env provider for the default project
   (rule 2), or the hub's env provider borrowed under hub sharing (rule 3).
   Endpoints, Microsoft tenant pins and allow-lists, native audiences and
   Apple's team id, key id and private key all come from the base; Apple's
   override replaces only the Services ID, the others replace client id and
   secret.

   An override never enables a provider: with no base (a non-default project
   that configures no `P` and does not borrow), `P` stays unavailable at every
   host. A host with no override uses the base, exactly as before.

   Overrides are part of the project's stored configuration, so a request
   carries them when it resolves to the project by an auth domain or a
   project key. A request that names no project falls back to the default
   project's env settings, which have no stored configuration and so no
   overrides.

4. **A broken override is unavailable.** An override whose secret will not
   decrypt, or whose env base cannot be rebuilt (an embedder supplied its own
   `OAuthRegistry`, so the server cannot rebuild an env provider with another
   client), makes `P` unavailable at that host, and the build failure is
   logged once per configuration. It never falls back to the base client,
   which is not registered for that host's callback (ADR-0010 rule 1's
   "configured but broken" rule).

5. **The hosted page starts an overridden provider on its own host.** Without
   an override, an own provider starts on the project's primary auth domain
   and a borrowed one on the hub (ADR-0011), because that is where its client
   is registered. A provider with an override for the page's host starts on
   that host, needing no `project_key`: its client is registered there.

6. **Authoring.** `AdminSetProjectOAuthProvider` with `callback_host` set
   writes the override for that host and provider, and accepts only
   `client_id` and `client_secret` (an empty secret keeps the stored one; Apple
   takes none). `AdminDeleteProjectOAuthProvider` with `callback_host` removes
   it, and `AdminListProjectOAuthProviders` returns the overrides, redacted, in
   `host_clients`. Setting or deleting the base provider leaves its overrides
   alone.

7. **Caching.** An override's exchanger is cached in its own slot per
   (project, provider, host), keyed on a hash of the base and the override,
   so editing either rebuilds it. Only hosts that carry an override are ever
   cached, so request hosts cannot grow the cache.

## Consequences

- **Positive.** One project, one account pool, and each auth host's consent
  screens name its own product.
- **Operational.** A host with no override follows the primary auth domain or
  the hub, as before. If the primary auth domain itself has an override, the
  own-provider flows other hosts start there use it too; to keep the base
  client on another host's pages, make a host without an override the primary.
- **Operational.** Configure overrides only once every replica runs a version
  that reads them. An older replica ignores `oauth.hosts` (the config decoder
  tolerates unknown keys and the admin merge preserves them), so a flow started
  on a newer replica and completed on an older one would exchange its code with
  the base client and fail.
- **Neutral.** Native sign-in is unchanged: it verifies ID tokens against the
  provider's `native_audiences`, which an override does not touch.
