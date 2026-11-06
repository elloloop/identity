# ADR-0020 — Per-host passkey relying parties

## Status

Accepted (2026-11-06).

Sits above the project `passkey` block for the hosts it names. Unset, nothing
changes.

## Context

A passkey is bound for good to the relying party it was created under. A
deployment that serves several products on their own domains needs each to have
its own relying party, or a product's users hold credentials named after
another product's domain, and a native app cannot use them unless it proves
association with that domain.

Today the relying party comes from the global `GATEWAY_PASSKEY_*` settings or
from a project's `config_json.passkey` block. A project is the account pool
(ADR-0003), so one product per project is not always available, for the same
reason as ADR-0019. A project block also does not stop a product that has none
from receiving the global relying party, which belongs to some other product.

## Decision

1. **`GATEWAY_PASSKEY_RELYING_PARTIES`** is a JSON array, one entry per public
   auth host:

   ```json
   [
     {
       "host": "auth.acme.example",
       "rp_id": "acme.example",
       "rp_name": "Acme",
       "origins": ["https://acme.example", "https://accounts.acme.example"]
     }
   ]
   ```

   `rp_name` is optional and falls back to `GATEWAY_PASSKEY_RP_NAME`.

2. **The key is the host the request arrived on**, the one project resolution
   reads. The `Origin` header cannot be the key: a native app's call to Identity
   sends none, and a browser's names the page rather than the product.

3. **Precedence.** The host's entry, then the project's block, then the global
   settings, and the last only while the variable is unset. Once it is set, a
   host with no entry whose project names no complete relying party of its own
   is refused with `FAILED_PRECONDITION`. A partial project block is refused
   too, since it would inherit the global `rp_id`. An unconfigured host never
   receives another product's relying party.

4. **Checked at boot.** The server refuses to start on: malformed JSON, an unknown
   field, a repeated host, a host that is not a lower-case DNS name, an origin
   that is not written exactly as a browser reports it, plain `http` other than on
   loopback, or an `rp_id` that is not a registrable suffix of the host and of
   every origin. A public suffix is never a valid `rp_id`.

5. **A list of origins**, because one relying party can have several pages, and
   a native app's assertion carries `https://<rp_id>` whatever page signed the
   user in. `pkg/passkeys.Config` gains an additive `AdditionalOrigins`.

## Consequences

- Unset is byte-for-byte today's behaviour: every path still returns the same
  global instance, and a broken project block still falls back to it.
- A credential is not moved. Users who hold a credential under the old relying
  party register a new one on the new host; verification of the old one fails on
  the relying-party hash and is reported as a failed sign-in.
- An operator who sets the variable must list every host that runs a ceremony.
  An omitted one fails closed, visibly, rather than minting credentials under the
  wrong domain.
- A call that did not arrive over HTTP, such as an embedder's native gRPC server,
  carries no host, and is refused once the variable is set unless its project
  names a relying party.
- The `Host` header is client-supplied. It chooses only which options are
  returned; the browser or platform checks the `rp_id` against the real page or
  the app's association, and verification checks the origin and the `rp_id` hash,
  so naming another host gains nothing.
