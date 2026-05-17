# JWT signing key rotation runbook

This runbook covers rotating the RS256 signing key used by the identity
service for access tokens (and the OAuth state token). The procedure
below is for the **file-backed signer**, which is the default and the
mode every OSS deployer starts in. A KMS-backed deployment performs
rotation through the KMS API; see the bottom of this document for the
high-level shape there.

## Scope

The identity service signs:

- **Access tokens** (RS256, 15-minute default lifetime — controlled by
  `GATEWAY_JWT_EXPIRY_SECONDS`).
- **OAuth state tokens** (RS256, 5-minute lifetime — used to bind the
  outbound OAuth `state` + PKCE verifier to the in-flight login).

Both use the same `jwt.Signer` and pick up the same key rotation. The
`/.well-known/jwks.json` endpoint publishes every key in the signer so
downstream services can verify tokens minted before, during, and after
a rotation without restarting.

Refresh tokens are not signed — they are random opaque strings hashed
in the database. They are not part of this rotation.

## When to rotate

Rotate JWT signing keys when **any** of the following is true:

- A key has been in use for more than ~6 months.
- A key file has been exposed (e.g. a leaked backup, a compromised
  workstation, a misconfigured volume).
- A team member with file-system access to production keys leaves.
- A compliance regime (SOC 2, FedRAMP, …) calls for a scheduled rotation.

The rotation is **non-disruptive**: no client restarts, no log-out, no
deploy. The service reloads the keys file on `SIGHUP` and the
`/.well-known/jwks.json` document updates to reflect every key the
signer currently knows about. Tokens minted before the rotation
continue to validate until their natural expiry.

## File format

`GATEWAY_JWT_KEYS_FILE` points at a JSON document of this shape:

```jsonc
{
  "keys": [
    {
      "kid": "2026-q2",
      "not_before": "2026-04-01T00:00:00Z",
      "expires_at": "2026-10-01T00:00:00Z",
      "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n"
    }
  ]
}
```

Field semantics:

- `kid` — the JWS `"kid"` header value stamped on tokens signed with
  this key. **Globally unique** across the rotation history; never
  reuse a kid. Tools downstream cache by kid.
- `not_before` — RFC 3339 timestamp. The key becomes eligible to sign
  new tokens at this instant. Empty / absent means "no lower bound".
- `expires_at` — RFC 3339 timestamp. The key stops signing new tokens
  at this instant. The key remains in the JWKS document (and the
  verifier accepts tokens minted earlier) until it is **removed from
  the file**. Empty / absent means "never expires from a signing
  perspective".
- `private_key_pem` — the RSA private key, PEM-encoded. PKCS#1
  (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8
  (`-----BEGIN PRIVATE KEY-----`) are both accepted. RSA only — the
  service rejects EC / Ed25519 keys.

The **active** signing key at any moment is the entry with the latest
`not_before` that is currently in force (i.e. `not_before <= now <
expires_at`). The startup assertion in `cmd/identity` panics if no key
is active at boot — there is no fallback signing path.

## Rotation procedure (file-backed)

The window between phases must be **at least one access-token TTL**
(default 15 minutes) so all tokens minted before the cutover have
expired before the old key is retired.

A worked example is below; substitute your own kid scheme.

### Phase 1 — add the new key

Generate the new key:

```bash
openssl genrsa -out new-key.pem 2048
chmod 600 new-key.pem
```

Edit `keys.json` to add the new entry **before** the cutover:

```jsonc
{
  "keys": [
    {
      "kid": "2026-q2",
      "not_before": "2026-04-01T00:00:00Z",
      "expires_at": "2026-10-01T00:00:00Z",
      "private_key_pem": "..."   // existing key, unchanged
    },
    {
      "kid": "2026-q3",
      "not_before": "2026-07-15T12:00:00Z",   // <— future: cutover time
      "expires_at": "2027-01-15T00:00:00Z",
      "private_key_pem": "..."   // new key
    }
  ]
}
```

Reload the running service:

```bash
kill -HUP $(pidof identity)
```

What happens:

- The JWKS document immediately starts including the new key's public
  half so downstream services that cache JWKS pick it up before the
  cutover.
- The active signing key does not change yet: `2026-q3` has a
  `not_before` in the future, so the signer ignores it for signing.

Wait at least one JWKS cache lifetime (the service sets
`Cache-Control: public, max-age=3600` on the JWKS response — adjust if
your downstream caches longer).

### Phase 2 — cut over

When the new key's `not_before` arrives, the file-backed signer picks
it as the active key automatically on its next `Reload()` (i.e. on the
next SIGHUP or process restart). To trigger the cutover immediately:

1. Edit the file: drop the old key's `expires_at` to the current
   instant (any time at or before now) so the new key is the latest
   in-force entry.
2. `kill -HUP $(pidof identity)`.

Tokens minted before this moment continue to validate — their kid is
still in the JWKS document and the verifier accepts both kids.

### Phase 3 — drain old tokens

Wait **at least** `GATEWAY_JWT_EXPIRY_SECONDS` (default 15 min) for
all tokens signed by the old key to expire naturally. If your service
has an OAuth state token in flight that uses the JWT signer, wait for
the longer of the two TTLs.

### Phase 4 — retire the old key

Edit `keys.json` to remove the old entry entirely:

```jsonc
{
  "keys": [
    {
      "kid": "2026-q3",
      "not_before": "2026-07-15T12:00:00Z",
      "expires_at": "2027-01-15T00:00:00Z",
      "private_key_pem": "..."
    }
  ]
}
```

Reload: `kill -HUP $(pidof identity)`.

The JWKS document stops advertising the old kid. Any client still
holding an old-kid token will see verification fail — but by this
point there should not be any (Phase 3 made sure of it).

Securely delete the retired private-key PEM:

```bash
shred -u old-key.pem
```

### Failure modes

- **Reload fails to parse the file** — the running process keeps the
  previous in-memory snapshot. New signing operations succeed; only
  the next `Reload()` will re-attempt the parse. The error is logged
  with the field `jwt_signer_reload_failed`. Fix the file and HUP
  again.
- **No active key at boot** — `cmd/identity` panics with
  `jwt_signer_init_failed: no active signing key at <ts>`. Check that
  at least one entry has `not_before <= now < expires_at`. Fix and
  redeploy.
- **Active kid not in JWKS** — the startup assertion panics with
  `jwks_active_kid_drift`. This is a programmer bug, not a config
  bug; file an issue.

## Sample `keys.json`

Two-key rotation window, ready to copy + edit:

```jsonc
{
  "keys": [
    {
      "kid": "primary-2026-q2",
      "not_before": "2026-04-01T00:00:00Z",
      "expires_at": "2026-09-01T00:00:00Z",
      "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nREPLACE_ME\n-----END RSA PRIVATE KEY-----\n"
    },
    {
      "kid": "next-2026-q3",
      "not_before": "2026-07-15T12:00:00Z",
      "expires_at": "2027-01-15T00:00:00Z",
      "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nREPLACE_ME\n-----END RSA PRIVATE KEY-----\n"
    }
  ]
}
```

## KMS-backed rotation (high-level)

When `GATEWAY_JWT_SIGNER=kms_aws`, the rotation flow shifts to KMS:

1. Create the next asymmetric KMS key (KeySpec `RSA_2048`, KeyUsage
   `SIGN_VERIFY`).
2. Add it to `GATEWAY_JWT_KMS_KEYS` (CSV of `kid=arn` entries) with
   the new kid as the latest entry.
3. Restart / redeploy the service. The startup assertion confirms
   every active kid is published in JWKS before the listener accepts
   traffic.
4. Wait for the access-token TTL plus the JWKS cache window.
5. Disable the old KMS key (`aws kms disable-key --key-id <arn>`).
6. Remove the old kid from `GATEWAY_JWT_KMS_KEYS` and redeploy.

A worked KMS rotation runbook with IAM policy snippets is out of scope
for this document; see your cloud's KMS rotation guide.
