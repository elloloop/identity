# Embedding identity as a library

identity ships two ways:

- as the **container** (`cmd/identity`), the default for most deployers; and
- as an **embeddable Go library** (`github.com/elloloop/identity/identityserver`),
  for a host that already runs a Go gRPC/HTTP server and wants identity
  mounted into it rather than running a second process.

Both run the exact same wiring. The container is a thin shim over the
library — see decision log §11 in [IDENTITY.md](./IDENTITY.md).

## API

```go
import "github.com/elloloop/identity/identityserver"

srv, err := identityserver.New(ctx, opts)   // construct; no goroutines, no listeners
if err != nil { /* ... */ }

mux.Handle("/", srv.Handler())              // mount surface 1: HTTP (Connect/gRPC/gRPC-Web)
srv.RegisterGRPC(grpcServer)                // mount surface 2: native *grpc.Server

if err := srv.Start(ctx); err != nil { /* ... */ }   // launch background workers
defer srv.Shutdown(ctx)                               // drain workers, release resources
```

- **`New(ctx, Options) (*Server, error)`** assembles the persistence,
  signer, WebAuthn, IDV and OpenTelemetry adapters that are not injected,
  validates the config, and wires the service layer. It performs
  construction-time I/O (builds the configured repo driver from
  `Config.RepoDriver` — memory, sqlite or postgres — plus AWS config load
  and OTel exporter init)
  but starts no goroutines and binds no listener. `ctx` scopes that setup;
  it is not retained.
- **`Handler() http.Handler`** is the full middleware chain (logging,
  recover, CORS, health, client-IP, rate-limit, JWKS, JWT auth, metrics)
  wrapping the Connect mux. It serves the Connect, gRPC and gRPC-Web
  protocols plus `/health`, `/readyz` and `/.well-known/jwks.json`. Mount
  it on any HTTP/2 (or h2c) server.
- **`RegisterGRPC(grpc.ServiceRegistrar)`** registers identity onto a host
  `*grpc.Server`. It delegates to the same service implementation
  `Handler` serves (see _Native gRPC_ below).
- **`Start(ctx) error`** launches the background workers: the async audit
  flusher, the expired-row sweeper, and (for the file signer) SIGHUP-driven
  key reload. Idempotent.
- **`Shutdown(ctx) error`** drains the workers and releases everything
  `New` acquired (signer watcher, repo driver, OTel exporter), in reverse
  order. Safe without a preceding `Start`, and safe to call more than once.

## Options

`Options.Config` is the full configuration — the same struct the container
loads from the environment. Build it field-by-field, or take the
environment defaults:

```go
opts, err := identityserver.OptionsFromEnv()   // reads every GATEWAY_* var
opts.Logger = myLogger                          // then tweak as needed
```

Every adapter field is optional. Left nil, `New` builds it from `Config`
exactly as the container does. Set one to inject your own:

| Field                              | nil behavior                                            |
| ---------------------------------- | ------------------------------------------------------- |
| `Signer`                           | built from `Config.JWTSigner` (file or `kms_aws`)       |
| `Repo` + `DB`                      | built from `Config.RepoDriver` (must be set together)   |
| `EmailTransport`                   | built from SMTP settings (falls back to log-only)       |
| `SMSSender`                        | built from `GATEWAY_SMS_*` (log-only when SMS disabled)  |
| `OAuthRegistry`                    | built from the OAuth client credentials in `Config`     |
| `IDVProvider`                      | built from `Config.IDVProvider` (may be disabled)       |
| `AssuranceWebVerifier`             | built from `Config.AssuranceWebProvider`; nil (and no configured provider) means NO web verifier, so browser clients cannot obtain an assurance token |
| `DNSResolver`                      | `net.DefaultResolver` (used by `VerifyDomain` on the postgres control plane) |
| `Logger`                           | no-op logger                                             |
| `MetricsRegistry`                  | `prometheus.DefaultRegisterer`                           |

Injecting `Repo`+`DB` is how a host that already owns a database — or a
test — mounts identity without standing up a real repo driver. The per-request,
per-project repository is resolved internally from the project scope (see
[ADR-0002](./adr/0002-project-is-the-isolation-shard.md)); there is no
per-tenant repository factory to supply.

## Mount surface 1 — HTTP

`Handler()` is an ordinary `http.Handler`. Mount it on your own mux
alongside your routes, then serve over HTTP/2 (TLS) or h2c:

```go
mux := http.NewServeMux()
mux.Handle("/", srv.Handler())
mux.HandleFunc("/healthz", myHealth)

httpSrv := &http.Server{Addr: ":8080", Handler: h2c.NewHandler(mux, &http2.Server{})}
```

This path runs the full middleware chain, including the JWT auth
middleware that verifies the bearer token and populates
`X-Authenticated-User-Id` for the handlers.

## Mount surface 2 — native gRPC

`RegisterGRPC` registers identity on an existing `*grpc.Server`:

```go
grpcSrv := grpc.NewServer( /* your interceptors */ )
srv.RegisterGRPC(grpcSrv)
myservicepb.RegisterMyServiceServer(grpcSrv, myImpl)
```

Connect and grpc-go are different RPC stacks. The bridge
(`identityserver/grpc_bridge.go`) implements the grpc-go
`IdentityServiceServer` interface — generated by the pinned
`buf.build/grpc/go` plugin in `buf.gen.yaml` — by delegating every RPC to
the same `connect.Handler` the HTTP surface serves. No handler logic is
duplicated; both surfaces share one service-layer wiring.

**Authentication is the host's responsibility on this path.** The HTTP
middleware chain (CORS, rate-limit, JWKS, and the JWT auth middleware) is
HTTP-only and does not run over native gRPC. Identity's handlers read the
authenticated user id from the `x-authenticated-user-id` metadata key (the
bridge copies incoming gRPC metadata into the Connect request headers).
Supply a server interceptor that verifies the bearer token and sets that
metadata. Two rules it must follow, both of them load-bearing:

1. **Verify with `jwt.VerifyAccessToken`.** It refuses tokens carrying a
   `purpose` claim — the short-lived tickets identity hands to
   *unauthenticated* callers to complete an interrupted flow (a required-DOB
   submission, a managed child's passkey enrolment). Those are signed with
   the same key and the same audience as a session token; only that claim
   separates them. A verifier that ignores it turns a ticket into a full
   session for every RPC on this surface.
2. **Strip the identity metadata a client sent.** The bridge copies incoming
   metadata verbatim, and `AppendToIncomingContext` puts your value *after*
   any the client supplied — so a client-set `x-authenticated-user-id` would
   win. Delete the three identity keys before appending your own.

```go
func authInterceptor(kp jwt.KeyProvider, tenant, audience string, requireAud bool) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
        md, _ := metadata.FromIncomingContext(ctx)
        md = md.Copy()
        // Never trust these from the wire — identity's handlers read them
        // as the verified caller.
        md.Delete("x-authenticated-user-id")
        md.Delete("x-authenticated-tenant-id")
        md.Delete("x-authenticated-project-id")
        if toks := md.Get("authorization"); len(toks) > 0 {
            // VerifyAccessToken rejects a purpose-bearing ticket for us.
            claims, err := jwt.VerifyAccessToken(
                strings.TrimPrefix(toks[0], "Bearer "), kp, tenant, audience, requireAud)
            if err == nil {
                md.Set("x-authenticated-user-id", claims.Sub)
            }
        }
        return handler(metadata.NewIncomingContext(ctx, md), req)
    }
}
```

Unauthenticated RPCs (`PasswordSignup`, `PasswordLogin`, `BeginOAuthLogin`,
…) work without any of this. JWKS verification keys are still served over
the HTTP surface at `/.well-known/jwks.json`; a native-gRPC-only host
either mounts `Handler()` on a side port for JWKS or distributes the keys
out of band.

## Lifecycle

```go
srv, _ := identityserver.New(ctx, opts)
// ... register on your servers ...
srv.Start(ctx)          // workers begin
// ... serve ...
srv.Shutdown(ctx)       // workers drain, resources released
```

Start your own listeners after `Start`, and stop accepting connections
before `Shutdown` so in-flight requests drain cleanly. Until `Start` runs,
audit writes happen synchronously on the calling goroutine, so a
never-started server is still correct, just slower.

## Example

A runnable example mounting identity onto both a host `*grpc.Server` and an
HTTP mux, backed by the in-memory repository (no external dependencies),
is in [`examples/embedded`](../examples/embedded):

```sh
go run ./examples/embedded
```

It serves the HTTP surface on `:8080` (h2c) and the native gRPC surface on
`:8090`.
