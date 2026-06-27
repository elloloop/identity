# Load And Soak Harness

This directory owns the checked-in load harness for issue `#12`.

The harness uses a pinned `k6` container image:

- `grafana/k6:0.49.0`

The four scenarios in the issue are all explicit files under
`tests/load/k6/`:

- `login_steady.js`
- `refresh_steady.js`
- `signup_burst.js`
- `mixed_workload.js`

Run them through `tests/load/run.sh`.

`hotpath_test.go` is a deterministic Go load test for CI and nightly
automation. It starts the real HTTP/Connect handler with the in-process
memory repository, seeds password users, and drives the login plus
refresh hot path without Docker, Postgres, or staging.

## Default launch baselines

The checked-in defaults are the prelaunch capacity targets for one
Identity deployment before user volume ramps:

| Scenario | Default duration | Default target | Thresholds |
| --- | --- | --- | --- |
| `login_steady` | `30m` | `60` `PasswordLogin` requests/s | login `p95 < 300ms`, login `p99 < 450ms`, login error rate `< 0.5%` |
| `refresh_steady` | `30m` | `180` `RefreshToken` requests/s | refresh `p95 < 250ms`, refresh `p99 < 350ms`, refresh error rate `< 0.5%` |
| `signup_burst` | `5m` | `48` `PasswordSignup` requests/s in `6`-request collision batches | signup `p95 < 450ms`, signup `p99 < 750ms`, signup error rate `< 1%`, `duplicate_user_violations == 0` |
| `mixed_workload` | `60m` | `100` total requests/s | overall error rate `< 1%`, signup `p99 < 800ms`, login `p99 < 400ms`, refresh `p99 < 250ms`, logout `p99 < 250ms` |

The mixed workload uses a fixed production-shape ratio:

- `5%` signup
- `20%` login
- `60%` refresh
- `15%` logout

`signup_burst` deliberately races duplicate signups for the same email in
concurrent `http.batch()` calls. It treats the run as failed if more
than one authenticated user ID appears for a collision set.

## Local prerequisites

- Docker with support for `--add-host=host.docker.internal:host-gateway`
- a reachable Identity instance
- a real shared backend if you want meaningful persistence behavior

## Local example

Start Postgres:

```bash
docker compose up -d postgres
```

Start Identity in another shell:

```bash
GATEWAY_REPO_DRIVER=postgres \
GATEWAY_POSTGRES_DSN=postgres://identity:secret@localhost:5432/identity \
GATEWAY_DEFAULT_PROJECT_ID=loadtest \
GATEWAY_CONNECT_PORT=18080 \
GATEWAY_METRICS_PORT=19090 \
GATEWAY_APP_BASE_URL=http://localhost:18080 \
go run ./cmd/identity
```

Run a short local smoke pass for each scenario:

```bash
BASE_URL=http://host.docker.internal:18080 \
RESULT_PREFIX=local-postgres \
TARGET_QPS=6 \
DURATION=30s \
USERS=48 \
./tests/load/run.sh login_steady

BASE_URL=http://host.docker.internal:18080 \
RESULT_PREFIX=local-postgres \
TARGET_QPS=18 \
DURATION=30s \
USERS=48 \
VUS=12 \
./tests/load/run.sh refresh_steady

BASE_URL=http://host.docker.internal:18080 \
RESULT_PREFIX=local-postgres \
TARGET_QPS=12 \
DURATION=30s \
BATCH_SIZE=4 \
./tests/load/run.sh signup_burst

BASE_URL=http://host.docker.internal:18080 \
RESULT_PREFIX=local-postgres \
TARGET_QPS=20 \
DURATION=30s \
USERS=64 \
VUS=16 \
./tests/load/run.sh mixed_workload
```

On Linux, `run.sh` injects `host.docker.internal` through Docker's
`host-gateway` mapping. If that still does not resolve in your setup,
point `BASE_URL` at a routable address for the service.

## CI and nightly hot-path test

The in-process Go runner is build-tagged so normal unit and integration
test runs do not spend time on load work.

Short CI profile:

```bash
go test -tags=load -count=1 -timeout=120s ./tests/load/...
```

Nightly soak profile:

```bash
IDENTITY_LOAD_PROFILE=soak \
go test -tags=load -count=1 -timeout=40m ./tests/load/...
```

The `ci` profile defaults to an 8-second run at `20` logins/s and `60`
refreshes/s. The `soak` profile defaults to a 30-minute run at the launch
baseline of `60` logins/s and `180` refreshes/s.

The Go runner accepts these overrides:

| Variable | Meaning |
| --- | --- |
| `IDENTITY_LOAD_PROFILE` | `ci` or `soak` default profile |
| `IDENTITY_LOAD_DURATION` | Go duration for the hot-path run |
| `IDENTITY_LOAD_USERS` | Seeded user count |
| `IDENTITY_LOAD_LOGIN_RPS` | Login request rate |
| `IDENTITY_LOAD_REFRESH_RPS` | Refresh request rate |
| `IDENTITY_LOAD_WORKERS` | Concurrent refresh-token rotation lanes |
| `IDENTITY_LOAD_LOGIN_P99_MS` | Login p99 threshold |
| `IDENTITY_LOAD_REFRESH_P99_MS` | Refresh p99 threshold |
| `IDENTITY_LOAD_MAX_ERROR_RATE` | Maximum allowed operation error rate |
| `IDENTITY_LOAD_MIN_COUNT_FACTOR` | Minimum completed operation count as a fraction of target arrivals |

`.github/workflows/load.yml` runs the same Go test and validates all k6
scenario syntax with the pinned k6 image. Manual dispatch runs the `ci`
profile by default; the scheduled nightly run uses `soak`.

## Staging runbook

The acceptance criterion for issue `#12` requires one real staging run
with captured results. Use the checked-in defaults unless staging
capacity is smaller than the launch target.

1. Deploy Identity against the staging backend you intend to launch.
2. Confirm the staging base URL and tenant.
3. Run each scenario with the default thresholds:

```bash
BASE_URL=https://identity-staging.example.com \
RESULT_PREFIX=staging \
./tests/load/run.sh login_steady

BASE_URL=https://identity-staging.example.com \
RESULT_PREFIX=staging \
./tests/load/run.sh refresh_steady

BASE_URL=https://identity-staging.example.com \
RESULT_PREFIX=staging \
./tests/load/run.sh signup_burst

BASE_URL=https://identity-staging.example.com \
RESULT_PREFIX=staging \
./tests/load/run.sh mixed_workload
```

4. Archive the resulting `tests/load/results/staging-*.txt` and
   `tests/load/results/staging-*.json` files with the launch checklist.
5. Review service metrics during the run:
   - request latency tails for `PasswordLogin` and `RefreshToken`
   - DB connection-pool saturation
   - heap growth and GC pause time
   - error spikes during any deliberate backend failover or stall test

## Tunables

`run.sh` forwards the following environment variables:

| Variable | Meaning |
| --- | --- |
| `BASE_URL` | Identity base URL seen by k6 |
| `USERS` | Number of seeded accounts for scenarios that need them |
| `TARGET_QPS` | Per-scenario request-rate target |
| `DURATION` | Main scenario duration |
| `PREALLOCATED_VUS` / `MAX_VUS` | VU pool for arrival-rate scenarios |
| `SLEEP_SECONDS` | Think-time between iterations in closed-loop scenarios |
| `CLEANUP_LOGOUT` | Whether `login_steady` logs out each new session immediately |
| `BATCH_SIZE` | Concurrent duplicate-signup requests per burst iteration |
| `SIGNUP_WEIGHT` / `LOGIN_WEIGHT` / `REFRESH_WEIGHT` / `LOGOUT_WEIGHT` | `mixed_workload` traffic shape |
| `RESULT_PREFIX` | Output filename prefix |
| `K6_IMAGE` | Exact k6 image tag |

## Result files

- `*.txt` is the captured k6 console summary
- `*.json` is the machine-readable k6 summary export
- `tests/load/results/` is intentionally ignored in git; keep local
  smoke runs and staging artifacts out of the source tree history

## Remaining launch artifact

The repo contains the deterministic hot-path runner, k6 staging harness,
and explicit targets. The remaining acceptance item that cannot be
solved purely in-repo is a real staging soak run with captured artifacts.
