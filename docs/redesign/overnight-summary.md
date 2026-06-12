# Overnight run — summary (autonomous loop)

_Status: **shipped.** All foundation PRs merged to `main`; `v0.15.0` cut._

## ✅ Merged to `main`

Bottom-up stack + the independent migrate PR — all squash-merged, all CI-green
(coverage gates included).

| PR | Slice | What landed | Verified |
|---|---|---|---|
| **#196** | Foundation | schema + ADRs `0001–0003` + migration `0013` (new control-plane & per-project tables, additive) | real Postgres |
| **#195** | Migrate | `identity migrate` subcommand (idempotent, advisory-locked) + DB-migrations doc | build/lint/tests |
| **#197** | ProjectStore | Postgres control-plane store (projects / credentials / auth-domains; resolve by key + Host) | real Postgres, `internal/ 84.93%` |
| **#198** | EnsureDefaultProject | idempotent, race-safe default-project bootstrap (8-racer convergence test) | real Postgres, `internal/ 84.92%` |

### Coverage note (resolved mid-run)
`project_store.go` was first covered only by `//go:build dockerpostgres`
container tests, which CI's coverage job never runs — it dropped `internal/`
to 83.85% and tripped the 84% gate. Fixed by mirroring the existing
`runRepositorySmoke` split: an untagged `*_Smoke` test driven by
`GATEWAY_TEST_POSTGRES_DSN` (the path CI counts) sharing one body with the
container test, plus extending `truncateAll` to the new tables. Both #197 and
#198 carry this. `internal/` back to ~84.9% with margin.

## 🚀 Release `v0.15.0`

Annotated tag `v0.15.0` → `main@3ad6cb3`, pushed to trigger `release.yml`
(re-runs every gate, builds + cosign-signs the image, attaches the proto
bundle, creates the GitHub release). Notes summarise #195–#198 and flag the
storage inversion as the next, human-reviewed step. Everything in the release
is **additive** — no serving-path change, no breaking change.

## Remaining plan (after this release)
- **Slice 2b** — `GATEWAY_DEFAULT_PROJECT_ID` config + the `app.New` boot call
  invoking `EnsureDefaultProject` (the store exists but nothing calls it yet).
- **Slices 3–9** — project resolution by key + Host, public-domain blocklist,
  tenants/domains auto-formation, login policy, membership/invitations, drop
  Organization.
- **Slice 10 (storage inversion) is HUMAN-REVIEWED ONLY** — an irreversible
  live-data migration. Never run autonomously.

## Non-blocking follow-ups (fold into a later slice)
- #197: `columnsPrefixed` vs `userColumnsPrefixed` DRY; dockertest container-helper DRY.
- The defensive re-read-error branches in `EnsureDefaultProject` and the
  `wrapPgErr` paths on the `Get*` methods remain uncovered (hard to force
  deterministically; consistent with the rest of the postgres package).

_Updated after `v0.15.0` was cut._
