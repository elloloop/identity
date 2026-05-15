# Identity — server hardening: parallel work plan

This document is a parallel-work plan for finishing the identity-server
hardening backlog. identity is an OSS server (Docker image + Go binary)
that deployers run as a backend in their own systems; this backlog is
what's left before they can run it in production with confidence. It is
written so multiple agents (or humans) can pick up independent slices
in parallel without stepping on each other.

Each item below points at exactly one GitHub issue, names the files
the work touches, lists what blocks it, and gives concrete
acceptance criteria. Pick any unblocked item; treat the issue as the
source of truth for design details.

Companion docs:
- [`docs/IDENTITY.md`](IDENTITY.md) — what the service *is*. Read this first.
- [`AGENTS.md`](../AGENTS.md) — *how* to write code in this repo.

---

## Status at a glance

Latest released: **v0.6.10** (2026-05-14).

Operational hardening from the original review is **shipped**. The
architectural items — substantial implementations of the server's
remaining surface — are what remains.

| Issue | Title | Severity | Blocked by | Effort | Lane |
|---|---|---|---|---|---|
| **#90** | C4: JWT signing keys — pluggable signer (file/rotation default) | CRITICAL | — | 1–3 days | A |
| **#91** | H2: refresh-token revocation — both models, config-driven | HIGH | — | 2–4 days | A |
| **#92** | H7: CI conformance matrix | HIGH | — | 2–3 days | A |
| **#93** | H9: implement \`mode=multi\` | HIGH | — | 1–2 weeks | B |
| **#94** | M3: GC sweeper | MEDIUM | #82 for entdb-side | 3–5 days | C |
| **#95** | M8: OpenTelemetry + RED | MEDIUM | — | 3–5 days | A |
| **#82** | v1.12 migration | (PR draft) | upstream #508 | 1 day post-unblock | D |
| **#14** | QR session CAS | HIGH | #82 | 1–2 days post-#82 | D |
| **#24** | Refresh-token CAS | HIGH | #82 | 1–2 days post-#82 | D |
| **#84** | Nightly: concurrent refresh test | open | #24 | follows #24 | D |

**"Lanes"** group items that can be worked in parallel without conflicting.

---

## Lanes (parallelism map)

These lanes are designed so two agents picking different lanes will
not touch the same files. An agent should pick one lane and run it to
completion before switching.

### Lane A — observability + security infrastructure

Items that touch shared infrastructure files (config, middleware,
top-level wiring) but do so in narrow, well-defined places. Sequence
them within the lane because they all touch `internal/app/app.go` and
`internal/config/config.go`.

- **#95 (M8 OpenTelemetry)** — biggest infrastructure touch. Land first.
- **#90 (C4 JWT signer)** — pluggable signer + file/rotation default,
  KMS as optional plugin. Orthogonal to #95 but touches the same
  `internal/app/app.go` wiring. Land after #95 to avoid rebase pain.
- **#91 (H2 refresh-token revocation)** — both models, config-driven.
  Adds a request middleware similar to OTel's. Land after #95.
- **#92 (H7 CI conformance matrix)** — touches `.github/workflows/`
  only. Can be parallel with any of the above.

### Lane B — multi-tenant mode (#93)

The biggest single item. Touches almost everything: a new RPC,
middleware for per-request tenant resolution, every handler's tenant
scoping, schema additions for the `Organization` type, a tenant-aware
invitation flow.

**One agent owns this end-to-end.** Trying to split it across agents
will produce merge conflicts at the per-request-tenant-resolution
layer.

When this lane lands, it will likely conflict with Lane A's middleware
changes; sequence accordingly or plan a coordinated merge.

### Lane C — garbage collection (#94)

The Postgres-backend portion can land **today, independently** — it
only touches `internal/repo/postgres/` and `internal/app/`. The
EntDB-backend portion waits on Lane D.

This lane is good for an agent that wants a self-contained 3–5-day
piece of work without coordinating with anyone else.

### Lane D — v1.12 migration + CAS (sequential)

- **#82** unblocks only when upstream #508 closes (tracked via a
  background monitor on this session).
- Once #82 lands: **#24** (refresh-token CAS) and **#14** (QR session
  CAS) can be worked in parallel — they touch different repo methods.
- **#84** closes automatically once #24 ships.

An agent can pick this lane up the moment #82 unblocks. Until then it
is idle.

---

## What "100% done" looks like

All ten issues above closed, all PRs merged, all referenced features
covered by tests, and `docs/IDENTITY.md`'s decision log updated for
any architectural choices made along the way.

At that point the server supports both product shapes from
`docs/IDENTITY.md` (B2C single-tenant and B2B multi-tenant), has
production-grade observability, a pluggable JWT signer with key
rotation, both refresh-token revocation models available config-driven,
server-side CAS for the single-use token paths, and a sweep loop that
prevents unbounded table growth.

---

## How to pick up an item

1. **Read `docs/IDENTITY.md`** so you understand the service charter.
2. **Read this file** to pick a lane.
3. **Open the issue** linked next to your chosen item. The issue
   carries the full design — file paths to touch, acceptance
   criteria, expected tests.
4. **Branch off `main`.** Name the branch after the issue:
   `feat/idv-multitenant`, `feat/otel-traces`, `feat/jwt-kms`, etc.
5. **Land one PR per issue.** Don't bundle. See
   [AGENTS.md rule 6 — no half-finished implementations](../AGENTS.md).
6. **Update the decision log in `docs/IDENTITY.md`** if your work
   makes an architectural decision (signer-interface shape, revocation
   contract, sweeper cadence, etc.).
7. **Close the issue** as part of the merging PR (`closes #N`).

---

## Coordination guarantees between lanes

- **Lane A and Lane B will conflict** at the middleware layer
  (correlation-id middleware vs. per-request tenant-resolution
  middleware). Whichever lands first wins; the other rebases.
- **Lane C is conflict-free** with A and B (touches a non-overlapping
  set of files).
- **Lane D is conflict-free** with A, B, and C until the CAS work
  edits `internal/repo/entdb/repo.go`'s refresh-token and QR-session
  methods. If Lane B touched those methods first (e.g., to attach a
  tenant id to QR sessions), Lane D will need a small rebase.

---

## When this plan is wrong

This plan reflects the state of the backlog as of v0.6.10. If you find:

- An item whose linked issue has already been closed → mark it done here.
- A new item not in the table → add it with the same shape.
- A blocker that was wrong → update the table.

Update this file in the same PR as the work. The plan must stay in
sync with the issues it references; if the two disagree, agents will
make wrong picks.
