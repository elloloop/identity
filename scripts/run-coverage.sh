#!/usr/bin/env bash

set -euo pipefail

# COVERAGE_PART runs one part of the suite, so CI can run the parts in
# parallel and merge their profiles (scripts/merge-coverage.sh):
#   unit:<i>/<n>  the i-th of n round-robin shards of the unit packages
#   integration | e2e | realpostgres | postgres
# Unset, it runs every part in turn and writes the merged cover.out.
part="${COVERAGE_PART:-all}"
runs() { [[ "$part" == all || "$part" == "$1" ]]; }

rm -f cover.out cover.*.out

profiles=()
unit_coverpkg=./internal/...,./pkg/...,./cmd/...
tagged_coverpkg=./internal/...,./pkg/...

if [[ "$part" == all || "$part" == unit:* ]]; then
  unit_pkgs=(./...)
  unit_profile=cover.unit.out
  if [[ "$part" == unit:* ]]; then
    shard="${part#unit:}"
    index="${shard%/*}"
    count="${shard#*/}"
    mapfile -t unit_pkgs < <(go list ./... | awk -v i="$index" -v n="$count" '(NR - 1) % n == i - 1')
    unit_profile="cover.unit-$index.out"
  fi
  if [[ ${#unit_pkgs[@]} -gt 0 ]]; then
    go test -count=1 -race -timeout=1200s \
      -coverprofile="$unit_profile" \
      -coverpkg="$unit_coverpkg" \
      "${unit_pkgs[@]}"
    profiles+=("$unit_profile")
  fi
fi

if [[ "${RUN_INTEGRATION_COVERAGE:-}" == "1" ]] && runs integration; then
  go test -count=1 -tags=integration -race -timeout=180s \
    -coverprofile=cover.integration.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/...
  profiles+=(cover.integration.out)
fi

# E2E suite — drives the public HTTP/JSON wire format (no Connect-Go
# codegen import). Exercises the same handler chain as the container,
# in-process via httptest. Contributes coverage of internal/connect,
# internal/middleware, internal/app, internal/service, and
# internal/repo/memory.
#
# Timeout is 600s (not 180s): every test boots a full app.New and dials
# its own datastore connection, and the suite runs under -race. On a 2-core
# CI runner the whole-suite wall-clock is ~230s, so the old 180s budget
# timed out there even though the suite passes (~37s on a dev box). 600s
# matches the headroom the realpostgres suite already uses.
if [[ "${RUN_INTEGRATION_COVERAGE:-}" == "1" ]] && runs e2e; then
  go test -count=1 -tags=e2e -race -timeout=600s \
    -coverprofile=cover.e2e.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/e2e/...
  profiles+=(cover.e2e.out)
fi

if [[ -n "${GATEWAY_POSTGRES_DSN:-}" ]] && runs realpostgres; then
  go test -count=1 -tags=realpostgres -race -timeout=300s \
    -coverprofile=cover.realpostgres.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/...
  profiles+=(cover.realpostgres.out)
fi

if [[ -n "${GATEWAY_TEST_POSTGRES_DSN:-}" ]] && runs postgres; then
  go test -count=1 -race -timeout=300s \
    -coverprofile=cover.postgres.out \
    -coverpkg="$tagged_coverpkg" \
    ./internal/repo/postgres/...
  profiles+=(cover.postgres.out)
fi

if [[ "$part" == all ]]; then
  bash "$(dirname "$0")/merge-coverage.sh" cover.out "${profiles[@]}"
fi
