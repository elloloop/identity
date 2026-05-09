#!/usr/bin/env bash

set -euo pipefail

rm -f cover.out cover.*.out

profiles=()
unit_coverpkg=./internal/...,./pkg/...,./cmd/...
tagged_coverpkg=./internal/...,./pkg/...

go test -count=1 -race -timeout=1200s \
  -coverprofile=cover.unit.out \
  -coverpkg="$unit_coverpkg" \
  ./...
profiles+=(cover.unit.out)

if [[ "${RUN_INTEGRATION_COVERAGE:-}" == "1" ]]; then
  go test -count=1 -tags=integration -race -timeout=180s \
    -coverprofile=cover.integration.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/...
  profiles+=(cover.integration.out)
fi

if [[ -n "${GATEWAY_ENTDB_ADDRESS:-}" ]]; then
  go test -count=1 -tags=realentdb -race -timeout=300s \
    -coverprofile=cover.realentdb.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/... ./internal/repo/entdb/...
  profiles+=(cover.realentdb.out)
fi

if [[ -n "${GATEWAY_POSTGRES_DSN:-}" ]]; then
  go test -count=1 -tags=realpostgres -race -timeout=300s \
    -coverprofile=cover.realpostgres.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/...
  profiles+=(cover.realpostgres.out)
fi

if [[ -n "${GATEWAY_TEST_POSTGRES_DSN:-}" ]]; then
  go test -count=1 -race -timeout=300s \
    -coverprofile=cover.postgres.out \
    -coverpkg="$tagged_coverpkg" \
    ./internal/repo/postgres/...
  profiles+=(cover.postgres.out)
fi

head -n 1 "${profiles[0]}" > cover.out
for profile in "${profiles[@]}"; do
  tail -n +2 "$profile" >> cover.out
done
