#!/usr/bin/env bash
#
# check-entdb-image-version.sh — guard against entdb SDK / server-image drift.
#
# The repo talks to tenant-shard-db through the Go SDK pinned in go.mod
# (github.com/elloloop/tenant-shard-db/sdk/go/entdb/vN) and runs the matching
# SERVER as a container image pinned in CI workflows + docker-compose. If the
# SDK is bumped (e.g. by Dependabot) without bumping the server image, CI runs
# a new client against an OLD server and silently fails to exercise the new
# server-side behaviour (see #180: the v2.4.x actor-privilege change was not
# caught because CI still pinned a 2.0.x server).
#
# This script fails if any pinned server image's major.minor is LOWER than the
# SDK's major.minor. Equal or higher is fine (a newer server is backward
# compatible; the floor is what matters). It is dependency-free (grep + awk).

set -euo pipefail

cd "$(dirname "$0")/.."

# ── SDK version from go.mod ──────────────────────────────────────────────
sdk_line="$(grep -E 'tenant-shard-db/sdk/go/entdb/v[0-9]+ v[0-9]' go.mod | head -1)"
if [[ -z "$sdk_line" ]]; then
  echo "check-entdb-image: could not find the entdb SDK require line in go.mod" >&2
  exit 2
fi
# e.g. "... entdb/v2 v2.5.0" -> "2.5"
sdk_mm="$(echo "$sdk_line" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed -E 's/^v([0-9]+)\.([0-9]+)\..*/\1.\2/')"
if [[ -z "$sdk_mm" ]]; then
  echo "check-entdb-image: could not parse SDK version from: $sdk_line" >&2
  exit 2
fi

sdk_major="${sdk_mm%.*}"
sdk_minor="${sdk_mm#*.}"

# ── Every pinned server image ────────────────────────────────────────────
# Search the files that pin the server image. Keep this list in sync with
# where the image is referenced.
files=(
  .github/workflows/ci.yml
  .github/workflows/conformance.yml
  .github/workflows/release.yml
  .github/workflows/nightly.yml
  docker-compose.yml
)

fail=0
checked=0
for f in "${files[@]}"; do
  [[ -f "$f" ]] || continue
  while IFS= read -r ver; do
    checked=$((checked + 1))
    img_major="$(echo "$ver" | cut -d. -f1)"
    img_minor="$(echo "$ver" | cut -d. -f2)"
    if (( img_major < sdk_major )) || { (( img_major == sdk_major )) && (( img_minor < sdk_minor )); }; then
      echo "check-entdb-image: FAIL  $f pins server image $ver but SDK is $sdk_mm.x — the server image must be >= the SDK major.minor"
      fail=1
    fi
  done < <(grep -oE 'tenant-shard-db:[0-9]+\.[0-9]+\.[0-9]+' "$f" | sed -E 's/.*:([0-9]+\.[0-9]+)\..*/\1/')
done

if [[ $checked -eq 0 ]]; then
  echo "check-entdb-image: no server-image pins found — nothing to check" >&2
  exit 2
fi

if [[ $fail -eq 0 ]]; then
  echo "check-entdb-image: ok  SDK $sdk_mm.x; all $checked server-image pin(s) >= $sdk_mm"
fi
exit "$fail"
