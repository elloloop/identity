#!/usr/bin/env bash
#
# check-entdb-image-version.sh — guard against entdb SDK / server-image drift.
#
# The repo talks to tenant-shard-db through the Go SDK pinned in go.mod
# (github.com/elloloop/tenant-shard-db/sdk/go/entdb/vN) and runs the matching
# SERVER as a container image pinned in CI workflows, docker-compose, and the
# install docs. If the SDK is bumped (e.g. by Dependabot) without bumping the
# server image, CI runs a new client against an OLD server and silently fails
# to exercise the new server-side behaviour (see #180: the v2.4.x
# actor-privilege change was not caught because CI still pinned a 2.0.x server).
#
# This script SELF-DISCOVERS every pinned server image (so a new pin site can
# never escape the guard by being left off a hardcoded list) and fails if any
# pin's MAJOR differs from the SDK's, or its minor is below the SDK's. A newer
# patch is fine (the floor is what matters); a different major is where
# client/server incompatibility is most likely, so it is rejected. Dependency-
# free: git grep + POSIX text utilities + bash arithmetic.

set -euo pipefail

cd "$(dirname "$0")/.."

# ── SDK version from go.mod ──────────────────────────────────────────────
sdk_line="$(grep -E 'tenant-shard-db/sdk/go/entdb/v[0-9]+ v[0-9]' go.mod | head -1)"
if [[ -z "$sdk_line" ]]; then
  echo "check-entdb-image: could not find the entdb SDK require line in go.mod" >&2
  exit 2
fi
sdk_ver="$(echo "$sdk_line" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed -E 's/^v//')"
if [[ -z "$sdk_ver" ]]; then
  echo "check-entdb-image: could not parse SDK version from: $sdk_line" >&2
  exit 2
fi
sdk_major="$((10#${sdk_ver%%.*}))"
sdk_rest="${sdk_ver#*.}"
sdk_minor="$((10#${sdk_rest%%.*}))"

# ── Self-discover every pinned server image across tracked files ─────────
# git grep restricts to tracked files (so vendored/build junk is ignored).
mapfile -t pins < <(git grep -hoE 'tenant-shard-db:[0-9]+\.[0-9]+\.[0-9]+' -- \
  ':!scripts/check-entdb-image-version.sh' | sed -E 's/.*://' | sort -u)

if [[ ${#pins[@]} -eq 0 ]]; then
  echo "check-entdb-image: no server-image pins found — nothing to check" >&2
  exit 2
fi

fail=0
for ver in "${pins[@]}"; do
  img_major="$((10#${ver%%.*}))"
  img_rest="${ver#*.}"
  img_minor="$((10#${img_rest%%.*}))"
  if (( img_major != sdk_major )) || (( img_minor < sdk_minor )); then
    echo "check-entdb-image: FAIL  server image pinned at $ver but SDK is $sdk_ver — the server image must be the same major and minor >= the SDK's ($sdk_major.$sdk_minor.x)"
    # Show where, to make the fix obvious.
    git grep -nE "tenant-shard-db:${ver//./\\.}" -- ':!scripts/check-entdb-image-version.sh' | sed 's/^/  /'
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "check-entdb-image: ok  SDK $sdk_ver; all ${#pins[@]} discovered server-image pin(s) match major $sdk_major and minor >= $sdk_minor"
fi
exit "$fail"
