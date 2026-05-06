#!/usr/bin/env bash
#
# coverage-gate.sh — fail CI if per-package-tree coverage drops below a threshold.
#
# Usage:
#   coverage-gate.sh <profile> <threshold> <prefix> [<prefix>...]
#
# Example:
#   coverage-gate.sh cover.out 80 internal/ pkg/
#
# Reads `go tool cover -func=<profile>` and computes the weighted statement
# coverage for every package whose import path contains any of the given
# prefixes. Exits non-zero if any of the prefixes ends up below <threshold>.
#
# The script is intentionally dependency-free — only awk + go tool cover.

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <profile> <threshold> <prefix> [<prefix>...]" >&2
  exit 2
fi

PROFILE="$1"; shift
THRESHOLD="$1"; shift
PREFIXES=("$@")

if [[ ! -f "$PROFILE" ]]; then
  echo "coverage-gate: profile not found: $PROFILE" >&2
  exit 2
fi

# Per-package weighted coverage: parse the raw profile so we get statement
# counts (the `-func` summary already aggregates by func and rounds %, which
# loses the weights we need).
#
# Profile format (after the mode line):
#   <file>:<startLine>.<startCol>,<endLine>.<endCol> <numStmts> <count>
#
# A statement is "covered" if count > 0. Package = dirname(file).
#
# When `go test ./... -coverpkg=./...` runs, each package's test instruments
# the full union and writes a profile section into the same file. The same
# (file, range) entry then appears once per tested package — typically 15-20×.
# We dedupe by composite key and treat a line as covered if ANY appearance
# has count > 0; otherwise the denominator is inflated by the duplication
# factor and the gate reports a fraction of true coverage.

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Skip the first line (mode: ...) and emit "<pkg> <stmts> <covered>".
awk 'NR > 1 {
  key = $1
  stmts[key] = $2            # numStmts is identical across appearances
  if ($3 > 0) hit[key] = 1
}
END {
  for (k in stmts) {
    n = split(k, a, ":")
    file = a[1]
    m = split(file, p, "/")
    pkg = p[1]
    for (i = 2; i < m; i++) pkg = pkg "/" p[i]
    s[pkg] += stmts[k]
    if (k in hit) c[pkg] += stmts[k]
  }
  for (k in s) printf "%s %d %d\n", k, s[k], c[k]+0
}' "$PROFILE" > "$tmp"

fail=0
for prefix in "${PREFIXES[@]}"; do
  total=0; covered=0
  while read -r pkg stmts cov; do
    case "$pkg" in
      *"$prefix"*) total=$((total + stmts)); covered=$((covered + cov)) ;;
    esac
  done < "$tmp"

  if [[ $total -eq 0 ]]; then
    echo "coverage-gate: no statements found for prefix '$prefix' — skipping"
    continue
  fi

  pct=$(awk -v c="$covered" -v t="$total" 'BEGIN { printf "%.2f", (c/t)*100 }')
  cmp=$(awk -v p="$pct" -v th="$THRESHOLD" 'BEGIN { print (p+0 < th+0) ? "fail" : "ok" }')
  if [[ "$cmp" == "fail" ]]; then
    echo "coverage-gate: FAIL  $prefix  $pct% < $THRESHOLD% ($covered/$total stmts)"
    fail=1
  else
    echo "coverage-gate: ok    $prefix  $pct% >= $THRESHOLD% ($covered/$total stmts)"
  fi
done

exit "$fail"
