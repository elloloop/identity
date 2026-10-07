#!/usr/bin/env bash
#
# disclosure-check.sh — does the text on stdin contain a confidential term?
#
# Usage:
#   CONFIDENTIAL_TERMS=$'term one\nterm two' disclosure-check.sh < text
#
# The terms come from CONFIDENTIAL_TERMS, one per line. In CI that is the
# repository secret of the same name, so the list never lives in the
# repository (AGENTS.md §13). Matching is a case-insensitive, literal
# substring match after every run of whitespace — in the text and in each
# term — is collapsed to one space, so a term split across lines or spaced
# differently still matches. Blank lines and CR line endings in the list
# are ignored.
#
# The script never prints a term, nor the text that matched one. Under
# GitHub Actions (GITHUB_ACTIONS=true) it first registers every term with
# ::add-mask::, so no later output in the job can show one either.
#
# Exit status:
#   0  no term found (or empty text)
#   1  a term was found
#   2  the match itself failed
#   3  no terms are configured
#
# Dependency-free: awk, tr and grep.

set -euo pipefail

terms="$(mktemp)"
text="$(mktemp)"
trap 'rm -f "$terms" "$text"' EXIT

# One normalized term per line: whitespace runs collapsed, ends trimmed,
# blank lines dropped (an empty pattern would match every text).
printf '%s\n' "${CONFIDENTIAL_TERMS-}" | awk '
  { gsub(/[[:space:]]+/, " "); sub(/^ /, ""); sub(/ $/, "") }
  length($0) > 0 { print }
' > "$terms"

if [[ ! -s "$terms" ]]; then
  echo "disclosure-check: no confidential terms configured" >&2
  exit 3
fi

if [[ "${GITHUB_ACTIONS-}" == "true" ]]; then
  while IFS= read -r term; do
    echo "::add-mask::${term}"
  done < "$terms"
fi

# The whole text on one line, whitespace collapsed like the terms. It goes
# through a file rather than a pipe: grep -q stops reading at the first
# match, and under pipefail the writer's SIGPIPE would mask that match.
tr -s '[:space:]' ' ' > "$text"
status=0
grep -qiF -f "$terms" "$text" || status=$?

case "$status" in
  0) echo "disclosure-check: a confidential term was found" >&2; exit 1 ;;
  1) exit 0 ;;
  *) echo "disclosure-check: matching failed" >&2; exit 2 ;;
esac
