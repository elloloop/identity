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
# substring match after the text and each term are folded the same way:
# invisible characters (soft hyphen U+00AD, Mongolian vowel separator
# U+180E, zero-width space, non-joiner and joiner U+200B-U+200D, word joiner
# U+2060, byte order mark U+FEFF) are dropped, '-', '_' and
# '.' count as whitespace, and every run of whitespace becomes one space.
# So "acme-widgets", "ACME_Widgets", "acme.widgets" and "acme\n widgets"
# all match the term "acme widgets", and a term split across lines, spelled
# with another separator, or broken by an invisible character still
# matches. Blank lines and CR line endings in the list are ignored.
#
# The script never prints a term, nor the text that matched one. Under
# GitHub Actions (GITHUB_ACTIONS=true) it first registers every term with
# ::add-mask::, as written and as folded, so no later output in the job can
# show one either.
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
masks="$(mktemp)"
text="$(mktemp)"
trap 'rm -f "$terms" "$masks" "$text"' EXIT

# fold drops the invisible characters, turns the separators into spaces and
# collapses whitespace. It works on bytes (LC_ALL=C) so the octal escapes
# name the UTF-8 encodings on any awk: U+00AD, U+180E, U+200B-U+200D,
# U+2060 and U+FEFF, in that order.
fold='{ gsub(/\302\255|\341\240\216|\342\200[\213\214\215]|\342\201\240|\357\273\277/, ""); gsub(/[-_.]/, " "); gsub(/[[:space:]]+/, " ") }'

# One folded term per line, ends trimmed, blank lines dropped (an empty
# pattern would match every text). The masks get each term as written too:
# that is the spelling a log line would carry.
printf '%s\n' "${CONFIDENTIAL_TERMS-}" | LC_ALL=C awk -v terms="$terms" -v masks="$masks" '
  { written = $0; gsub(/[[:space:]]+/, " ", written); sub(/^ /, "", written); sub(/ $/, "", written) }
  '"$fold"'
  { sub(/^ /, ""); sub(/ $/, "") }
  length($0) > 0 {
    print > terms
    if (!seen[written]++) print written > masks
    if (!seen[$0]++) print > masks
  }
'

if [[ ! -s "$terms" ]]; then
  echo "disclosure-check: no confidential terms configured" >&2
  exit 3
fi

if [[ "${GITHUB_ACTIONS-}" == "true" ]]; then
  while IFS= read -r term; do
    echo "::add-mask::${term}"
  done < "$masks"
fi

# The whole text on one line, folded like the terms. It goes through a
# file rather than a pipe: grep -q stops reading at the first match, and
# under pipefail the writer's SIGPIPE would mask that match.
LC_ALL=C awk "$fold"' { print }' | tr -s '[:space:]' ' ' > "$text"
status=0
grep -qiF -f "$terms" "$text" || status=$?

case "$status" in
  0) echo "disclosure-check: a confidential term was found" >&2; exit 1 ;;
  1) exit 0 ;;
  *) echo "disclosure-check: matching failed" >&2; exit 2 ;;
esac
