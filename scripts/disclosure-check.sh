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
# substring match after the text and each term are folded the same way
# (fold, below, lists the characters): invisible characters are dropped,
# Unicode spaces and dashes and '-', '_' and '.' count as whitespace, and
# every run of whitespace becomes one space. So "acme-widgets",
# "ACME_Widgets", "acme.widgets" and "acme\n widgets" all match the term
# "acme widgets", and a term split across lines, spelled with another
# separator, or broken by an invisible character still matches. Blank lines
# and CR line endings in the list are ignored.
#
# A term's leading and trailing separators fold away with its edge spaces:
# ".internal" is matched as "internal", wherever that word appears. The
# script warns on stderr when that happens, naming the term by its place in
# the list, never by its text.
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

# fold drops the invisible characters, turns the Unicode spaces and dashes
# and '-', '_' and '.' into spaces, and collapses whitespace. It works on
# bytes (LC_ALL=C), so the octal escapes name UTF-8 encodings on any awk.
#   dropped: U+00AD soft hyphen, U+180E Mongolian vowel separator,
#     U+200B-U+200F zero-width and direction marks, U+202A-U+202E and
#     U+2066-U+2069 bidi controls, U+2060 word joiner, U+FEFF BOM
#   spaces: U+00A0, U+2000-U+200A, U+202F, U+205F, U+3000
#   dashes: U+2010-U+2015, U+2212
invisible='\302\255|\341\240\216|\342\200[\213\214\215\216\217\252\253\254\255\256]|\342\201[\240\246\247\250\251]|\357\273\277'
spacing='\302\240|\342\200[\200\201\202\203\204\205\206\207\210\211\212\220\221\222\223\224\225\257]|\342\201\237|\343\200\200|\342\210\222'
fold='{ gsub(/'"$invisible"'/, ""); gsub(/'"$spacing"'/, " "); gsub(/[-_.]/, " "); gsub(/[[:space:]]+/, " ") }'

# One folded term per line, ends trimmed, blank lines dropped (an empty
# pattern would match every text). The masks get each term as written too:
# that is the spelling a log line would carry.
printf '%s\n' "${CONFIDENTIAL_TERMS-}" | LC_ALL=C awk -v terms="$terms" -v masks="$masks" '
  { written = $0; gsub(/[[:space:]]+/, " ", written); sub(/^ /, "", written); sub(/ $/, "", written) }
  '"$fold"'
  { sub(/^ /, ""); sub(/ $/, "") }
  length($0) > 0 {
    n++
    if (written ~ /^[-_.]|[-_.]$/) {
      print "disclosure-check: term " n " starts or ends with a separator, which folding drops" > "/dev/stderr"
    }
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
LC_ALL=C awk "$fold"' { print }' | LC_ALL=C tr -s '[:space:]' ' ' > "$text"
status=0
grep -qiF -f "$terms" "$text" || status=$?

case "$status" in
  0) echo "disclosure-check: a confidential term was found" >&2; exit 1 ;;
  1) exit 0 ;;
  *) echo "disclosure-check: matching failed" >&2; exit 2 ;;
esac
