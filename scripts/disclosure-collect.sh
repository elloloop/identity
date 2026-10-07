#!/usr/bin/env bash
#
# disclosure-collect.sh — print the text the Disclosure check matches for
# one GitHub event (AGENTS.md §13). The output goes to disclosure-check.sh.
#
# Usage:
#   GITHUB_EVENT_PATH=event.json GH_REPO=owner/repo disclosure-collect.sh <kind>
#
# kind is one of:
#   pr              title, description, branch name; then, for every commit,
#                   its message and each changed file's name and added lines
#   merge-group     the same for every commit the merge queue is about to land
#   issue           title and description
#   comment         an issue or PR conversation comment
#   review          a PR review's body
#   review-comment  an inline PR review comment
#
# Everything is read as data: the event through jq, the rest through
# `gh api`. Nothing from the event is ever run.
#
# Commits are read one by one rather than as the PR's net diff, so a term
# added in one commit and removed in a later one is still found: the earlier
# commit stays public under refs/pull/<n>/head. A file the API returns no
# patch for (binary, or too large to diff) is read whole at that commit
# instead of being skipped.
#
# Only text from the project's own people (OWNER, MEMBER, COLLABORATOR) is
# collected. The threat is a maintainer's own accidental leak; checking
# anyone else's text would let them confirm guesses against the secret term
# list one public check at a time. Outside contributions are covered by the
# maintainer-run review gate (§11), and by the merge-group check, which a
# maintainer triggers and which reads every commit whoever wrote it.
#
# Exit status:
#   0  the text is on stdout
#   2  bad usage or a failed read
#   4  not collected: the author is outside the project (stdout empty)
#   5  not collected: the PR is past what the API lists (stdout empty)
#
# Needs bash, jq, gh and tr.

set -euo pipefail

# The pull request commits API lists at most 250 commits, and a PR's file
# list stops at 3000 files; past either, part of the PR would go unread.
readonly max_commits=250
readonly max_files=3000

die() {
  echo "disclosure-collect: $*" >&2
  exit 2
}

[[ $# -eq 1 ]] || die "usage: disclosure-collect.sh <pr|merge-group|issue|comment|review|review-comment>"
kind="$1"
event="${GITHUB_EVENT_PATH:?GITHUB_EVENT_PATH is not set}"

ev() { jq -r "$1" "$event"; }

# require_insider exits 4 unless the association at $1 in the event is the
# project's own.
require_insider() {
  case "$(ev "$1 // \"\"")" in
    OWNER | MEMBER | COLLABORATOR) ;;
    *)
      echo "disclosure-collect: not checked, the author is outside the project" >&2
      exit 4
      ;;
  esac
}

# commits_text prints, for the commits listed (as {sha, message} objects) on
# stdin: every message, then each commit's changed file names and added
# lines, and the whole content, at that commit, of each file the API gives
# no patch for.
commits_text() {
  local repo="${GH_REPO:?GH_REPO is not set}" commits files sha path
  commits="$(cat)"
  jq -r '.message' <<<"$commits"
  for sha in $(jq -r '.sha' <<<"$commits"); do
    files="$(gh api "repos/$repo/commits/$sha" --paginate --jq '.files[]')"
    # The files API patch starts at the first "@@" hunk: it has no "+++"
    # file header, so every line that starts with "+" is an added line.
    jq -r '.filename, ((.patch // "") | split("\n")[] | select(startswith("+")) | .[1:])' <<<"$files"
    while IFS= read -r path; do
      [[ -n "$path" ]] || continue
      path="$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')"
      # NULs would cut the matcher's lines short; nothing in them is text.
      gh api -H "Accept: application/vnd.github.raw" "repos/$repo/contents/$path?ref=$sha" | tr -d '\000'
      echo
    done <<<"$(jq -r 'select(.patch == null and .status != "removed") | .filename' <<<"$files")"
  done
}

case "$kind" in
  pr)
    require_insider '.pull_request.author_association'
    commits="$(ev '.pull_request.commits // 0')"
    files="$(ev '.pull_request.changed_files // 0')"
    if ((commits > max_commits || files > max_files)); then
      echo "disclosure-collect: the PR has $commits commits and $files changed files; the API lists at most $max_commits and $max_files" >&2
      exit 5
    fi
    ev '.pull_request | .title, (.body // ""), .head.ref'
    listed="$(gh api "repos/${GH_REPO:?GH_REPO is not set}/pulls/$(ev '.pull_request.number')/commits" \
      --paginate --jq '.[] | {sha, message: .commit.message}')"
    commits_text <<<"$listed"
    ;;
  merge-group)
    # Only a maintainer can queue a PR, so the queue's run is never an
    # outsider's oracle: it reads every commit, whoever wrote it.
    range="$(ev '.merge_group | "\(.base_sha)...\(.head_sha)"')"
    listed="$(gh api "repos/${GH_REPO:?GH_REPO is not set}/compare/$range" \
      --paginate --jq '.commits[] | {sha, message: .commit.message}')"
    commits_text <<<"$listed"
    ;;
  issue)
    require_insider '.issue.author_association'
    ev '.issue | .title, (.body // "")'
    ;;
  comment | review-comment)
    require_insider '.comment.author_association'
    ev '.comment.body // ""'
    ;;
  review)
    require_insider '.review.author_association'
    ev '.review.body // ""'
    ;;
  *)
    die "unknown kind $kind"
    ;;
esac
