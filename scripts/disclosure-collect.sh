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
#   merge-group     the same for the commits the merge queue is about to land
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
# Only text from people with write access to the repository is collected.
# The threat is a maintainer's own accidental leak; checking anyone else's
# text would let them confirm guesses against the secret term list one
# public check at a time. Write access is read from the repository
# permission API, because the event's author_association shows org
# membership only when it is public. If that lookup fails, the author is
# checked anyway: an unreadable permission never skips the check.
#
# Outside contributions are covered by the maintainer-run review gate
# (§11). The merge queue squashes, so its run sees one squash commit per
# queued PR: it checks what lands on main (each PR's squash commit message
# and net diff), not an outside PR's description, branch name or
# intermediate commits.
#
# A review on a fork PR is never checked, whoever wrote it: GitHub gives a
# run triggered from a fork no secrets, so there is no term list to match.
#
# Exit status:
#   0   the text is on stdout
#   2   bad usage, or a read failed (the check must fail, not pass)
#   10  not collected: the author has no write access (stdout empty)
#   11  not collected: past what the API lists (stdout empty)
#   12  not collected: a review on a fork PR, which gets no secrets
#
# The statuses past 2 are ones jq and gh never return, so a tool failure
# cannot pass for one of them. Needs bash, jq, gh and tr.

set -euo pipefail

readonly outside=10 too_big=11 fork_review=12

# The pull request commits API lists at most 250 commits, and a commit's
# file list stops at 3000 files; at either cap, part of it may go unread.
readonly max_commits=250
readonly max_files=3000

die() {
  echo "disclosure-collect: $*" >&2
  exit 2
}

[[ $# -eq 1 ]] || die "usage: disclosure-collect.sh <pr|merge-group|issue|comment|review|review-comment>"
kind="$1"
event="${GITHUB_EVENT_PATH:?GITHUB_EVENT_PATH is not set}"
repo="${GH_REPO:?GH_REPO is not set}"

ev() { jq -r "$1" "$event" || die "could not read $1 from the event"; }

# require_writer exits $outside unless the author at $1 (the event object
# that carries .user.login and .author_association) can write to the
# repository. A public OWNER, MEMBER or COLLABORATOR association settles it
# without a call; otherwise the permission API decides.
require_writer() {
  local association login permission
  association="$(ev "$1.author_association // \"\"")"
  case "$association" in
    OWNER | MEMBER | COLLABORATOR) return ;;
  esac
  login="$(ev "$1.user.login // \"\" | @uri")"
  if ! permission="$(gh api "repos/$repo/collaborators/$login/permission" --jq .permission)"; then
    echo "disclosure-collect: could not read the author's permission; checking the text anyway" >&2
    return
  fi
  case "$permission" in
    admin | maintain | write) ;;
    *)
      echo "disclosure-collect: not checked, the author has no write access" >&2
      exit "$outside"
      ;;
  esac
}

# commits_text prints, for the commits listed (as {sha, message} objects) on
# stdin: every message, then each commit's changed file names and added
# lines, and the whole content, at that commit, of each file the API gives
# no patch for.
commits_text() {
  local commits shas files count patchless sha path
  commits="$(cat)"
  jq -r '.message' <<<"$commits" || die "could not read the commit messages"
  shas="$(jq -r '.sha' <<<"$commits")" || die "could not read the commit list"
  for sha in $shas; do
    files="$(gh api "repos/$repo/commits/$sha" --paginate --jq '.files[]')" || die "could not read commit $sha"
    count="$(jq -s 'length' <<<"$files")" || die "could not count the files of commit $sha"
    if ((count >= max_files)); then
      echo "disclosure-collect: commit $sha lists $count files, the API's cap; the rest would go unread" >&2
      exit "$too_big"
    fi
    # The files API patch starts at the first "@@" hunk: it has no "+++"
    # file header, so every line that starts with "+" is an added line.
    jq -r '.filename, ((.patch // "") | split("\n")[] | select(startswith("+")) | .[1:])' <<<"$files" ||
      die "could not read the files of commit $sha"
    patchless="$(jq -r 'select(.patch == null and .status != "removed") | .filename' <<<"$files")" ||
      die "could not read the files of commit $sha"
    while IFS= read -r path; do
      [[ -n "$path" ]] || continue
      path="$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')"
      # NULs would cut the matcher's lines short; nothing in them is text.
      gh api -H "Accept: application/vnd.github.raw" "repos/$repo/contents/$path?ref=$sha" | tr -d '\000' ||
        die "could not read $path at $sha"
      echo
    done <<<"$patchless"
  done
}

case "$kind" in
  pr)
    require_writer '.pull_request'
    commits="$(ev '.pull_request.commits // 0')"
    if ((commits > max_commits)); then
      echo "disclosure-collect: the PR has $commits commits; the API lists at most $max_commits" >&2
      exit "$too_big"
    fi
    ev '.pull_request | .title, (.body // ""), .head.ref'
    number="$(ev '.pull_request.number')"
    listed="$(gh api "repos/$repo/pulls/$number/commits" --paginate --jq '.[] | {sha, message: .commit.message}')" ||
      die "could not list the commits of PR $number"
    commits_text <<<"$listed"
    ;;
  merge-group)
    # Only a maintainer can queue a PR, so the queue's run is never an
    # outsider's oracle. The queue squashes: each queued PR is one commit.
    range="$(ev '.merge_group | "\(.base_sha)...\(.head_sha)"')"
    compared="$(gh api "repos/$repo/compare/$range" --paginate \
      --jq '{total: .total_commits, commits: [.commits[] | {sha, message: .commit.message}]}')" ||
      die "could not compare $range"
    total="$(jq -se 'first.total | numbers' <<<"$compared")" || die "could not read the commit count of $range"
    listed="$(jq -c '.commits[]' <<<"$compared")" || die "could not read the commits of $range"
    count="$(jq -s 'length' <<<"$listed")" || die "could not count the commits of $range"
    if ((count < total)); then
      echo "disclosure-collect: the merge group has $total commits and the API listed fewer" >&2
      exit "$too_big"
    fi
    commits_text <<<"$listed"
    ;;
  issue)
    require_writer '.issue'
    ev '.issue | .title, (.body // "")'
    ;;
  comment)
    require_writer '.comment'
    ev '.comment.body // ""'
    ;;
  review | review-comment)
    if [[ "$(ev '.pull_request.head.repo.fork // false')" == "true" ]]; then
      echo "disclosure-collect: not checked, reviews on fork PRs get no secrets" >&2
      exit "$fork_review"
    fi
    if [[ "$kind" == review ]]; then
      require_writer '.review'
      ev '.review.body // ""'
    else
      require_writer '.comment'
      ev '.comment.body // ""'
    fi
    ;;
  *)
    die "unknown kind $kind"
    ;;
esac
