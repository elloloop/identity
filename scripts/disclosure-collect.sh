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
# Only text from people with write access to the repository (admin,
# maintain or write) is collected: the item's author, or the event's sender
# (a maintainer editing an outsider's issue, or pushing to an outsider's
# PR). The threat is our own accidental leak; checking anyone else's text
# would let them confirm guesses against the secret term list one public
# check at a time. Write access is read from the repository permission API,
# because an event's author_association shows org membership only when it is
# public. A lookup that fails, or answers anything but a known permission,
# fails the check (exit 2, nothing printed): it never matches the text. An
# app's bot account is checked like a writer, since only an installed app
# can post as one.
#
# Outside contributions are covered by the maintainer-run review gate
# (§11). The merge queue squashes, so its run sees one squash commit per
# queued PR: it checks what lands on main (each PR's squash commit message
# and net diff), not an outside PR's description, branch name or
# intermediate commits.
#
# A review on a fork PR is never checked, whoever wrote it: GitHub gives a
# run triggered from a fork no secrets, so there is no term list to match.
# The fork is told apart by the head repository's name, which also catches
# a fork since deleted.
#
# Exit status:
#   0   the text is on stdout
#   2   bad usage, or a read failed (the check must fail, not pass)
#   10  not collected: no writer wrote or sent it (stdout empty)
#   11  not collected: past what the API lists (stdout empty)
#   12  not collected: a review on a fork PR, which gets no secrets
#
# The statuses past 2 are ones jq and gh never return, so a tool failure
# cannot pass for one of them. AGENTS.md §13 says what each means for a
# contributor. Needs bash, jq, gh and tr.

set -euo pipefail

readonly outside=10 too_big=11 fork_review=12

# Seconds to wait before the one retry of a failed permission lookup.
readonly retry_after=1

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

# permission_of prints login's permission on the repository: admin,
# maintain, write, triage, read or none. A lookup that fails twice, or any
# other answer (an empty or unknown permission, a deleted account's 404, a
# rate limit), exits 2 instead: the check fails and is re-run, and no text
# is matched for an author whose access is unknown.
permission_of() {
  local path permission
  path="repos/$repo/collaborators/$(jq -rn --arg l "$1" '$l | @uri')/permission"
  if ! permission="$(gh api "$path" --jq '.permission // ""')"; then
    sleep "$retry_after"
    permission="$(gh api "$path" --jq '.permission // ""')" ||
      die "could not read a permission (an API failure, often the hourly limit); re-run the check"
  fi
  case "$permission" in
    admin | maintain | write | triage | read | none) echo "$permission" ;;
    *) die "the permission API answered no known permission; re-run the check" ;;
  esac
}

# require_writer exits $outside unless the author of the item at $1 (an
# event object with .user) or the event's sender can write to the
# repository. It runs before anything is printed.
require_writer() {
  local author sender permission
  [[ "$(ev "$1.user.type // \"\"")" != Bot ]] || return 0
  author="$(ev "$1.user.login // \"\"")"
  [[ -n "$author" ]] || die "the event names no author"
  permission="$(permission_of "$author")"
  case "$permission" in admin | maintain | write) return 0 ;; esac
  sender="$(ev '.sender.login // ""')"
  if [[ -n "$sender" && "$sender" != "$author" ]]; then
    permission="$(permission_of "$sender")"
    case "$permission" in admin | maintain | write) return 0 ;; esac
  fi
  echo "disclosure-collect: not checked, neither the author nor the sender has write access" >&2
  exit "$outside"
}

# commits_text prints, for the commits listed (as {sha, message, parents}
# objects) on stdin: every message, then each commit's changed file names and
# added lines, and the whole content, at that commit, of each file the API
# gives no patch for.
#
# A merge commit's files are not read. The commits API diffs it against its
# first parent, so merging the base branch in would read all of the base
# branch's changes as this PR's; and what it brings is either the branch's
# own commits, read one by one here, or the base branch's, checked when they
# landed. The one thing it can add itself, a conflict resolution, is read by
# the merge queue's run, which sees the squashed net diff.
commits_text() {
  local commits shas files count patchless sha path n
  commits="$(cat)"
  jq -r '.message' <<<"$commits" || die "could not read the commit messages"
  shas="$(jq -r 'select(.parents < 2) | .sha' <<<"$commits")" || die "could not read the commit list"
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
    n=0
    while IFS= read -r path; do
      [[ -n "$path" ]] || continue
      n=$((n + 1))
      path="$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')"
      # NULs would cut the matcher's lines short; nothing in them is text.
      # The error names the file by its place, never its path, and gh's own
      # error, which quotes the URL, is dropped: the masks are not
      # registered until the check step.
      gh api -H "Accept: application/vnd.github.raw" "repos/$repo/contents/$path?ref=$sha" 2>/dev/null | tr -d '\000' ||
        die "could not read patchless file $n of commit $sha"
      echo
    done <<<"$patchless"
  done
}

# listing is the jq that turns a commit list into commits_text's input.
readonly listing='{sha, message: .commit.message, parents: (.parents | length)}'

case "$kind" in
  pr)
    require_writer '.pull_request'
    commits="$(ev '.pull_request.commits // 0')"
    if ((commits > max_commits)); then
      echo "disclosure-collect: the PR has $commits commits; the API lists at most $max_commits" >&2
      exit "$too_big"
    fi
    ev '.pull_request | .title, (.body // ""), .head.ref'
    # An edit of only the title or description changes no commit, and the
    # commits were read when they were pushed: spare the API calls, which
    # come out of an hourly budget the repository's workflows share.
    if [[ "$(ev '.action // ""')" == edited &&
      "$(ev '(.changes // {}) | keys - ["title", "body"] | length')" == 0 ]]; then
      exit 0
    fi
    number="$(ev '.pull_request.number')"
    listed="$(gh api "repos/$repo/pulls/$number/commits" --paginate --jq ".[] | $listing")" ||
      die "could not list the commits of PR $number"
    count="$(jq -s 'length' <<<"$listed")" || die "could not count the commits of PR $number"
    if ((count < commits)); then
      echo "disclosure-collect: the PR has $commits commits and the API listed $count" >&2
      exit "$too_big"
    fi
    commits_text <<<"$listed"
    ;;
  merge-group)
    # Only a maintainer can queue a PR, so the queue's run is never an
    # outsider's oracle. The queue squashes: each queued PR is one commit.
    range="$(ev '.merge_group | "\(.base_sha)...\(.head_sha)"')"
    compared="$(gh api "repos/$repo/compare/$range" --paginate \
      --jq "{total: .total_commits, commits: [.commits[] | $listing]}")" ||
      die "could not compare $range"
    total="$(jq -se 'first.total | numbers' <<<"$compared")" || die "could not read the commit count of $range"
    listed="$(jq -c '.commits[]' <<<"$compared")" || die "could not read the commits of $range"
    count="$(jq -s 'length' <<<"$listed")" || die "could not count the commits of $range"
    if ((count < total)); then
      echo "disclosure-collect: the merge group has $total commits and the API listed $count" >&2
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
    # A fork's run gets no secrets. Its head repository is another
    # repository, or none once the fork is deleted; .fork alone reads false
    # for a deleted fork.
    if [[ "$(ev '.pull_request.head.repo.full_name // ""')" != "$repo" ]]; then
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
