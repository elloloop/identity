package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Exit statuses of scripts/disclosure-collect.sh.
const (
	collectOK         = 0
	collectFailed     = 2
	collectOutside    = 10
	collectTooBig     = 11
	collectForkReview = 12
)

// fakeGH answers `gh api <path>` from fixtures, one file per API path, and
// logs every path it is asked for. A fixture may hold several JSON documents,
// one per page: `--jq` runs over each, as gh's --paginate does. With the raw
// Accept header the fixture is returned as is. A path with no fixture fails,
// as an API error would.
const fakeGH = `#!/usr/bin/env bash
set -euo pipefail
[ "$1" = api ] || { echo "fake gh: unexpected: $*" >&2; exit 64; }
shift
path= filter= raw=
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) shift ;;
    --jq) filter="$2"; shift 2 ;;
    -H) [ "$2" = "Accept: application/vnd.github.raw" ] && raw=1; shift 2 ;;
    *) path="$1"; shift ;;
  esac
done
echo "$path" >> "$FAKE_GH_DIR/calls"
fixture="$FAKE_GH_DIR/fixtures/$(printf '%s' "$path" | sed -e 's#/#__#g' -e 's#?#@@#g')"
[ -e "$fixture" ] || { echo "fake gh: HTTP 404 for $path" >&2; exit 1; }
if [ -n "$raw" ]; then cat "$fixture"; exit 0; fi
jq -r "$filter" "$fixture"
`

var fixtureName = strings.NewReplacer("/", "__", "?", "@@")

type collectRun struct {
	out, stderr string
	code        int
	calls       []string
}

// runCollect runs disclosure-collect.sh for kind against event (written to
// the event file unless it is nil), with gh answering from fixtures (API
// path -> body), and returns its stdout, stderr, exit status and the API
// paths it read.
func runCollect(t *testing.T, kind string, event *string, fixtures map[string]string) collectRun {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatal("jq is required: the collect script and the fake gh both use it")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Join(dir, "fixtures")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(bin, "gh"), fakeGH, 0o700)
	if event != nil {
		writeFile(t, filepath.Join(dir, "event.json"), *event, 0o600)
	}
	for path, body := range fixtures {
		writeFile(t, filepath.Join(dir, "fixtures", fixtureName.Replace(path)), body, 0o600)
	}

	//nolint:gosec // The command is the repository-owned collect script.
	cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts", "disclosure-collect.sh"), kind)
	cmd.Env = append(withoutEnv(os.Environ(), "PATH", "GH_REPO", "GITHUB_EVENT_PATH", "FAKE_GH_DIR"),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_REPO=acme/widgets",
		"GITHUB_EVENT_PATH="+filepath.Join(dir, "event.json"),
		"FAKE_GH_DIR="+dir,
	)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	run := collectRun{}
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		run.code = exitErr.ExitCode()
	default:
		t.Fatalf("run disclosure-collect.sh: %v", err)
	}
	run.out, run.stderr = out.String(), errOut.String()
	if calls, err := os.ReadFile(filepath.Join(dir, "calls")); err == nil {
		run.calls = strings.Fields(string(calls))
	}
	return run
}

// expect fails the test unless the run exited with code, showing what the
// script said on stderr.
func (r collectRun) expect(t *testing.T, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", r.code, code, r.stderr)
	}
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

const prEvent = `{"pull_request": {"number": 7, "title": "Title line", "body": "Body line",
  "head": {"ref": "topic/branch"}, "commits": 2, "user": {"login": "alice"}, "author_association": "MEMBER"}}`

// A PR of two commits. The first adds a line the second removes, a line
// that itself starts with "++", and a file the API gives no patch for; the
// second deletes a file.
var prFixtures = map[string]string{
	"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "first message"}}]
[{"sha": "c2", "commit": {"message": "second message"}}]`,
	"repos/acme/widgets/commits/c1": `{"files": [{"filename": "main.go", "status": "added",
  "patch": "@@ -0,0 +1,3 @@\n+added in c1\n+++doubled plus\n+tail"}]}
{"files": [{"filename": "assets/big file.bin", "status": "added"}]}`,
	"repos/acme/widgets/contents/assets/big%20file.bin?ref=c1": "raw\x00content",
	"repos/acme/widgets/commits/c2": `{"files": [
  {"filename": "main.go", "status": "modified", "patch": "@@ -1,3 +1,2 @@\n-added in c1\n context line\n+replaced"},
  {"filename": "old.bin", "status": "removed"}]}`,
}

func TestDisclosureCollectPullRequest(t *testing.T) {
	run := runCollect(t, "pr", ptr(prEvent), prFixtures)
	run.expect(t, collectOK)
	want := strings.Join([]string{
		"Title line", "Body line", "topic/branch",
		"first message", "second message",
		// Commit c1, page by page: its added lines (one of them starts with
		// "++"), then the whole patchless file, NULs dropped.
		"main.go", "added in c1", "++doubled plus", "tail",
		"assets/big file.bin",
		"rawcontent",
		// Commit c2: "added in c1" is gone from the net diff, but was read
		// from c1 above. Removed and context lines are not added lines.
		"main.go", "replaced",
		"old.bin",
	}, "\n") + "\n"
	if run.out != want {
		t.Fatalf("collected:\n%s\nwant:\n%s", run.out, want)
	}
	for _, call := range run.calls {
		if strings.Contains(call, "old.bin") {
			t.Errorf("read the content of a removed file: %s", call)
		}
	}
}

// The merge queue squashes, so a merge group holds one squash commit per
// queued PR: its message and its files are what lands on main.
func TestDisclosureCollectMergeGroup(t *testing.T) {
	event := `{"merge_group": {"base_sha": "b0", "head_sha": "h1", "head_ref": "gh-readonly-queue/main/pr-7-h1"}}`
	run := runCollect(t, "merge-group", &event, map[string]string{
		"repos/acme/widgets/compare/b0...h1": `{"total_commits": 2, "commits": [{"sha": "m1", "commit": {"message": "queued message (#7)"}}]}
{"total_commits": 2, "commits": [{"sha": "m2", "commit": {"message": "second queued (#8)"}}]}`,
		"repos/acme/widgets/commits/m1": `{"files": [{"filename": "x.go", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new line"}]}`,
		"repos/acme/widgets/commits/m2": `{"files": []}`,
	})
	run.expect(t, collectOK)
	if want := "queued message (#7)\nsecond queued (#8)\nx.go\nnew line\n"; run.out != want {
		t.Fatalf("collected %q, want %q", run.out, want)
	}
}

func TestDisclosureCollectTextEvents(t *testing.T) {
	for name, tc := range map[string]struct{ kind, event, want string }{
		"issue":   {"issue", `{"issue": {"title": "T", "body": "B", "author_association": "OWNER"}}`, "T\nB\n"},
		"comment": {"comment", `{"comment": {"body": "C", "author_association": "COLLABORATOR"}}`, "C\n"},
		"review": {"review", `{"pull_request": {"head": {"repo": {"fork": false}}},
			"review": {"body": "R", "author_association": "MEMBER"}}`, "R\n"},
		"review comment": {"review-comment", `{"pull_request": {"head": {"repo": {"fork": false}}},
			"comment": {"body": "RC", "author_association": "MEMBER"}}`, "RC\n"},
		// A review with no body (an approval alone) is empty text.
		"review without body": {"review", `{"review": {"body": null, "author_association": "MEMBER"}}`, "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			run := runCollect(t, tc.kind, ptr(tc.event), nil)
			run.expect(t, collectOK)
			if run.out != tc.want {
				t.Fatalf("collected %q, want %q", run.out, tc.want)
			}
		})
	}
}

// authorEvents holds, per kind, an event whose author is "alice" with the
// association left as %q.
var authorEvents = map[string]string{
	"pr": `{"pull_request": {"number": 7, "title": "T", "head": {"ref": "b"}, "commits": 0,
		"user": {"login": "alice"}, "author_association": %q}}`,
	"issue":          `{"issue": {"title": "T", "body": "B", "user": {"login": "alice"}, "author_association": %q}}`,
	"comment":        `{"comment": {"body": "C", "user": {"login": "alice"}, "author_association": %q}}`,
	"review":         `{"review": {"body": "R", "user": {"login": "alice"}, "author_association": %q}}`,
	"review-comment": `{"comment": {"body": "RC", "user": {"login": "alice"}, "author_association": %q}}`,
}

const permissionPath = "repos/acme/widgets/collaborators/alice/permission"

// Whether a text is checked turns on the author's write access to the
// repository. The event's author_association shows org membership only when
// it is public, so a maintainer whose membership is private arrives as
// CONTRIBUTOR: the permission API, not the association, decides.
func TestDisclosureCollectChecksEveryoneWithWriteAccess(t *testing.T) {
	for kind, event := range authorEvents {
		// A public association of the project's own needs no lookup.
		for _, association := range []string{"OWNER", "MEMBER", "COLLABORATOR"} {
			t.Run(kind+"/"+association, func(t *testing.T) {
				t.Parallel()
				run := runCollect(t, kind, ptr(fmt.Sprintf(event, association)),
					map[string]string{"repos/acme/widgets/pulls/7/commits": `[]`})
				run.expect(t, collectOK)
				for _, call := range run.calls {
					if call == permissionPath {
						t.Errorf("looked up the permission of a %s", association)
					}
				}
			})
		}
		// Any other association, a private member's included, is settled by
		// the permission: write or above is checked, anything less is not.
		cases := map[[2]string]int{}
		for _, association := range []string{"CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN", "NONE", ""} {
			cases[[2]string{association, "admin"}] = collectOK
			cases[[2]string{association, "read"}] = collectOutside
		}
		for permission, want := range map[string]int{"maintain": collectOK, "write": collectOK, "triage": collectOutside, "none": collectOutside} {
			cases[[2]string{"CONTRIBUTOR", permission}] = want
		}
		for c, want := range cases {
			association, permission := c[0], c[1]
			t.Run(kind+"/"+association+"/"+permission, func(t *testing.T) {
				t.Parallel()
				run := runCollect(t, kind, ptr(fmt.Sprintf(event, association)), map[string]string{
					permissionPath:                       `{"permission": "` + permission + `"}`,
					"repos/acme/widgets/pulls/7/commits": `[]`,
				})
				run.expect(t, want)
				if want == collectOutside && (run.out != "" || len(run.calls) != 1) {
					t.Fatalf("collected %q with calls %q from an author without write access", run.out, run.calls)
				}
			})
		}
	}
}

// An unreadable permission never skips the check: the author is treated as
// one of ours and the text is collected.
func TestDisclosureCollectChecksWhenThePermissionCannotBeRead(t *testing.T) {
	for kind, event := range authorEvents {
		t.Run(kind, func(t *testing.T) {
			run := runCollect(t, kind, ptr(fmt.Sprintf(event, "CONTRIBUTOR")),
				map[string]string{"repos/acme/widgets/pulls/7/commits": `[]`})
			run.expect(t, collectOK)
			if run.out == "" {
				t.Fatal("collected nothing")
			}
		})
	}
}

// A run triggered by a review on a fork PR gets no secrets, so there is no
// list to match; the script says so rather than pass it as clean.
func TestDisclosureCollectReportsReviewsOnForkPullRequests(t *testing.T) {
	for _, kind := range []string{"review", "review-comment"} {
		t.Run(kind, func(t *testing.T) {
			event := `{"pull_request": {"head": {"repo": {"fork": true}}},
				"review": {"body": "R", "author_association": "OWNER"}, "comment": {"body": "C", "author_association": "OWNER"}}`
			run := runCollect(t, kind, &event, nil)
			run.expect(t, collectForkReview)
			if run.out != "" || len(run.calls) != 0 {
				t.Fatalf("collected %q with calls %q", run.out, run.calls)
			}
		})
	}
}

// Past what the API lists, part of the PR would go unread: fail rather
// than pass it.
func TestDisclosureCollectRefusesWhatTheAPICannotList(t *testing.T) {
	t.Run("PR commits", func(t *testing.T) {
		for commits, want := range map[int]int{0: collectOK, 250: collectOK, 251: collectTooBig, 1000: collectTooBig} {
			event := strings.Replace(prEvent, `"commits": 2`, `"commits": `+strconv.Itoa(commits), 1)
			run := runCollect(t, "pr", &event, map[string]string{"repos/acme/widgets/pulls/7/commits": `[]`})
			run.expect(t, want)
			if want == collectTooBig && (run.out != "" || len(run.calls) != 0) {
				t.Fatalf("%d commits: collected %q with calls %q", commits, run.out, run.calls)
			}
		}
	})
	t.Run("files in one commit", func(t *testing.T) {
		for files, want := range map[int]int{2999: collectOK, 3000: collectTooBig} {
			names := make([]string, files)
			for i := range names {
				names[i] = fmt.Sprintf(`{"filename": "f%d", "status": "removed"}`, i)
			}
			run := runCollect(t, "pr", ptr(prEvent), map[string]string{
				"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}}]`,
				"repos/acme/widgets/commits/c1":      `{"files": [` + strings.Join(names, ",") + `]}`,
			})
			run.expect(t, want)
		}
	})
	t.Run("merge group commits", func(t *testing.T) {
		event := `{"merge_group": {"base_sha": "b0", "head_sha": "h1"}}`
		run := runCollect(t, "merge-group", &event, map[string]string{
			"repos/acme/widgets/compare/b0...h1": `{"total_commits": 300, "commits": [{"sha": "m1", "commit": {"message": "m"}}]}`,
			"repos/acme/widgets/commits/m1":      `{"files": []}`,
		})
		run.expect(t, collectTooBig)
	})
}

// A read that fails fails the check: it never passes for clean or for an
// outside author.
func TestDisclosureCollectFailsClosedOnAFailedRead(t *testing.T) {
	for name, tc := range map[string]struct {
		kind     string
		event    *string
		fixtures map[string]string
	}{
		"no event file":     {"issue", nil, nil},
		"event not JSON":    {"issue", ptr("{"), nil},
		"commit list fails": {"pr", ptr(prEvent), nil},
		"a commit fails":    {"pr", ptr(prEvent), map[string]string{"repos/acme/widgets/pulls/7/commits": prFixtures["repos/acme/widgets/pulls/7/commits"]}},
		"a file's content fails": {"pr", ptr(prEvent), map[string]string{
			"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}}]`,
			"repos/acme/widgets/commits/c1":      `{"files": [{"filename": "a.bin", "status": "added"}]}`,
		}},
		"compare fails": {"merge-group", ptr(`{"merge_group": {"base_sha": "b0", "head_sha": "h1"}}`), nil},
		"unknown kind":  {"wiki", ptr(`{}`), nil},
	} {
		t.Run(name, func(t *testing.T) {
			runCollect(t, tc.kind, tc.event, tc.fixtures).expect(t, collectFailed)
		})
	}
}
