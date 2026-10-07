package policy

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
// as an API error would, and so does the first call to a path whose fixture
// has a ".fail-once" twin.
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
if [ -e "$fixture.fail-once" ]; then rm "$fixture.fail-once"; echo "fake gh: HTTP 502 for $path" >&2; exit 1; fi
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

const permissionPath = "repos/acme/widgets/collaborators/alice/permission"

// fixtures returns the given API answers plus alice's permission.
func fixtures(permission string, more map[string]string) map[string]string {
	all := map[string]string{permissionPath: `{"permission": "` + permission + `"}`}
	maps.Copy(all, more)
	return all
}

const prEvent = `{"action": "synchronize", "pull_request": {"number": 7, "title": "Title line", "body": "Body line",
  "head": {"ref": "topic/branch"}, "commits": 3, "user": {"login": "alice"}}}`

// A PR of three commits. The first adds a line the second removes, a line
// that itself starts with "++", and a file the API gives no patch for; the
// second deletes a file; the third merges the base branch in, and the
// commits API has nothing for it (reading it would fail the test).
var prFixtures = fixtures("admin", map[string]string{
	"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "first message"}, "parents": [{"sha": "p0"}]}]
[{"sha": "c2", "commit": {"message": "second message"}, "parents": [{"sha": "c1"}]},
 {"sha": "c3", "commit": {"message": "Merge main"}, "parents": [{"sha": "c2"}, {"sha": "m9"}]}]`,
	"repos/acme/widgets/commits/c1": `{"files": [{"filename": "main.go", "status": "added",
  "patch": "@@ -0,0 +1,3 @@\n+added in c1\n+++doubled plus\n+tail"}]}
{"files": [{"filename": "assets/big file.bin", "status": "added"}]}`,
	"repos/acme/widgets/contents/assets/big%20file.bin?ref=c1": "raw\x00content",
	"repos/acme/widgets/commits/c2": `{"files": [
  {"filename": "main.go", "status": "modified", "patch": "@@ -1,3 +1,2 @@\n-added in c1\n context line\n+replaced"},
  {"filename": "old.bin", "status": "removed"}]}`,
})

func TestDisclosureCollectPullRequest(t *testing.T) {
	run := runCollect(t, "pr", ptr(prEvent), prFixtures)
	run.expect(t, collectOK)
	want := strings.Join([]string{
		"Title line", "Body line", "topic/branch",
		"first message", "second message", "Merge main",
		// Commit c1, page by page: its added lines (one of them starts with
		// "++"), then the whole patchless file, NULs dropped.
		"main.go", "added in c1", "++doubled plus", "tail",
		"assets/big file.bin",
		"rawcontent",
		// Commit c2: "added in c1" is gone from the net diff, but was read
		// from c1 above. Removed and context lines are not added lines.
		"main.go", "replaced",
		"old.bin",
		// Commit c3, a merge: its message only.
	}, "\n") + "\n"
	if run.out != want {
		t.Fatalf("collected:\n%s\nwant:\n%s", run.out, want)
	}
	for _, call := range run.calls {
		if strings.Contains(call, "old.bin") || strings.HasSuffix(call, "/commits/c3") {
			t.Errorf("read what it must not: %s", call)
		}
	}
}

// An edit of only the title or description reads no commits; an edit that
// moves the base branch reads them all.
func TestDisclosureCollectDescriptionOnlyEdit(t *testing.T) {
	edited := func(changes string) *string {
		return ptr(strings.Replace(prEvent, `"action": "synchronize"`, `"action": "edited", "changes": `+changes, 1))
	}
	run := runCollect(t, "pr", edited(`{"title": {"from": "old"}, "body": {"from": "old"}}`), prFixtures)
	run.expect(t, collectOK)
	if want := "Title line\nBody line\ntopic/branch\n"; run.out != want {
		t.Fatalf("collected %q, want %q", run.out, want)
	}
	if !slices.Equal(run.calls, []string{permissionPath}) {
		t.Fatalf("calls = %q, want only the permission lookup", run.calls)
	}

	run = runCollect(t, "pr", edited(`{"base": {"ref": {"from": "old"}}}`), prFixtures)
	run.expect(t, collectOK)
	if !strings.Contains(run.out, "added in c1") {
		t.Fatalf("a base change read no commits:\n%s", run.out)
	}
}

// The merge queue squashes, so a merge group holds one squash commit per
// queued PR: its message and its files are what lands on main.
func TestDisclosureCollectMergeGroup(t *testing.T) {
	event := `{"merge_group": {"base_sha": "b0", "head_sha": "h1", "head_ref": "gh-readonly-queue/main/pr-7-h1"}}`
	run := runCollect(t, "merge-group", &event, map[string]string{
		"repos/acme/widgets/compare/b0...h1": `{"total_commits": 2, "commits": [{"sha": "m1", "commit": {"message": "queued message (#7)"}, "parents": [{"sha": "b0"}]}]}
{"total_commits": 2, "commits": [{"sha": "m2", "commit": {"message": "second queued (#8)"}, "parents": [{"sha": "m1"}]}]}`,
		"repos/acme/widgets/commits/m1": `{"files": [{"filename": "x.go", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new line"}]}`,
		"repos/acme/widgets/commits/m2": `{"files": []}`,
	})
	run.expect(t, collectOK)
	if want := "queued message (#7)\nsecond queued (#8)\nx.go\nnew line\n"; run.out != want {
		t.Fatalf("collected %q, want %q", run.out, want)
	}
}

// sameRepoPR is the pull_request of a review event on a PR from a branch of
// this repository.
const sameRepoPR = `"pull_request": {"head": {"repo": {"full_name": "acme/widgets"}}}`

func TestDisclosureCollectTextEvents(t *testing.T) {
	for name, tc := range map[string]struct{ kind, event, want string }{
		"issue":   {"issue", `{"issue": {"title": "T", "body": "B", "user": {"login": "alice"}}}`, "T\nB\n"},
		"comment": {"comment", `{"comment": {"body": "C", "user": {"login": "alice"}}}`, "C\n"},
		"review":  {"review", `{` + sameRepoPR + `, "review": {"body": "R", "user": {"login": "alice"}}}`, "R\n"},
		"review comment": {"review-comment", `{` + sameRepoPR + `,
			"comment": {"body": "RC", "user": {"login": "alice"}}}`, "RC\n"},
		// A review with no body (an approval alone) is empty text.
		"review without body": {"review", `{` + sameRepoPR + `, "review": {"body": null, "user": {"login": "alice"}}}`, "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			run := runCollect(t, tc.kind, ptr(tc.event), fixtures("write", nil))
			run.expect(t, collectOK)
			if run.out != tc.want {
				t.Fatalf("collected %q, want %q", run.out, tc.want)
			}
		})
	}
}

// authorEvents holds, per kind, an event whose item alice wrote (with the
// given author_association) and bob sent.
var authorEvents = map[string]string{
	"pr": `{"pull_request": {"number": 7, "title": "T", "head": {"ref": "b"}, "commits": 0,
		"user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
	"issue":          `{"issue": {"title": "T", "body": "B", "user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
	"comment":        `{"comment": {"body": "C", "user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
	"review":         `{` + sameRepoPR + `, "review": {"body": "R", "user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
	"review-comment": `{` + sameRepoPR + `, "comment": {"body": "RC", "user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
}

const senderPermissionPath = "repos/acme/widgets/collaborators/bob/permission"

// Whether a text is checked turns on write access to the repository, read
// from the permission API: an event's author_association shows org
// membership only when it is public, so a maintainer whose membership is
// private arrives as CONTRIBUTOR, and a MEMBER may hold only read. The
// item's author or the event's sender (a maintainer editing an outsider's
// item) having write access is enough.
func TestDisclosureCollectChecksEveryoneWithWriteAccess(t *testing.T) {
	for kind, event := range authorEvents {
		for name, tc := range map[string]struct {
			association, author, sender string
			want                        int
		}{
			"private member, admin":    {"CONTRIBUTOR", "admin", "read", collectOK},
			"maintainer":               {"NONE", "maintain", "read", collectOK},
			"writer":                   {"CONTRIBUTOR", "write", "none", collectOK},
			"member with read only":    {"MEMBER", "read", "read", collectOutside},
			"collaborator with triage": {"COLLABORATOR", "triage", "none", collectOutside},
			"outsider":                 {"NONE", "none", "none", collectOutside},
			"outsider, writer sends":   {"NONE", "none", "admin", collectOK},
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				t.Parallel()
				run := runCollect(t, kind, ptr(fmt.Sprintf(event, tc.association)), map[string]string{
					permissionPath:                       `{"permission": "` + tc.author + `"}`,
					senderPermissionPath:                 `{"permission": "` + tc.sender + `"}`,
					"repos/acme/widgets/pulls/7/commits": `[]`,
				})
				run.expect(t, tc.want)
				if tc.want == collectOutside && run.out != "" {
					t.Fatalf("collected %q from an item no writer wrote or sent", run.out)
				}
			})
		}
	}
}

// An app's bot account is checked like a writer, with no lookup: the
// permission API reports none for it, yet only an installed app can post
// as one.
func TestDisclosureCollectChecksBotAccounts(t *testing.T) {
	event := `{"issue": {"title": "T", "body": "B", "user": {"login": "acme-app[bot]", "type": "Bot"}}}`
	run := runCollect(t, "issue", &event, nil)
	run.expect(t, collectOK)
	if run.out != "T\nB\n" || len(run.calls) != 0 {
		t.Fatalf("collected %q with calls %q", run.out, run.calls)
	}
}

// A permission the API does not answer plainly fails the check: nothing is
// printed, so nothing is matched, and nothing else is read.
func TestDisclosureCollectFailsWhenAPermissionIsUnknown(t *testing.T) {
	for name, answer := range map[string]*string{
		"lookup fails (404, 5xx, rate limit)": nil,
		"empty object":                        ptr(`{}`),
		"empty permission":                    ptr(`{"permission": ""}`),
		"unknown permission":                  ptr(`{"permission": "superuser"}`),
	} {
		for kind, event := range authorEvents {
			t.Run(name+"/"+kind, func(t *testing.T) {
				t.Parallel()
				fx := map[string]string{"repos/acme/widgets/pulls/7/commits": `[]`}
				if answer != nil {
					fx[permissionPath] = *answer
				}
				run := runCollect(t, kind, ptr(fmt.Sprintf(event, "NONE")), fx)
				run.expect(t, collectFailed)
				if run.out != "" {
					t.Fatalf("printed %q for an author whose access is unknown", run.out)
				}
				for _, call := range run.calls {
					if call != permissionPath {
						t.Fatalf("read %s after the lookup failed", call)
					}
				}
			})
		}
	}
	// One failed lookup is retried before the check fails.
	t.Run("lookup fails once", func(t *testing.T) {
		run := runCollect(t, "issue", ptr(fmt.Sprintf(authorEvents["issue"], "NONE")),
			fixtures("admin", map[string]string{permissionPath + ".fail-once": ""}))
		run.expect(t, collectOK)
		if !slices.Equal(run.calls, []string{permissionPath, permissionPath}) {
			t.Fatalf("calls = %q, want the lookup and one retry", run.calls)
		}
	})
	// The sender's lookup fails the same way.
	t.Run("sender lookup fails", func(t *testing.T) {
		run := runCollect(t, "issue", ptr(fmt.Sprintf(authorEvents["issue"], "NONE")), fixtures("read", nil))
		run.expect(t, collectFailed)
		if run.out != "" {
			t.Fatalf("printed %q", run.out)
		}
	})
}

// A run triggered by a review on a fork PR gets no secrets, so there is no
// list to match; the script says so rather than pass it as clean. A fork
// is any other head repository, or none once the fork is deleted.
func TestDisclosureCollectReportsReviewsOnForkPullRequests(t *testing.T) {
	for name, pr := range map[string]string{
		"fork":         `"pull_request": {"head": {"repo": {"full_name": "someone/widgets", "fork": true}}}`,
		"deleted fork": `"pull_request": {"head": {"repo": null}}`,
		"no head":      `"pull_request": {}`,
	} {
		for _, kind := range []string{"review", "review-comment"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				event := `{` + pr + `, "review": {"body": "R", "user": {"login": "alice"}}, "comment": {"body": "C", "user": {"login": "alice"}}}`
				run := runCollect(t, kind, &event, fixtures("admin", nil))
				run.expect(t, collectForkReview)
				if run.out != "" || len(run.calls) != 0 {
					t.Fatalf("collected %q with calls %q", run.out, run.calls)
				}
			})
		}
	}
}

// Past what the API lists, part of the PR would go unread: fail rather
// than pass it.
func TestDisclosureCollectRefusesWhatTheAPICannotList(t *testing.T) {
	// n merge commits: a full list of n commits with no files to read.
	mergeCommits := func(n int) string {
		listed := make([]string, n)
		for i := range listed {
			listed[i] = fmt.Sprintf(`{"sha": "c%d", "commit": {"message": "m"}, "parents": [{"sha": "a"}, {"sha": "b"}]}`, i)
		}
		return "[" + strings.Join(listed, ",") + "]"
	}
	t.Run("PR commits", func(t *testing.T) {
		for _, tc := range []struct{ commits, listed, want int }{
			{0, 0, collectOK},
			{250, 250, collectOK},
			{251, 251, collectTooBig},
			{1000, 250, collectTooBig},
			{3, 2, collectTooBig}, // a list the API cut short
		} {
			event := strings.Replace(prEvent, `"commits": 3`, `"commits": `+strconv.Itoa(tc.commits), 1)
			run := runCollect(t, "pr", &event, fixtures("admin", map[string]string{
				"repos/acme/widgets/pulls/7/commits": mergeCommits(tc.listed),
			}))
			run.expect(t, tc.want)
			if tc.want == collectTooBig && run.out != "" && tc.commits > 250 {
				t.Fatalf("%d commits: collected %q past the cap", tc.commits, run.out)
			}
		}
	})
	t.Run("files in one commit", func(t *testing.T) {
		for files, want := range map[int]int{2999: collectOK, 3000: collectTooBig} {
			names := make([]string, files)
			for i := range names {
				names[i] = fmt.Sprintf(`{"filename": "f%d", "status": "removed"}`, i)
			}
			event := strings.Replace(prEvent, `"commits": 3`, `"commits": 1`, 1)
			run := runCollect(t, "pr", &event, fixtures("admin", map[string]string{
				"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}, "parents": [{"sha": "p"}]}]`,
				"repos/acme/widgets/commits/c1":      `{"files": [` + strings.Join(names, ",") + `]}`,
			}))
			run.expect(t, want)
		}
	})
	t.Run("merge group commits", func(t *testing.T) {
		event := `{"merge_group": {"base_sha": "b0", "head_sha": "h1"}}`
		run := runCollect(t, "merge-group", &event, map[string]string{
			"repos/acme/widgets/compare/b0...h1": `{"total_commits": 300, "commits": [{"sha": "m1", "commit": {"message": "m"}, "parents": [{"sha": "b0"}]}]}`,
			"repos/acme/widgets/commits/m1":      `{"files": []}`,
		})
		run.expect(t, collectTooBig)
	})
}

// A read that fails fails the check: it never passes for clean or for an
// outside author.
func TestDisclosureCollectFailsClosedOnAFailedRead(t *testing.T) {
	oneCommit := strings.Replace(prEvent, `"commits": 3`, `"commits": 1`, 1)
	for name, tc := range map[string]struct {
		kind     string
		event    *string
		fixtures map[string]string
	}{
		"no event file":     {"issue", nil, nil},
		"event not JSON":    {"issue", ptr("{"), nil},
		"no author":         {"issue", ptr(`{"issue": {"title": "T"}}`), nil},
		"commit list fails": {"pr", ptr(prEvent), fixtures("admin", nil)},
		"a commit fails": {"pr", ptr(oneCommit), fixtures("admin", map[string]string{
			"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}, "parents": [{"sha": "p"}]}]`,
		})},
		"a file's content fails": {"pr", ptr(oneCommit), fixtures("admin", map[string]string{
			"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}, "parents": [{"sha": "p"}]}]`,
			"repos/acme/widgets/commits/c1":      `{"files": [{"filename": "secret/a.bin", "status": "added"}]}`,
		})},
		"compare fails": {"merge-group", ptr(`{"merge_group": {"base_sha": "b0", "head_sha": "h1"}}`), nil},
		"unknown kind":  {"wiki", ptr(`{}`), nil},
	} {
		t.Run(name, func(t *testing.T) {
			run := runCollect(t, tc.kind, tc.event, tc.fixtures)
			run.expect(t, collectFailed)
			// The masks are registered only in the check step, so an error
			// never names a file.
			if strings.Contains(run.stderr, "secret/a.bin") {
				t.Fatalf("the error names the file: %s", run.stderr)
			}
		})
	}
}
