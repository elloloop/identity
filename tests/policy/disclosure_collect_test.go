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
	collectOK      = 0
	collectFailed  = 2
	collectOutside = 10
	collectTooBig  = 11
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

// Every run reports the Disclosure check on the head anew, so an edit of
// only the title or description reads every commit too: a run that read
// less would replace a failing result with a passing one.
func TestDisclosureCollectEveryEditReadsEveryCommit(t *testing.T) {
	full := runCollect(t, "pr", ptr(prEvent), prFixtures)
	full.expect(t, collectOK)
	for name, changes := range map[string]string{
		"title only": `{"title": {"from": "old"}}`,
		"body only":  `{"body": {"from": "old"}}`,
		"both":       `{"title": {"from": "old"}, "body": {"from": "old"}}`,
		"base":       `{"base": {"ref": {"from": "old"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			event := strings.Replace(prEvent, `"action": "synchronize"`, `"action": "edited", "changes": `+changes, 1)
			run := runCollect(t, "pr", &event, prFixtures)
			run.expect(t, collectOK)
			if run.out != full.out || !slices.Equal(run.calls, full.calls) {
				t.Fatalf("an edit read less than a push:\ncollected:\n%s\ncalls %q, want %q", run.out, run.calls, full.calls)
			}
		})
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

func TestDisclosureCollectTextEvents(t *testing.T) {
	for name, tc := range map[string]struct{ kind, event, want string }{
		"issue":   {"issue", `{"issue": {"title": "T", "body": "B", "user": {"login": "alice"}}}`, "T\nB\n"},
		"comment": {"comment", `{"comment": {"body": "C", "user": {"login": "alice"}}}`, "C\n"},
		// An issue opened with no description is its title alone.
		"issue without body": {"issue", `{"issue": {"title": "T", "body": null, "user": {"login": "alice"}}}`, "T\n\n"},
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
	"issue":   `{"issue": {"title": "T", "body": "B", "user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
	"comment": `{"comment": {"body": "C", "user": {"login": "alice"}, "author_association": %q}, "sender": {"login": "bob"}}`,
}

const senderPermissionPath = "repos/acme/widgets/collaborators/bob/permission"

// Whether a text is checked turns on its author's write access to the
// repository, read from the permission API: an event's author_association
// shows org membership only when it is public, so a maintainer whose
// membership is private arrives as CONTRIBUTOR, and a MEMBER may hold only
// read. The event's sender never counts, so another person's push, retitle
// or reopen neither exposes an outsider's text to the match nor exempts a
// writer's.
func TestDisclosureCollectChecksWhatWritersWrote(t *testing.T) {
	for kind, event := range authorEvents {
		for name, tc := range map[string]struct {
			association, author, sender string
			want                        int
		}{
			"private member, admin":         {"CONTRIBUTOR", "admin", "none", collectOK},
			"maintainer":                    {"NONE", "maintain", "none", collectOK},
			"writer, outsider sends":        {"CONTRIBUTOR", "write", "none", collectOK},
			"member with read only":         {"MEMBER", "read", "none", collectOutside},
			"collaborator with triage":      {"COLLABORATOR", "triage", "none", collectOutside},
			"outsider":                      {"NONE", "none", "none", collectOutside},
			"outsider, writer sends":        {"NONE", "none", "admin", collectOutside},
			"first-timer, maintainer sends": {"FIRST_TIME_CONTRIBUTOR", "read", "maintain", collectOutside},
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
					t.Fatalf("collected %q from an item whose author has no write access", run.out)
				}
				if slices.Contains(run.calls, senderPermissionPath) {
					t.Fatalf("looked up the sender's permission: %q", run.calls)
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
	for name, tc := range map[string]struct{ commits, listed, want int }{
		"no commits":         {0, 0, collectOK},
		"at the cap":         {250, 250, collectOK},
		"one over the cap":   {251, 251, collectTooBig},
		"far past the cap":   {1000, 250, collectTooBig},
		"a list cut short":   {3, 2, collectTooBig},
		"a list one too few": {250, 249, collectTooBig},
	} {
		t.Run("PR commits/"+name, func(t *testing.T) {
			event := strings.Replace(prEvent, `"commits": 3`, `"commits": `+strconv.Itoa(tc.commits), 1)
			run := runCollect(t, "pr", &event, fixtures("admin", map[string]string{
				"repos/acme/widgets/pulls/7/commits": mergeCommits(tc.listed),
			}))
			run.expect(t, tc.want)
			// Past the cap, nothing is read beyond the author's permission.
			if tc.commits > 250 && !slices.Equal(run.calls, []string{permissionPath}) {
				t.Fatalf("read %q past the cap", run.calls)
			}
		})
	}
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
		kind    string
		event   *string
		answers map[string]string
	}{
		"no event file (issue)":   {"issue", nil, nil},
		"no event file (comment)": {"comment", nil, nil},
		"no event file (pr)":      {"pr", nil, nil},
		"event not JSON":          {"issue", ptr("{"), nil},
		"no author":               {"issue", ptr(`{"issue": {"title": "T"}}`), nil},
		"commit list fails":       {"pr", ptr(prEvent), fixtures("admin", nil)},
		"a commit fails": {"pr", ptr(oneCommit), fixtures("admin", map[string]string{
			"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}, "parents": [{"sha": "p"}]}]`,
		})},
		"a file's content fails": {"pr", ptr(oneCommit), fixtures("admin", map[string]string{
			"repos/acme/widgets/pulls/7/commits": `[{"sha": "c1", "commit": {"message": "m"}, "parents": [{"sha": "p"}]}]`,
			"repos/acme/widgets/commits/c1":      `{"files": [{"filename": "secret/a.bin", "status": "added"}]}`,
		})},
		"compare fails": {"merge-group", ptr(`{"merge_group": {"base_sha": "b0", "head_sha": "h1"}}`), nil},
		"unknown kind":  {"wiki", ptr(`{}`), nil},
		"a review kind": {"review", ptr(`{"review": {"body": "R", "user": {"login": "alice"}}}`), nil},
	} {
		t.Run(name, func(t *testing.T) {
			run := runCollect(t, tc.kind, tc.event, tc.answers)
			run.expect(t, collectFailed)
			// The masks are registered only in the check step, so an error
			// never names a file.
			if strings.Contains(run.stderr, "secret/a.bin") {
				t.Fatalf("the error names the file: %s", run.stderr)
			}
		})
	}
}

// Without its event or repository the script fails with the documented
// status rather than the shell's own.
func TestDisclosureCollectNeedsItsEnvironment(t *testing.T) {
	for _, unset := range []string{"GITHUB_EVENT_PATH", "GH_REPO"} {
		t.Run(unset, func(t *testing.T) {
			//nolint:gosec // The command is the repository-owned collect script.
			cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts", "disclosure-collect.sh"), "issue")
			cmd.Env = append(withoutEnv(os.Environ(), "GITHUB_EVENT_PATH", "GH_REPO"),
				"GITHUB_EVENT_PATH=/nonexistent/event.json", "GH_REPO=acme/widgets")
			cmd.Env = withoutEnv(cmd.Env, unset)
			var exitErr *exec.ExitError
			if err := cmd.Run(); !errors.As(err, &exitErr) || exitErr.ExitCode() != collectFailed {
				t.Fatalf("with %s unset: %v, want exit %d", unset, err, collectFailed)
			}
		})
	}
}
