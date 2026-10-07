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
	collectOK      = 0
	collectUsage   = 2
	collectOutside = 4
	collectTooBig  = 5
)

// fakeGH answers `gh api <path>` from fixtures, one file per API path, and
// logs every path it is asked for. A fixture may hold several JSON documents,
// one per page: `--jq` runs over each, as gh's --paginate does. With the raw
// Accept header the fixture is returned as is.
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
[ -e "$fixture" ] || { echo "fake gh: no fixture for $path" >&2; exit 1; }
if [ -n "$raw" ]; then cat "$fixture"; exit 0; fi
jq -r "$filter" "$fixture"
`

var fixtureName = strings.NewReplacer("/", "__", "?", "@@")

type collectRun struct {
	out   string
	code  int
	calls []string
}

// runCollect runs disclosure-collect.sh for kind against event, with gh
// answering from fixtures (API path -> body), and returns its stdout, exit
// status and the API paths it read.
func runCollect(t *testing.T, kind, event string, fixtures map[string]string) collectRun {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Join(dir, "fixtures")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(bin, "gh"), fakeGH, 0o700)
	writeFile(t, filepath.Join(dir, "event.json"), event, 0o600)
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
	run.out = out.String()
	if calls, err := os.ReadFile(filepath.Join(dir, "calls")); err == nil {
		run.calls = strings.Fields(string(calls))
	}
	if run.code != collectOK && run.code != collectOutside && run.code != collectTooBig && run.code != collectUsage {
		t.Logf("stderr:\n%s", errOut.String())
	}
	return run
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

const prEvent = `{"pull_request": {"number": 7, "title": "Title line", "body": "Body line",
  "head": {"ref": "topic/branch"}, "commits": 2, "changed_files": 3, "author_association": "MEMBER"}}`

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
	run := runCollect(t, "pr", prEvent, prFixtures)
	if run.code != collectOK {
		t.Fatalf("exit = %d, want %d", run.code, collectOK)
	}
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

func TestDisclosureCollectMergeGroup(t *testing.T) {
	event := `{"merge_group": {"base_sha": "b0", "head_sha": "h1", "head_ref": "gh-readonly-queue/main/pr-7-h1"}}`
	run := runCollect(t, "merge-group", event, map[string]string{
		"repos/acme/widgets/compare/b0...h1": `{"commits": [{"sha": "m1", "commit": {"message": "queued message"}}]}`,
		"repos/acme/widgets/commits/m1":      `{"files": [{"filename": "x.go", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new line"}]}`,
	})
	if run.code != collectOK {
		t.Fatalf("exit = %d, want %d", run.code, collectOK)
	}
	if want := "queued message\nx.go\nnew line\n"; run.out != want {
		t.Fatalf("collected %q, want %q", run.out, want)
	}
}

func TestDisclosureCollectTextEvents(t *testing.T) {
	for kind, tc := range map[string]struct{ event, want string }{
		"issue":          {`{"issue": {"title": "T", "body": "B", "author_association": "OWNER"}}`, "T\nB\n"},
		"comment":        {`{"comment": {"body": "C", "author_association": "COLLABORATOR"}}`, "C\n"},
		"review":         {`{"review": {"body": "R", "author_association": "MEMBER"}}`, "R\n"},
		"review-comment": {`{"comment": {"body": "RC", "author_association": "MEMBER"}}`, "RC\n"},
		// A review with no body (an approval alone) is empty text.
		"review without body": {`{"review": {"body": null, "author_association": "MEMBER"}}`, "\n"},
	} {
		t.Run(kind, func(t *testing.T) {
			run := runCollect(t, strings.TrimSuffix(kind, " without body"), tc.event, nil)
			if run.code != collectOK || run.out != tc.want {
				t.Fatalf("exit %d, collected %q; want exit 0 and %q", run.code, run.out, tc.want)
			}
		})
	}
}

// Only the project's own people are checked: anyone else could otherwise
// test guesses against the term list through the public result.
func TestDisclosureCollectChecksOnlyTheProjectsOwnPeople(t *testing.T) {
	events := map[string]string{
		"pr":             `{"pull_request": {"number": 7, "title": "T", "head": {"ref": "b"}, "commits": 0, "changed_files": 0, "author_association": %q}}`,
		"issue":          `{"issue": {"title": "T", "body": "B", "author_association": %q}}`,
		"comment":        `{"comment": {"body": "C", "author_association": %q}}`,
		"review":         `{"review": {"body": "R", "author_association": %q}}`,
		"review-comment": `{"comment": {"body": "RC", "author_association": %q}}`,
	}
	fixtures := map[string]string{"repos/acme/widgets/pulls/7/commits": `[]`}
	for kind, event := range events {
		for _, association := range []string{"OWNER", "MEMBER", "COLLABORATOR"} {
			t.Run(kind+"/"+association, func(t *testing.T) {
				if run := runCollect(t, kind, fmt.Sprintf(event, association), fixtures); run.code != collectOK {
					t.Fatalf("exit = %d, want %d (checked)", run.code, collectOK)
				}
			})
		}
		for _, association := range []string{"CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN", "NONE", ""} {
			t.Run(kind+"/"+association, func(t *testing.T) {
				run := runCollect(t, kind, fmt.Sprintf(event, association), fixtures)
				if run.code != collectOutside || run.out != "" || len(run.calls) != 0 {
					t.Fatalf("exit %d, collected %q, API calls %q; want exit %d, nothing, no calls",
						run.code, run.out, run.calls, collectOutside)
				}
			})
		}
	}
}

// Past what the API lists, part of the PR would go unread: fail rather
// than pass it.
func TestDisclosureCollectRefusesAPullRequestPastTheAPICaps(t *testing.T) {
	for name, tc := range map[string]struct {
		commits, files int
		want           int
	}{
		"at both caps":    {250, 3000, collectOK},
		"one commit over": {251, 1, collectTooBig},
		"one file over":   {250, 3001, collectTooBig},
		"an empty PR":     {0, 0, collectOK},
	} {
		t.Run(name, func(t *testing.T) {
			event := strings.NewReplacer("COMMITS", strconv.Itoa(tc.commits), "FILES", strconv.Itoa(tc.files)).Replace(
				`{"pull_request": {"number": 7, "title": "T", "head": {"ref": "b"}, "commits": COMMITS, "changed_files": FILES, "author_association": "MEMBER"}}`)
			run := runCollect(t, "pr", event, map[string]string{"repos/acme/widgets/pulls/7/commits": `[]`})
			if run.code != tc.want {
				t.Fatalf("exit = %d, want %d", run.code, tc.want)
			}
			if tc.want == collectTooBig && (run.out != "" || len(run.calls) != 0) {
				t.Fatalf("collected %q with calls %q past the caps", run.out, run.calls)
			}
		})
	}
}

func TestDisclosureCollectRejectsBadUsage(t *testing.T) {
	if run := runCollect(t, "wiki", `{}`, nil); run.code != collectUsage {
		t.Fatalf("unknown kind: exit = %d, want %d", run.code, collectUsage)
	}
}
