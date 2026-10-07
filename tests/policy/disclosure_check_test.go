package policy

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Exit statuses of scripts/disclosure-check.sh.
const (
	disclosureClean    = 0
	disclosureMatch    = 1
	disclosureNoTerms  = 3
	disclosureTermsEnv = "CONFIDENTIAL_TERMS"
)

// The terms below are made up for the tests; the real list lives only in
// the CONFIDENTIAL_TERMS repository secret.
const testTerms = "acme widgets\nsecret.example.test\nacme-labs\n"

func TestDisclosureCheckFindsTerms(t *testing.T) {
	for name, text := range map[string]string{
		"exact":                  "We ship acme widgets.",
		"case-insensitive":       "Ask ACME Widgets about it",
		"split across lines":     "acme\nwidgets",
		"extra whitespace":       "acme \t  widgets",
		"hostname in a URL":      "see https://login.secret.example.test/reset",
		"substring of a word":    "the acme-labs2 repo",
		"term in a later line":   "line one\nline two\nACME-LABS",
		"added diff line marker": "+\tbase := \"https://secret.example.test\"",
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runDisclosureCheck(t, testTerms, text, nil)
			if code != disclosureMatch {
				t.Fatalf("exit = %d, want %d (match); output:\n%s", code, disclosureMatch, out)
			}
			assertNoTermIn(t, out)
		})
	}
}

func TestDisclosureCheckPassesCleanText(t *testing.T) {
	for name, text := range map[string]string{
		"neutral examples":         "Use acme, example.com and example.test.",
		"words apart":              "acme ships widgets",
		"separator not a wildcard": "secretXexampleXtest",
		"empty text":               "",
		"term with a word inside":  "acme-big-labs",
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runDisclosureCheck(t, testTerms, text, nil)
			if code != disclosureClean {
				t.Fatalf("exit = %d, want %d (clean); output:\n%s", code, disclosureClean, out)
			}
		})
	}
}

// The text and the terms fold the same way: '-', '_' and '.' are
// whitespace, and zero-width characters are dropped, so another separator
// or an invisible character does not hide a term.
func TestDisclosureCheckFoldsSeparatorsAndInvisibleCharacters(t *testing.T) {
	for name, text := range map[string]string{
		"hyphen for a space":       "acme-widgets",
		"underscore for a space":   "ACME_Widgets",
		"dot for a space":          "acme.widgets",
		"space for a hyphen":       "acme labs",
		"underscore for a hyphen":  "ACME_LABS",
		"hyphens for dots":         "secret-example-test",
		"zero-width space":         "ac\u200bme-labs",
		"zero-width non-joiner":    "acme \u200cwidgets",
		"zero-width joiner":        "acme\u200d widgets",
		"byte order mark":          "\ufeffsecret.example.test",
		"soft hyphen":              "ac\u00adme widgets",
		"word joiner":              "acme\u2060 widgets",
		"Mongolian vowel sep":      "acme \u180ewidgets",
		"separators and invisible": "acme\u200b_\u200blabs",
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runDisclosureCheck(t, testTerms, text, nil)
			if code != disclosureMatch {
				t.Fatalf("exit = %d, want %d (match); output:\n%s", code, disclosureMatch, out)
			}
			assertNoTermIn(t, out)
		})
	}
	for name, text := range map[string]string{
		"no separator at all":   "acmelabs",
		"slash is not folded":   "acme/labs",
		"invisible joins words": "acme\u200bwidgets",
	} {
		t.Run(name, func(t *testing.T) {
			if out, code := runDisclosureCheck(t, testTerms, text, nil); code != disclosureClean {
				t.Fatalf("exit = %d, want %d (clean); output:\n%s", code, disclosureClean, out)
			}
		})
	}
}

// A blank line in the list must not become an empty pattern, which would
// match every text.
func TestDisclosureCheckIgnoresBlankAndCRLFLines(t *testing.T) {
	terms := "\r\n\n  \nacme widgets\r\n\n"
	if out, code := runDisclosureCheck(t, terms, "nothing to see here", nil); code != disclosureClean {
		t.Fatalf("clean text: exit = %d, want %d; output:\n%s", code, disclosureClean, out)
	}
	if out, code := runDisclosureCheck(t, terms, "ACME WIDGETS", nil); code != disclosureMatch {
		t.Fatalf("term with CRLF list: exit = %d, want %d; output:\n%s", code, disclosureMatch, out)
	}
}

// Terms are literal strings, never patterns: regex metacharacters neither
// widen a match nor break the matcher.
func TestDisclosureCheckTreatsTermsLiterally(t *testing.T) {
	terms := "a*b\na+b\n[unclosed\n(x|y)\n"
	if out, code := runDisclosureCheck(t, terms, "b ab aab x y", nil); code != disclosureClean {
		t.Fatalf("metacharacters widened the match: exit = %d; output:\n%s", code, out)
	}
	for _, text := range []string{"a [unclosed bracket", "1 a+b 2", "A*B"} {
		if out, code := runDisclosureCheck(t, terms, text, nil); code != disclosureMatch {
			t.Fatalf("literal term in %q: exit = %d, want %d; output:\n%s", text, code, disclosureMatch, out)
		}
	}
}

func TestDisclosureCheckWithoutTermsReportsUnconfigured(t *testing.T) {
	for name, terms := range map[string]*string{
		"unset":           nil,
		"empty":           ptr(""),
		"whitespace only": ptr(" \n\t\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runDisclosureCheckEnv(t, terms, "acme widgets", nil)
			if code != disclosureNoTerms {
				t.Fatalf("exit = %d, want %d (no terms); output:\n%s", code, disclosureNoTerms, out)
			}
		})
	}
}

// Under GitHub Actions every term is registered as a mask, as written and
// as folded, before anything else runs, and the masks are the only place a
// term appears: the runner consumes ::add-mask:: lines instead of printing
// them.
func TestDisclosureCheckMasksTermsUnderGitHubActions(t *testing.T) {
	out, code := runDisclosureCheck(t, "acme  widgets\nacme-labs\n", "Acme Widgets", []string{"GITHUB_ACTIONS=true"})
	if code != disclosureMatch {
		t.Fatalf("exit = %d, want %d; output:\n%s", code, disclosureMatch, out)
	}
	var masks, rest []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "::add-mask::") {
			masks = append(masks, strings.TrimPrefix(line, "::add-mask::"))
			continue
		}
		rest = append(rest, line)
	}
	if strings.Join(masks, "|") != "acme widgets|acme-labs|acme labs" {
		t.Fatalf("masks = %q, want each term as written and, where it differs, folded", masks)
	}
	assertNoTermIn(t, strings.Join(rest, "\n"))
}

func assertNoTermIn(t *testing.T, out string) {
	t.Helper()
	lower := strings.ToLower(out)
	for _, term := range []string{"acme", "widgets", "secret.example", "labs"} {
		if strings.Contains(lower, term) {
			t.Fatalf("output echoes part of a confidential term (%q):\n%s", term, out)
		}
	}
}

func runDisclosureCheck(t *testing.T, terms, text string, env []string) (string, int) {
	t.Helper()
	return runDisclosureCheckEnv(t, &terms, text, env)
}

// runDisclosureCheckEnv runs the script with CONFIDENTIAL_TERMS set to
// *terms, or unset when terms is nil, and returns its combined output and
// exit status.
func runDisclosureCheckEnv(t *testing.T, terms *string, text string, env []string) (string, int) {
	t.Helper()

	//nolint:gosec // The command is the repository-owned disclosure script.
	cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts", "disclosure-check.sh"))
	cmd.Dir = repoRoot(t)
	cmd.Env = withoutEnv(os.Environ(), disclosureTermsEnv, "GITHUB_ACTIONS")
	if terms != nil {
		cmd.Env = append(cmd.Env, disclosureTermsEnv+"="+*terms)
	}
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = strings.NewReader(text)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &exitErr):
		return out.String(), exitErr.ExitCode()
	default:
		t.Fatalf("run disclosure-check.sh: %v", err)
		return "", -1
	}
}

func withoutEnv(env []string, names ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		keep := true
		for _, name := range names {
			if strings.HasPrefix(kv, name+"=") {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}

func ptr(s string) *string { return &s }

var (
	jobLine        = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):$`)
	permissionLine = regexp.MustCompile(`^ {6}([a-z-]+): ([a-z]+)$`)
	runLine        = regexp.MustCompile(`^( *)(?:- )?run:(.*)$`)
	checkoutRef    = regexp.MustCompile(`(?m)^\s+ref:`)
	termsName      = regexp.MustCompile(`(?i)confidential_terms`)
	termsBinding   = regexp.MustCompile(`^ {10}CONFIDENTIAL_TERMS: \$\{\{ secrets\.CONFIDENTIAL_TERMS \}\}$`)
)

func disclosureWorkflow(t *testing.T, name string) string {
	t.Helper()
	return readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", name))
}

// The Disclosure workflow runs with secrets on pull_request_target, so the
// guarantees that make that safe are pinned here: it triggers only where
// its one job reports the required check, it starts from no permissions and
// the job holds only what it needs, it never checks out anything but the
// base branch's scripts, it never reads the PR head or any event text by
// expression, and the term list never enters its own shell.
func TestDisclosureWorkflowNeverRunsPullRequestCode(t *testing.T) {
	wf := disclosureWorkflow(t, "disclosure.yml")

	// Any other trigger would attach a skipped "Disclosure" job to the PR
	// head, which GitHub counts as a pass for the required check.
	if got, want := workflowTriggers(wf), map[string]string{
		"pull_request_target": "[opened, edited, synchronize, reopened]",
		"merge_group":         "[checks_requested]",
	}; !maps.Equal(got, want) {
		t.Errorf("disclosure.yml triggers = %v, want exactly %v", got, want)
	}
	jobs := workflowJobs(t, wf)
	if got := slices.Sorted(maps.Keys(jobs)); !slices.Equal(got, []string{"pull-request"}) {
		t.Fatalf("disclosure.yml jobs = %v, want only pull-request", got)
	}
	if got, want := jobPermissions(jobs["pull-request"]), map[string]string{"contents": "read", "pull-requests": "read"}; !maps.Equal(got, want) {
		t.Errorf("pull-request permissions = %v, want exactly %v", got, want)
	}
	if !strings.Contains(jobs["pull-request"], "    name: Disclosure\n") {
		t.Error("the pull-request job must report the Disclosure check")
	}
	if strings.Contains(jobs["pull-request"], "\n    if:") {
		t.Error("the Disclosure job must run on every event of its workflow, never skip")
	}
	assertDisclosureWorkflowBasics(t, "disclosure.yml", wf)
}

// Issues, comments and reviews are checked by a workflow of their own, under
// another check name, so none of their runs touches the required check.
func TestDisclosureDiscussionWorkflow(t *testing.T) {
	wf := disclosureWorkflow(t, "disclosure-discussion.yml")

	if got, want := workflowTriggers(wf), map[string]string{
		"issues":                      "[opened, edited]",
		"issue_comment":               "[created, edited]",
		"pull_request_review":         "[submitted, edited]",
		"pull_request_review_comment": "[created, edited]",
	}; !maps.Equal(got, want) {
		t.Errorf("disclosure-discussion.yml triggers = %v, want exactly %v", got, want)
	}
	jobs := workflowJobs(t, wf)
	if got := slices.Sorted(maps.Keys(jobs)); !slices.Equal(got, []string{"discussion"}) {
		t.Fatalf("disclosure-discussion.yml jobs = %v, want only discussion", got)
	}
	if got, want := jobPermissions(jobs["discussion"]), map[string]string{"contents": "read", "issues": "write"}; !maps.Equal(got, want) {
		t.Errorf("discussion permissions = %v, want exactly %v", got, want)
	}
	if strings.Contains(jobs["discussion"], "    name: Disclosure\n") {
		t.Error("the discussion job must not report the required Disclosure check")
	}
	assertDisclosureWorkflowBasics(t, "disclosure-discussion.yml", wf)
}

// assertDisclosureWorkflowBasics pins what both Disclosure workflows share:
// no permissions by default, a checkout of only the two scripts with no ref
// and no credentials, no event text read by expression, and the term list
// confined to one env binding per check step.
func assertDisclosureWorkflowBasics(t *testing.T, name, wf string) {
	t.Helper()
	if !strings.Contains(wf, "\npermissions: {}\n") {
		t.Errorf("%s must start from no permissions", name)
	}

	checkouts := strings.Count(wf, "uses: actions/checkout@")
	if checkouts == 0 {
		t.Fatalf("%s has no checkout of the scripts", name)
	}
	for _, want := range []string{
		"persist-credentials: false",
		"sparse-checkout: |\n            scripts/disclosure-collect.sh\n            scripts/disclosure-check.sh\n",
	} {
		if got := strings.Count(wf, want); got != checkouts {
			t.Errorf("%s: %d checkout(s) but %q appears %d time(s)", name, checkouts, want, got)
		}
	}
	if checkoutRef.MatchString(wf) {
		t.Errorf("%s must not set a checkout ref", name)
	}
	for _, forbidden := range []string{
		"github.event.pull_request.head",  // the PR head by expression
		"github.event.pull_request.title", // event text interpolated into a step
		"github.event.pull_request.body",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.comment.body",
		"github.event.review.body",
		"head_commit",
		"pull-requests: write",
		"contents: write",
	} {
		if strings.Contains(wf, forbidden) {
			t.Errorf("%s must not contain %q", name, forbidden)
		}
	}

	// The term list reaches only the matcher, through one env binding per
	// check step: it is never named in a run block, in any spelling.
	for _, run := range runBlocks(wf) {
		if termsName.MatchString(run) {
			t.Errorf("%s: a run block names the term list:\n%s", name, run)
		}
	}
	bindings := 0
	for _, line := range strings.Split(wf, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !termsName.MatchString(line), strings.HasPrefix(trimmed, "#"):
		case termsBinding.MatchString(line):
			bindings++
		default:
			t.Errorf("%s: the term list appears outside its env binding: %q", name, trimmed)
		}
	}
	if checks := strings.Count(wf, "- name: Check for confidential terms\n"); bindings != 1 || checks != 1 {
		t.Errorf("%s: %d env binding(s) of the term list for %d check step(s), want one of each", name, bindings, checks)
	}
}

// workflowTriggers reads a workflow's `on:` block as event -> types.
func workflowTriggers(wf string) map[string]string {
	_, block, ok := strings.Cut(wf, "\non:\n")
	if !ok {
		return nil
	}
	triggers := map[string]string{}
	event := ""
	for _, line := range strings.Split(block, "\n") {
		switch {
		case line == "":
		case !strings.HasPrefix(line, " "):
			return triggers
		case strings.HasPrefix(line, "    types: "):
			triggers[event] = strings.TrimPrefix(line, "    types: ")
		default:
			event = strings.TrimSuffix(strings.TrimSpace(line), ":")
			triggers[event] = ""
		}
	}
	return triggers
}

// workflowJobs splits a workflow's jobs block into each job's text, keyed by
// job id. It relies on the two-space indentation every workflow here uses.
func workflowJobs(t *testing.T, wf string) map[string]string {
	t.Helper()
	_, body, ok := strings.Cut(wf, "\njobs:\n")
	if !ok {
		t.Fatal("workflow has no jobs block")
	}
	jobs := map[string]string{}
	id := ""
	for _, line := range strings.Split(body, "\n") {
		if m := jobLine.FindStringSubmatch(line); m != nil {
			id = m[1]
		}
		if id != "" {
			jobs[id] += line + "\n"
		}
	}
	return jobs
}

// jobPermissions reads a job's permissions block as a map.
func jobPermissions(job string) map[string]string {
	_, block, ok := strings.Cut(job, "\n    permissions:\n")
	if !ok {
		return nil
	}
	perms := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		m := permissionLine.FindStringSubmatch(line)
		if m == nil {
			break
		}
		perms[m[1]] = m[2]
	}
	return perms
}

// runBlocks returns the body of every `run: |` block and every one-line
// `run:` in a workflow.
func runBlocks(wf string) []string {
	var blocks []string
	lines := strings.Split(wf, "\n")
	for i := 0; i < len(lines); i++ {
		m := runLine.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		if rest := strings.TrimSpace(m[2]); rest != "|" && rest != ">" {
			blocks = append(blocks, rest)
			continue
		}
		var body []string
		for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || indent(lines[i+1]) > len(m[1])) {
			i++
			body = append(body, lines[i])
		}
		blocks = append(blocks, strings.Join(body, "\n"))
	}
	return blocks
}

func indent(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }
