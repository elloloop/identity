package policy

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
const testTerms = "acme widgets\nsecret.example.test\nproject-falcon\n"

func TestDisclosureCheckFindsTerms(t *testing.T) {
	for name, text := range map[string]string{
		"exact":                  "We ship acme widgets.",
		"case-insensitive":       "Ask ACME Widgets about it",
		"split across lines":     "acme\nwidgets",
		"extra whitespace":       "acme \t  widgets",
		"hostname in a URL":      "see https://login.secret.example.test/reset",
		"substring of a word":    "the project-falcons repo",
		"term in a later line":   "line one\nline two\nPROJECT-FALCON",
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
		"neutral examples":        "Use acme, example.com and example.test.",
		"words apart":             "acme ships widgets",
		"dot is literal":          "secretXexampleXtest",
		"empty text":              "",
		"term with a word inside": "project-big-falcon",
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runDisclosureCheck(t, testTerms, text, nil)
			if code != disclosureClean {
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
	terms := "a.b\n[unclosed\n(x|y)\n"
	if out, code := runDisclosureCheck(t, terms, "axb x y", nil); code != disclosureClean {
		t.Fatalf("metacharacters widened the match: exit = %d; output:\n%s", code, out)
	}
	if out, code := runDisclosureCheck(t, terms, "a [unclosed bracket", nil); code != disclosureMatch {
		t.Fatalf("literal bracket term: exit = %d, want %d; output:\n%s", code, disclosureMatch, out)
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

// Under GitHub Actions every term is registered as a mask before anything
// else runs, and the masks are the only place a term appears: the runner
// consumes ::add-mask:: lines instead of printing them.
func TestDisclosureCheckMasksTermsUnderGitHubActions(t *testing.T) {
	out, code := runDisclosureCheck(t, "acme  widgets\nproject-falcon\n", "Acme Widgets", []string{"GITHUB_ACTIONS=true"})
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
	if strings.Join(masks, "|") != "acme widgets|project-falcon" {
		t.Fatalf("masks = %q, want the two normalized terms", masks)
	}
	assertNoTermIn(t, strings.Join(rest, "\n"))
}

func assertNoTermIn(t *testing.T, out string) {
	t.Helper()
	lower := strings.ToLower(out)
	for _, term := range []string{"acme", "widgets", "secret.example", "falcon"} {
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

// The Disclosure workflow runs with secrets on pull_request_target, so the
// guarantees that make that safe are pinned here: it starts from no
// permissions, never checks out anything but the base branch's matcher,
// never reads the PR head by expression, and never handles the term list
// in its own shell.
func TestDisclosureWorkflowNeverRunsPullRequestCode(t *testing.T) {
	wf := readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "disclosure.yml"))

	for _, want := range []string{
		"pull_request_target:\n    types: [opened, edited, synchronize, reopened]",
		"issues:\n    types: [opened, edited]",
		"issue_comment:\n    types: [created, edited]",
		"\npermissions: {}\n",
		"    name: Disclosure\n",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("disclosure.yml is missing %q", want)
		}
	}

	checkouts := strings.Count(wf, "uses: actions/checkout@")
	if checkouts == 0 {
		t.Fatal("disclosure.yml has no checkout of the matcher")
	}
	for _, want := range []string{"persist-credentials: false", "sparse-checkout: scripts/disclosure-check.sh"} {
		if got := strings.Count(wf, want); got != checkouts {
			t.Errorf("%d checkout(s) but %q appears %d time(s)", checkouts, want, got)
		}
	}
	// A checkout pointed anywhere but the base branch.
	if regexp.MustCompile(`(?m)^\s+ref:`).MatchString(wf) {
		t.Error("disclosure.yml must not set a checkout ref")
	}
	for _, forbidden := range []string{
		"github.event.pull_request.head",  // the PR head by expression
		"github.event.pull_request.title", // PR text interpolated into a step
		"github.event.pull_request.body",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.comment.body",
		"$CONFIDENTIAL_TERMS", // the list handled in the workflow's shell
		"pull-requests: write",
		"contents: write",
	} {
		if strings.Contains(wf, forbidden) {
			t.Errorf("disclosure.yml must not contain %q", forbidden)
		}
	}
}
