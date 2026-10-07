package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		"no-break space":           "acme\u00a0widgets",
		"em space":                 "acme\u2003widgets",
		"ideographic space":        "acme\u3000widgets",
		"en dash":                  "acme\u2013labs",
		"minus sign":               "acme\u2212labs",
		"left-to-right mark":       "acme\u200e widgets",
		"right-to-left override":   "ac\u202eme widgets",
		"isolate":                  "ac\u2066me\u2069 widgets",
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

// A term's edge separators fold away, so ".example" matches the bare
// substring. The script says so, on stderr and under Actions as a warning
// annotation, naming the term by its place, never its text, whatever
// separator it was (an ASCII one, a Unicode dash or a no-break space), and
// still checks.
func TestDisclosureCheckWarnsWhenATermsEdgesFoldAway(t *testing.T) {
	terms := "acme widgets\n.acme-edge\nacme-tail_\n\u2013acme-dash\nacme-nbsp\u00a0\n"
	out, code := runDisclosureCheck(t, terms, "the acme edge case", []string{"GITHUB_ACTIONS=true"})
	if code != disclosureMatch {
		t.Fatalf("exit = %d, want %d; output:\n%s", code, disclosureMatch, out)
	}
	for n := 2; n <= 5; n++ {
		for _, prefix := range []string{"disclosure-check: ", "::warning::"} {
			if want := fmt.Sprintf("%sterm %d starts or ends with a separator", prefix, n); !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	}
	var rest []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "::add-mask::") {
			rest = append(rest, line)
		}
	}
	if joined := strings.Join(rest, "\n"); strings.Contains(joined, "term 1 ") ||
		strings.Contains(joined, "edge") || strings.Contains(joined, "tail") || strings.Contains(joined, "dash") || strings.Contains(joined, "nbsp") {
		t.Errorf("warned about a plain term, or echoed a term:\n%s", joined)
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
