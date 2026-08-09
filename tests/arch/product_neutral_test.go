// This test enforces the product-neutrality invariant:
//
//	elloloop/identity is a generic, product-agnostic identity server. No
//	consumer-specific value — a deployment's product names, project slugs,
//	domains, or operators' email addresses — may be hardcoded anywhere in
//	source, tests, or docs. Those values are injected at deploy time via
//	GATEWAY_* env and belong only to the consumer's own deployment config.
//
// Why this matters: consumer values accreted into tests and comments over
// several PRs (a real operator allowlist shipped in a test fixture; a
// specific product slug became the server-wide default product). Each one
// leaks deployment information in a public repo and misleads every reader
// into treating one consumer's deployment as the server's own shape. This
// test makes neutrality an enforced invariant rather than a convention.
//
// The guard is name-based, not email-shape-based: the gmail-canonicalization
// feature legitimately references public mailbox domains in both code and
// tests, so banning non-example addresses wholesale would false-positive on
// the feature itself. It bans the specific consumer identifiers instead —
// generic words (e.g. a bare "hold") are deliberately NOT banned for the
// same reason. New consumer deployments add their identifiers here BEFORE
// their values can accrete, not after a cleanup.
//
// It is a plain `go test` (no build tag) so it runs in the default
// `go test ./...` set and in the dedicated arch CI job.
package arch_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// consumerIdentifierRe matches the consumer-specific identifiers that must
// never appear in this repo, case-insensitively. Generic English words are
// intentionally absent — precision beats recall here, because a false
// positive trains people to disable the guard.
var consumerIdentifierRe = regexp.MustCompile(
	`(?i)tinykite|nesta|arun88m|sowjanya|cursive\.ai|admin-gloss|account-portal`)

// neutralExts are the authored text formats the guard scans. Binary and
// image formats are skipped by omission.
var neutralExts = map[string]bool{
	".go": true, ".md": true, ".yaml": true, ".yml": true, ".json": true,
	".proto": true, ".toml": true, ".ts": true, ".tsx": true, ".js": true,
	".mjs": true, ".sh": true, ".sql": true, ".py": true, ".astro": true,
}

// neutralSkipDirs are directory names skipped anywhere in the walk:
// VCS metadata, dependency trees, and build output are not authored content.
var neutralSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist": true, ".astro": true, "testdata": true,
}

// neutralSkipPrefixes are repo-relative path prefixes excluded for a
// specific reason. Paths are slash-separated.
var neutralSkipPrefixes = map[string]string{
	"docs-site/public/scalar/": "vendored minified bundles — third-party bytes, not authored content",
	".antigravitycli/":         "tool session state — transient, not authored content",
}

// neutralExemptFiles are files that legitimately contain the banned
// patterns as data rather than as consumer values.
var neutralExemptFiles = map[string]string{
	"tests/arch/product_neutral_test.go": "the guard itself carries the patterns as data",
}

// neutralSkipFiles are individual file names skipped anywhere: lockfiles
// record third-party dependency data, not authored content.
var neutralSkipFiles = map[string]bool{
	"go.sum": true, "pnpm-lock.yaml": true, "package-lock.json": true, "yarn.lock": true,
}

func TestProductNeutralRepo(t *testing.T) {
	root := repoRoot(t)

	var violations []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if neutralSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for prefix := range neutralSkipPrefixes {
			if strings.HasPrefix(rel, prefix) {
				return nil
			}
		}
		if _, ok := neutralExemptFiles[rel]; ok {
			return nil
		}
		// Untracked local scratch files (*.local.md) are git-excluded by
		// convention and must never be committed; they are out of scope.
		if strings.HasSuffix(rel, ".local.md") {
			return nil
		}
		if neutralSkipFiles[filepath.Base(path)] {
			return nil
		}
		if !neutralExts[filepath.Ext(path)] {
			return nil
		}
		scanned++
		violations = append(violations, scanNeutral(t, rel, path)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo: %v", err)
	}

	if scanned == 0 {
		t.Fatal("scanned zero files; the walker is misconfigured")
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("product neutrality: %d consumer identifier(s) found — "+
			"consumer names, slugs, domains, and addresses belong in the deployment's "+
			"env config, not in this repo:\n  - %s",
			len(violations), strings.Join(violations, "\n  - "))
	}
}

// scanNeutral returns a violation string (file:line: match) for every line
// containing a banned consumer identifier.
func scanNeutral(t *testing.T, rel, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // transient file vanished mid-walk (tool state dirs)
	}
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	var out []string
	for i, line := range strings.Split(string(data), "\n") {
		if m := consumerIdentifierRe.FindString(line); m != "" {
			out = append(out, rel+":"+strconv.Itoa(i+1)+": consumer identifier "+strconv.Quote(m))
		}
	}
	return out
}
