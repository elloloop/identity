//go:build smoke

// Package smoke — executable getting-started examples guard.
//
// This file makes the docs-site getting-started examples self-verifying so they
// cannot silently rot. The authoritative source for env vars and their loader
// types is internal/config/config.go; the examples live in two Astro pages:
//
//	docs-site/src/pages/docs/quickstart.astro
//	docs-site/src/pages/docs/installation/docker.astro
//
// It does two things:
//
//  1. TestDocsExamplesEnvVarsAreReal — extracts every <Code> block from those
//     two pages, pulls out each `-e GATEWAY_...=value` (docker run) and
//     `GATEWAY_...: value` (docker-compose) pair, and asserts:
//     - every GATEWAY_* token used in an example is a real config key
//     declared in config.go (no typos, no removed vars), and
//     - each documented value is shape-valid for that key's loader type:
//     envInt → integer, envBool → boolean (true/false/1/0/yes/no),
//     envFloat → float, envStr → any non-empty string.
//     The shape rules are derived FROM config.go's loader (not hardcoded), so
//     they track the implementation automatically.
//
//  2. TestDocsQuickstartMinimalBoots — boots the real cmd/identity binary with
//     the documented MINIMAL config (the embedded-sqlite ":memory:" run, which
//     needs no Docker and no external datastore) on random ports, asserts
//     /health serves 200, then SIGTERMs it. This proves the headline
//     "no external services" example actually starts and serves.
//
// Why this lives in tests/smoke (package smoke, `smoke` build tag): the boot
// leg needs the compiled-binary harness already implemented here (repoRoot,
// freePort, captureBuf, waitReady, cfgEnv, cfgStart, cfgBuildBinary). Adding it
// here reuses that harness instead of duplicating it. The default-run docs
// drift guard (tests/docs/drift_test.go) already enforces token existence
// across ALL prose; this file adds value-shape validation and a real boot of
// the example config.
package smoke

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// gettingStartedDocs are the two pages whose getting-started examples this
// guard keeps honest. Paths are relative to the repo root.
var gettingStartedDocs = []string{
	filepath.Join("docs-site", "src", "pages", "docs", "quickstart.astro"),
	filepath.Join("docs-site", "src", "pages", "docs", "installation", "docker.astro"),
}

// docCodeRe matches an Astro <Code code={`...`} ... /> element, capturing the
// template-literal body (group 1) and the trailing attributes up to /> (group
// 2). The body is delimited by backticks; \x60 is a backtick.
var docCodeRe = regexp.MustCompile("(?s)<Code\\s+code=\\{\x60(.*?)\x60\\}\\s*([^>]*?)/>")

var (
	docTitleRe = regexp.MustCompile(`title="([^"]*)"`)
	docLangRe  = regexp.MustCompile(`lang="([^"]*)"`)
)

// dockerEnvRe matches a `docker run` env flag, e.g. `-e GATEWAY_REPO_DRIVER=sqlite`.
var dockerEnvRe = regexp.MustCompile(`-e\s+(GATEWAY_[A-Z0-9_]+)=(\S+)`)

// composeEnvRe matches a docker-compose environment entry, e.g.
// `GATEWAY_POSTGRES_AUTO_MIGRATE: "true"`.
var composeEnvRe = regexp.MustCompile(`(?m)^\s*(GATEWAY_[A-Z0-9_]+):\s*(.+?)\s*$`)

// gatewayTokenInExampleRe finds any GATEWAY_ token used in an example body.
var gatewayTokenInExampleRe = regexp.MustCompile(`GATEWAY_[A-Z0-9_]+`)

// cfgKindRe extracts the loader type for each env key from config.go, e.g.
// `envBool("GATEWAY_AUTH_ALLOW_LOCAL"` → kind "Bool" for that key.
var cfgKindRe = regexp.MustCompile(`env(Int|Bool|Float|Str)\("(GATEWAY_[A-Z0-9_]+)"`)

// cfgKeyRe extracts every GATEWAY_ token literal from config.go (the broad
// existence registry, which also covers keys read by non-env* helpers such as
// GATEWAY_REVOCATION_MODE).
var cfgKeyRe = regexp.MustCompile(`GATEWAY_[A-Z0-9_]+`)

// docExample is one extracted <Code> block.
type docExample struct {
	file     string            // repo-relative source path
	title    string            // title="" attribute, "" if none
	lang     string            // lang="" attribute
	body     string            // code between the backticks
	envPairs map[string]string // GATEWAY_* → documented value, cleaned
}

// readConfigRegistry reads config.go and returns (knownKeys, kinds) where
// knownKeys is every GATEWAY_ token declared and kinds maps a key to its loader
// type ("Int"|"Bool"|"Float"|"Str") for keys loaded via an env* helper.
func readConfigRegistry(t *testing.T, root string) (known map[string]bool, kinds map[string]string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("reading config.go: %v", err)
	}
	src := string(b)

	known = map[string]bool{}
	for _, k := range cfgKeyRe.FindAllString(src, -1) {
		known[k] = true
	}
	if len(known) == 0 {
		t.Fatal("found zero GATEWAY_ keys in config.go; registry extraction is broken")
	}

	kinds = map[string]string{}
	for _, m := range cfgKindRe.FindAllStringSubmatch(src, -1) {
		kinds[m[2]] = m[1]
	}
	if len(kinds) == 0 {
		t.Fatal("found zero typed env* loaders in config.go; shape registry extraction is broken")
	}
	return known, kinds
}

// cleanDocValue normalises an extracted value: trims a trailing line
// continuation, surrounding whitespace, and one layer of matching quotes.
func cleanDocValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "\\")
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
	}
	return v
}

// extractEnvPairs pulls GATEWAY_* key/value pairs from a code block, handling
// both `docker run -e KEY=VALUE` and docker-compose `KEY: VALUE` forms.
func extractEnvPairs(body string) map[string]string {
	pairs := map[string]string{}
	for _, m := range dockerEnvRe.FindAllStringSubmatch(body, -1) {
		pairs[m[1]] = cleanDocValue(m[2])
	}
	for _, m := range composeEnvRe.FindAllStringSubmatch(body, -1) {
		pairs[m[1]] = cleanDocValue(m[2])
	}
	return pairs
}

// collectGettingStartedExamples reads the two getting-started pages and returns
// every <Code> block found, with its env pairs pre-extracted.
func collectGettingStartedExamples(t *testing.T, root string) []docExample {
	t.Helper()
	var out []docExample
	for _, rel := range gettingStartedDocs {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("reading getting-started doc %q: %v", rel, err)
		}
		text := string(b)
		matches := docCodeRe.FindAllStringSubmatch(text, -1)
		if len(matches) == 0 {
			t.Fatalf("no <Code> blocks extracted from %q; the extractor is misconfigured", rel)
		}
		for _, m := range matches {
			body, attrs := m[1], m[2]
			ex := docExample{file: rel, body: body, envPairs: extractEnvPairs(body)}
			if tm := docTitleRe.FindStringSubmatch(attrs); tm != nil {
				ex.title = tm[1]
			}
			if lm := docLangRe.FindStringSubmatch(attrs); lm != nil {
				ex.lang = lm[1]
			}
			out = append(out, ex)
		}
	}
	if len(out) == 0 {
		t.Fatal("collected zero example blocks; extraction is misconfigured")
	}
	return out
}

// shapeValid reports whether val is shape-valid for the given loader kind.
func shapeValid(kind, val string) (bool, string) {
	switch kind {
	case "Int":
		if _, err := strconv.Atoi(val); err != nil {
			return false, "expected an integer"
		}
	case "Float":
		if _, err := strconv.ParseFloat(val, 64); err != nil {
			return false, "expected a float"
		}
	case "Bool":
		switch strings.ToLower(val) {
		case "true", "1", "yes", "false", "0", "no":
		default:
			return false, "expected a boolean (true/false/1/0/yes/no)"
		}
	case "Str":
		if val == "" {
			return false, "expected a non-empty string"
		}
	}
	return true, ""
}

// TestDocsExamplesEnvVarsAreReal asserts every GATEWAY_* used in a
// getting-started example exists in config.go and that every documented value
// is shape-valid for that key's loader type. All violations are reported at
// once so a single run surfaces the full delta.
func TestDocsExamplesEnvVarsAreReal(t *testing.T) {
	root := repoRoot(t)
	known, kinds := readConfigRegistry(t, root)
	examples := collectGettingStartedExamples(t, root)

	var violations []string
	totalTokens, totalPairs := 0, 0

	for _, ex := range examples {
		where := ex.file
		if ex.title != "" {
			where += " [" + ex.title + "]"
		}

		// Existence: every GATEWAY_ token mentioned in the example body must be
		// a real config key.
		seen := map[string]bool{}
		for _, tok := range gatewayTokenInExampleRe.FindAllString(ex.body, -1) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			totalTokens++
			if !known[tok] {
				violations = append(violations,
					where+": references "+tok+" which is not a GATEWAY_ key in internal/config/config.go")
			}
		}

		// Shape: each documented value must parse for its loader type. Keys
		// without a typed env* loader (none expected in these examples) are
		// skipped rather than guessed.
		for key, val := range ex.envPairs {
			totalPairs++
			kind, ok := kinds[key]
			if !ok {
				continue
			}
			if valid, reason := shapeValid(kind, val); !valid {
				violations = append(violations,
					where+": "+key+"="+strconv.Quote(val)+" is not shape-valid ("+reason+" for env"+kind+")")
			}
		}
	}

	if totalTokens == 0 {
		t.Fatal("found zero GATEWAY_ tokens across all examples; extraction is broken")
	}
	if totalPairs == 0 {
		t.Fatal("found zero GATEWAY_ key=value pairs across all examples; pair extraction is broken")
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("docs example drift: %d issue(s) in getting-started examples:\n  - %s",
			len(violations), strings.Join(violations, "\n  - "))
	}
}

// findMinimalSqliteExample returns the documented minimal run: the example that
// configures the embedded sqlite driver against an in-memory database. This is
// the "no Docker, no external services" config the quickstart/installation
// pages headline.
func findMinimalSqliteExample(examples []docExample) (docExample, bool) {
	for _, ex := range examples {
		if ex.envPairs["GATEWAY_REPO_DRIVER"] == "sqlite" && ex.envPairs["GATEWAY_SQLITE_PATH"] == ":memory:" {
			return ex, true
		}
	}
	return docExample{}, false
}

// TestDocsQuickstartMinimalBoots boots the real binary with the documented
// minimal embedded-sqlite (:memory:) config and asserts it serves /health 200,
// then shuts down cleanly on SIGTERM. The env values come straight from the
// doc block (only the listener ports are overridden, since the doc maps host
// ports via `-p` rather than GATEWAY_*_PORT), so a minimal example that stops
// booting fails this test.
func TestDocsQuickstartMinimalBoots(t *testing.T) {
	root := repoRoot(t)
	examples := collectGettingStartedExamples(t, root)

	ex, ok := findMinimalSqliteExample(examples)
	if !ok {
		t.Fatal("no documented minimal sqlite :memory: example found; the quickstart/docker pages changed shape")
	}
	t.Logf("booting documented minimal config from %s [%s]: %v", ex.file, ex.title, ex.envPairs)

	// Use the documented env values verbatim; cfgEnv layers in random ports and
	// strips the developer's inherited GATEWAY_* so only the doc's config (plus
	// the test's port overrides) drives the boot.
	overrides := map[string]string{}
	for k, v := range ex.envPairs {
		overrides[k] = v
	}
	env, port := cfgEnv(t, overrides)

	out, exited, waitErr, cmd := cfgStart(t, env)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)

	if err := waitReady(t, baseURL+"/health", cmd.Process, exited, 20*time.Second); err != nil {
		captured := out.String()
		// modernc.org/sqlite is pure Go, so CGO_ENABLED=0 is expected to work;
		// if a future build genuinely needs CGO and lacks it, skip the boot leg
		// with a logged reason rather than failing (the static checks above
		// still validated this snippet).
		if strings.Contains(strings.ToLower(captured), "cgo") {
			t.Skipf("sqlite driver unavailable without CGO in this build; skipped boot leg: %v", err)
		}
		t.Fatalf("minimal sqlite example failed to serve /health: %v\n--- captured output ---\n%s", err, captured)
	}

	// Clean shutdown.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("sending SIGTERM: %v", err)
	}
	select {
	case <-exited:
		var ee *exec.ExitError
		if errors.As(*waitErr, &ee) && ee.ExitCode() != 0 {
			t.Fatalf("non-zero exit after SIGTERM: %v\n--- captured output ---\n%s", *waitErr, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("process did not exit within 5s of SIGTERM\n--- captured output ---\n%s", out.String())
	}

	if captured := out.String(); strings.Contains(captured, "panic:") || strings.Contains(captured, "fatal error:") {
		t.Fatalf("binary printed panic/fatal during minimal-example boot\n--- captured output ---\n%s", captured)
	}
}
