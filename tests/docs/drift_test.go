// Package docs_test is a docs-anti-drift guard: it fails the build when prose
// in the docs site (docs-site/, Astro) or the long-form docs (docs/, Markdown)
// references a code identifier that does not exist in the implementation.
//
// It is deliberately a plain `go test` (no build tag) so it runs in the default
// `go test ./...` set and the dedicated "Docs drift" CI job. The authoritative
// registries it checks against are:
//
//   - GATEWAY_* env vars  → internal/config/config.go
//   - audit event types   → pkg/audit/logger.go (EventType string constants)
//   - RPC method names     → proto/identity/v1/identity.proto
//
// The API reference itself is generated from proto and never drifts; this guard
// extends that "single source of truth" philosophy to hand-written prose. Every
// check accumulates and reports ALL violations at once (file + token), not just
// the first, so a single run surfaces the full delta.
package docs_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// allowedGatewayTokens is the small, intentional escape hatch for GATEWAY_*
// tokens that legitimately appear in prose but are NOT live keys in
// internal/config/config.go. Keep it tiny and keep every entry justified —
// an unjustified entry defeats the whole guard.
//
// Two categories live here:
//
//  1. Removed/legacy env vars that the upgrade guide (docs/UPGRADE.md) names
//     precisely so operators know what to delete. They MUST be documented even
//     though — because — config.go no longer defines them.
//  2. Test-harness env vars read by *_test.go (e.g. the dockerpostgres DSN),
//     not by the runtime config, but referenced in ops/testing docs.
//
// NOTE: a token ending in "_" is treated as a prefix glob (see isPrefixToken),
// which already covers documented families like `GATEWAY_SMS_*` and prose that
// line-wraps a long name; such tokens do not belong here.
var allowedGatewayTokens = map[string]string{
	// (1) Removed in v1.0 (Project/Tenant/Domain redesign, ADR-0002); the
	// upgrade guide tells operators to unset them.
	"GATEWAY_IDENTITY_MODE":             "removed in v1.0; documented in docs/UPGRADE.md as an env var to delete",
	"GATEWAY_TENANT_HOST_BASE_DOMAIN":   "removed in v1.0; documented in docs/UPGRADE.md as an env var to delete",
	"GATEWAY_TENANT_RESOLUTION_SOURCES": "removed in v1.0; documented in docs/UPGRADE.md as an env var to delete",

	// Native OAuth per-product audience stopgap, superseded by per-project
	// config_json oauth.<provider>.native_audiences; documented in
	// docs/UPGRADE.md as removed env vars to migrate off.
	"GATEWAY_NATIVE_OAUTH_GOOGLE_AUDIENCES_BY_PRODUCT": "removed; migrate to per-project config_json native_audiences (docs/UPGRADE.md)",
	"GATEWAY_NATIVE_OAUTH_APPLE_AUDIENCES_BY_PRODUCT":  "removed; migrate to per-project config_json native_audiences (docs/UPGRADE.md)",

	// (2) Test-harness only: read by internal/repo/postgres/*_test.go and the
	// CI postgres legs, referenced in ops/testing docs (postgres-rls, redesign).
	"GATEWAY_TEST_POSTGRES_DSN": "test-harness env var (read by *_test.go and CI), not a runtime config key",
}

// gatewayTokenRe matches an env-var-shaped GATEWAY_ token (in docs prose or in
// the generated reference). A trailing underscore is captured (it signals a
// glob/wrapped fragment, handled below).
var gatewayTokenRe = regexp.MustCompile(`GATEWAY_[A-Z0-9_]+`)

// eventConstRe extracts the canonical audit event-type strings from the
// `Event... EventType = "..."` constant block in pkg/audit/logger.go.
var eventConstRe = regexp.MustCompile(`EventType\s*=\s*"([a-z0-9_]+)"`)

// docEventRe matches an audit event-type used in a docs example, e.g.
// `"eventType": "login_failure"`, `"event_type": "..."`, or `"event": "..."`.
var docEventRe = regexp.MustCompile(`"(?:eventType|event_type|event)"\s*:\s*"([a-z0-9_]+)"`)

// rpcURLRe matches an RPC referenced via its Connect/gRPC URL path in docs,
// e.g. `IdentityService/ListAuditEvents`. This URL form is an unambiguous RPC
// reference, which keeps the RPC check free of CamelCase false positives.
var rpcURLRe = regexp.MustCompile(`IdentityService/([A-Za-z0-9]+)`)

// protoRPCRe extracts RPC method names from the proto service definition.
var protoRPCRe = regexp.MustCompile(`rpc\s+([A-Za-z0-9]+)\s*\(`)

// repoRoot returns the repository root, derived from this test file's location
// (tests/docs/drift_test.go → three levels up). Using the source path rather
// than the working directory makes the test robust to how `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate repo root")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// docFile is one collected documentation file plus its text.
type docFile struct {
	relPath string
	text    string
}

// collectDocs walks docs-site/ (.astro) and docs/ (.md, .mdx), returning each
// file's relative path and contents.
func collectDocs(t *testing.T, root string) []docFile {
	t.Helper()
	var out []docFile

	roots := []struct {
		dir  string
		exts map[string]bool
	}{
		{dir: "docs-site", exts: map[string]bool{".astro": true}},
		{dir: "docs", exts: map[string]bool{".md": true, ".mdx": true}},
	}

	for _, r := range roots {
		base := filepath.Join(root, r.dir)
		if _, err := os.Stat(base); err != nil {
			t.Fatalf("expected docs dir %q to exist: %v", r.dir, err)
		}
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Skip dependency / build output trees under the Astro site.
				if d.Name() == "node_modules" || d.Name() == "dist" || d.Name() == ".astro" {
					return filepath.SkipDir
				}
				return nil
			}
			if !r.exts[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, docFile{relPath: rel, text: string(b)})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %q: %v", r.dir, err)
		}
	}

	if len(out) == 0 {
		t.Fatal("collected zero docs files; extraction is misconfigured")
	}
	return out
}

// readRegistry reads an authoritative source file and returns its text.
func readRegistry(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("reading registry %q: %v", rel, err)
	}
	return string(b)
}

// generatedConfigVar is one row of the generated config reference
// (docs-site/src/data/generated/config.json), the authoritative list of live
// GATEWAY_* keys (and their display categories) emitted by cmd/docsgen.
type generatedConfigVar struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	// Anchor is the URL fragment of the category section, emitted by cmd/docsgen
	// (slugify(Category)). The anchor-resolves guard consumes this directly so
	// the slug logic lives in exactly one place (the generator).
	Anchor string `json:"anchor"`
}

// readGeneratedConfig parses the generated config reference. Using this rather
// than regex-scanning all of config.go keeps the registry precise: only keys
// the generator actually emits count as valid, so a GATEWAY_* token that only
// appears in a config.go comment or error string is not silently accepted.
func readGeneratedConfig(t *testing.T, root string) []generatedConfigVar {
	t.Helper()
	path := filepath.Join(root, "docs-site", "src", "data", "generated", "config.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config reference: %v", err)
	}
	var vars []generatedConfigVar
	if err := json.Unmarshal(b, &vars); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if len(vars) == 0 {
		t.Fatal("generated config reference is empty; regenerate with `go run ./cmd/docsgen`")
	}
	return vars
}

// isPrefixToken reports whether a GATEWAY_ token is a glob/wrapped fragment
// (it ends with "_"). Such a token is accepted when some real config key has
// it as a prefix — this covers documented families like `GATEWAY_SMS_*` and
// prose that line-wraps a long var name across a newline.
func isPrefixToken(tok string) bool { return strings.HasSuffix(tok, "_") }

func TestDocsGatewayEnvVarsExist(t *testing.T) {
	root := repoRoot(t)

	known := map[string]bool{}
	for _, v := range readGeneratedConfig(t, root) {
		known[v.Name] = true
	}

	hasPrefix := func(prefix string) bool {
		for k := range known {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
		return false
	}

	var violations []string
	for _, df := range collectDocs(t, root) {
		seen := map[string]bool{}
		for _, tok := range gatewayTokenRe.FindAllString(df.text, -1) {
			if seen[tok] {
				continue
			}
			seen[tok] = true

			if _, ok := allowedGatewayTokens[tok]; ok {
				continue
			}
			if isPrefixToken(tok) {
				if !hasPrefix(tok) {
					violations = append(violations, df.relPath+": docs reference "+tok+"* but no GATEWAY_ key in config.go starts with it")
				}
				continue
			}
			if !known[tok] {
				violations = append(violations, df.relPath+": docs reference "+tok+" which does not exist in internal/config/config.go")
			}
		}
	}

	reportViolations(t, "GATEWAY_ env var", violations)
}

func TestDocsAuditEventTypesExist(t *testing.T) {
	root := repoRoot(t)
	logger := readRegistry(t, root, filepath.Join("pkg", "audit", "logger.go"))

	known := map[string]bool{}
	for _, m := range eventConstRe.FindAllStringSubmatch(logger, -1) {
		known[m[1]] = true
	}
	if len(known) == 0 {
		t.Fatal("found zero EventType constants in pkg/audit/logger.go; registry extraction is broken")
	}

	var violations []string
	for _, df := range collectDocs(t, root) {
		seen := map[string]bool{}
		for _, m := range docEventRe.FindAllStringSubmatch(df.text, -1) {
			ev := m[1]
			if seen[ev] {
				continue
			}
			seen[ev] = true
			if !known[ev] {
				violations = append(violations, df.relPath+`: docs example uses audit event "`+ev+`" which is not an EventType in pkg/audit/logger.go`)
			}
		}
	}

	reportViolations(t, "audit event type", violations)
}

func TestDocsRPCMethodsExist(t *testing.T) {
	root := repoRoot(t)
	proto := readRegistry(t, root, filepath.Join("proto", "identity", "v1", "identity.proto"))

	known := map[string]bool{}
	for _, m := range protoRPCRe.FindAllStringSubmatch(proto, -1) {
		known[m[1]] = true
	}
	if len(known) == 0 {
		t.Fatal("found zero rpc methods in identity.proto; registry extraction is broken")
	}

	var violations []string
	for _, df := range collectDocs(t, root) {
		seen := map[string]bool{}
		for _, m := range rpcURLRe.FindAllStringSubmatch(df.text, -1) {
			method := m[1]
			if seen[method] {
				continue
			}
			seen[method] = true
			if !known[method] {
				violations = append(violations, df.relPath+": docs reference IdentityService/"+method+" which is not an rpc in proto/identity/v1/identity.proto")
			}
		}
	}

	reportViolations(t, "RPC method", violations)
}

// TestGeneratedConfigDescriptionsNonEmpty asserts that the generated config
// reference (docs-site/src/data/generated/config.json) documents every
// GATEWAY_* env var. An empty description means a Config field in
// internal/config/config.go lost its doc comment; cmd/docsgen also guards
// against this at generation time, and this test guards the committed artifact.
func TestGeneratedConfigDescriptionsNonEmpty(t *testing.T) {
	root := repoRoot(t)

	var violations []string
	for _, v := range readGeneratedConfig(t, root) {
		if strings.TrimSpace(v.Description) == "" {
			violations = append(violations,
				v.Name+": empty description — add a Go doc comment to the matching Config field, then `go run ./cmd/docsgen`")
		}
	}
	reportViolations(t, "config reference empty-description", violations)
}

// configAnchorRefRe matches a deep link into the configuration reference,
// e.g. `configuration#passkeys-webauthn`, capturing the fragment.
var configAnchorRefRe = regexp.MustCompile(`configuration#([a-z0-9-]+)`)

// TestDocsConfigurationAnchorsResolve is an anti-drift guard for deep links into
// the configuration reference: every `configuration#<fragment>` referenced
// anywhere in the docs must match an id the configuration page actually emits
// (one per category section, using the generator-emitted `anchor`). This catches
// both a renamed category and a hand-edited href that no longer points at a live
// anchor. The anchor is consumed directly from the generated config so the slug
// rule lives only in cmd/docsgen.
func TestDocsConfigurationAnchorsResolve(t *testing.T) {
	root := repoRoot(t)

	emitted := map[string]bool{}
	for _, v := range readGeneratedConfig(t, root) {
		if strings.TrimSpace(v.Anchor) == "" {
			t.Fatalf("generated config var %q has an empty anchor; regenerate with `go run ./cmd/docsgen`", v.Name)
		}
		emitted[v.Anchor] = true
	}
	if len(emitted) == 0 {
		t.Fatal("derived zero category anchors from the generated config; extraction is broken")
	}

	var violations []string
	totalRefs := 0
	for _, df := range collectDocs(t, root) {
		seen := map[string]bool{}
		for _, m := range configAnchorRefRe.FindAllStringSubmatch(df.text, -1) {
			frag := m[1]
			if seen[frag] {
				continue
			}
			seen[frag] = true
			totalRefs++
			if !emitted[frag] {
				violations = append(violations,
					df.relPath+": link to configuration#"+frag+
						" does not resolve to any category anchor emitted by configuration.astro")
			}
		}
	}
	if totalRefs == 0 {
		t.Fatal("found zero configuration#<fragment> references; the extractor is misconfigured")
	}
	reportViolations(t, "configuration anchor", violations)
}

// reportViolations fails the test with every accumulated violation listed,
// sorted for stable output.
func reportViolations(t *testing.T, kind string, violations []string) {
	t.Helper()
	if len(violations) == 0 {
		return
	}
	sort.Strings(violations)
	t.Errorf("docs drift: %d %s reference(s) that do not exist in the implementation:\n  - %s",
		len(violations), kind, strings.Join(violations, "\n  - "))
}
