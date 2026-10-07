package policy

import (
	"path/filepath"
	"regexp"
	"testing"
)

var (
	nodeVersionPin = regexp.MustCompile(`(?m)^  NODE_VERSION: '([^']+)'$`)
	pnpmVersionPin = regexp.MustCompile(`(?m)^  PNPM_VERSION: '([^']+)'$`)
	exactVersion   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	nodeVersionSet = regexp.MustCompile(`node-version: [^$]`)
)

// Node is a toolchain, so it is pinned to a patch release (AGENTS.md §10),
// once per workflow, and CI's review-gate job and the docs build agree.
func TestWorkflowNodeAndPnpmArePinnedExactly(t *testing.T) {
	root := repoRoot(t)
	ci := readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	docs := readFile(t, filepath.Join(root, ".github", "workflows", "docs.yml"))

	versions := map[string]string{}
	for name, wf := range map[string]string{"ci.yml": ci, "docs.yml": docs} {
		m := nodeVersionPin.FindStringSubmatch(wf)
		if m == nil || !exactVersion.MatchString(m[1]) {
			t.Fatalf("%s must pin NODE_VERSION to an exact x.y.z", name)
		}
		versions[name] = m[1]
		if nodeVersionSet.MatchString(wf) {
			t.Errorf("%s sets node-version other than from NODE_VERSION", name)
		}
	}
	if versions["ci.yml"] != versions["docs.yml"] {
		t.Errorf("NODE_VERSION: ci.yml %s, docs.yml %s; want one version", versions["ci.yml"], versions["docs.yml"])
	}
	if m := pnpmVersionPin.FindStringSubmatch(docs); m == nil || !exactVersion.MatchString(m[1]) {
		t.Error("docs.yml must pin PNPM_VERSION to an exact x.y.z")
	}
}
