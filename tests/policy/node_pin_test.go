package policy

import (
	"path/filepath"
	"regexp"
	"testing"
)

var (
	exactVersion   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	nodeVersionSet = regexp.MustCompile(`node-version: [^$]`)
)

// Node is a toolchain, so it is pinned to a patch release (AGENTS.md §10),
// once per workflow, and CI's review-gate job and the docs build agree.
// pnpm is pinned exactly too.
func TestWorkflowNodeAndPnpmArePinnedExactly(t *testing.T) {
	root := repoRoot(t)
	ci := readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	docs := readFile(t, filepath.Join(root, ".github", "workflows", "docs.yml"))

	versions := map[string]string{}
	for name, wf := range map[string]string{"ci.yml": ci, "docs.yml": docs} {
		versions[name] = workflowEnvPin(t, wf, "NODE_VERSION")
		if !exactVersion.MatchString(versions[name]) {
			t.Errorf("%s must pin NODE_VERSION to an exact x.y.z, not %q", name, versions[name])
		}
		if nodeVersionSet.MatchString(wf) {
			t.Errorf("%s sets node-version other than from NODE_VERSION", name)
		}
	}
	if versions["ci.yml"] != versions["docs.yml"] {
		t.Errorf("NODE_VERSION: ci.yml %s, docs.yml %s; want one version", versions["ci.yml"], versions["docs.yml"])
	}
	if pnpm := workflowEnvPin(t, docs, "PNPM_VERSION"); !exactVersion.MatchString(pnpm) {
		t.Errorf("docs.yml must pin PNPM_VERSION to an exact x.y.z, not %q", pnpm)
	}
}
