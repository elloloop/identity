package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestContainerBuildUsesCIGoPatchVersion(t *testing.T) {
	root := repoRoot(t)
	dockerfile := readFile(t, filepath.Join(root, "Dockerfile"))
	ciGoVersion := workflowEnvPin(t, readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml")), "GO_VERSION")
	releaseGoVersion := workflowEnvPin(t, readFile(t, filepath.Join(root, ".github", "workflows", "release.yml")), "GO_VERSION")

	if releaseGoVersion != ciGoVersion {
		t.Fatalf("release GO_VERSION = %q, CI GO_VERSION = %q", releaseGoVersion, ciGoVersion)
	}

	builder := regexp.MustCompile(`(?m)^FROM --platform=\$BUILDPLATFORM golang:([0-9]+\.[0-9]+\.[0-9]+)-alpine[0-9]+\.[0-9]+ AS builder$`).
		FindStringSubmatch(dockerfile)
	if len(builder) != 2 {
		t.Fatalf("Dockerfile builder base must pin golang:<major>.<minor>.<patch>-alpine<major>.<minor>")
	}
	if builder[1] != ciGoVersion {
		t.Fatalf("Dockerfile builder Go version = %q, CI GO_VERSION = %q", builder[1], ciGoVersion)
	}
	if strings.Contains(dockerfile, "GOTOOLCHAIN=auto") {
		t.Fatal("Dockerfile must not auto-download a different Go toolchain")
	}
}

func TestContainerRuntimeHasNoDistributionPackageLayer(t *testing.T) {
	dockerfile := readFile(t, filepath.Join(repoRoot(t), "Dockerfile"))

	if !regexp.MustCompile(`(?m)^FROM scratch AS server$`).MatchString(dockerfile) {
		t.Fatal("runtime stage must be scratch")
	}
	if !strings.Contains(dockerfile, "COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt") {
		t.Fatal("scratch runtime must include CA roots")
	}
	if !regexp.MustCompile(`(?m)^USER 65532:65532$`).MatchString(dockerfile) {
		t.Fatal("runtime image must run as the nonroot uid/gid")
	}
}

// workflowEnvPin returns the value a workflow's env pins name to.
func workflowEnvPin(t *testing.T, workflow, name string) string {
	t.Helper()

	matches := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `:\s*'([^']+)'$`).FindStringSubmatch(workflow)
	if len(matches) != 2 {
		t.Fatalf("workflow %s not found", name)
	}
	return matches[1]
}

func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	//nolint:gosec // Tests read fixed repository files under the discovered go.mod root.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
