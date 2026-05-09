package policy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageGateConfigModePassesPerPackageThresholds(t *testing.T) {
	dir := t.TempDir()
	profile := writeCoverageProfile(t, dir)
	config := writeCoverageConfig(t, dir, `
default: 80
include:
  - internal/
  - pkg/
packages:
  internal/service: 70
  pkg/oauth: 80
`)

	out, err := runCoverageGate(t, profile, "--config", config)
	if err != nil {
		t.Fatalf("coverage gate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "coverage-gate: ok    internal/service  70.00% >= 70%") {
		t.Fatalf("missing internal/service result:\n%s", out)
	}
	if strings.Contains(out, "cmd/identity") {
		t.Fatalf("cmd/identity should not be gated by internal/pkg config:\n%s", out)
	}
}

func TestCoverageGateConfigModeFailsBelowPackageThreshold(t *testing.T) {
	dir := t.TempDir()
	profile := writeCoverageProfile(t, dir)
	config := writeCoverageConfig(t, dir, `
default: 80
include:
  - internal/
  - pkg/
packages:
  internal/service: 71
  pkg/oauth: 80
`)

	out, err := runCoverageGate(t, profile, "--config", config)
	if err == nil {
		t.Fatalf("coverage gate passed unexpectedly:\n%s", out)
	}
	if !strings.Contains(out, "coverage-gate: FAIL  internal/service  70.00% < 71%") {
		t.Fatalf("missing failure detail:\n%s", out)
	}
}

func TestCoverageGateConfigModeFailsMissingConfiguredPackage(t *testing.T) {
	dir := t.TempDir()
	profile := writeCoverageProfile(t, dir)
	config := writeCoverageConfig(t, dir, `
default: 80
packages:
  internal/missing: 80
`)

	out, err := runCoverageGate(t, profile, "--config", config)
	if err == nil {
		t.Fatalf("coverage gate passed unexpectedly:\n%s", out)
	}
	if !strings.Contains(out, "coverage-gate: FAIL  internal/missing  no statements found") {
		t.Fatalf("missing no-statements failure:\n%s", out)
	}
}

func writeCoverageProfile(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "cover.out")
	body := `mode: atomic
github.com/elloloop/identity/internal/service/auth.go:1.1,1.2 7 1
github.com/elloloop/identity/internal/service/auth.go:2.1,2.2 3 0
github.com/elloloop/identity/pkg/oauth/oauth.go:1.1,1.2 8 1
github.com/elloloop/identity/pkg/oauth/oauth.go:2.1,2.2 2 0
github.com/elloloop/identity/cmd/identity/main.go:1.1,1.2 10 0
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCoverageConfig(t *testing.T, dir, body string) string {
	t.Helper()

	path := filepath.Join(dir, "coverage.yml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCoverageGate(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmdArgs := append([]string{filepath.Join(repoRoot(t), "scripts", "coverage-gate.sh")}, args...)
	//nolint:gosec // The command is the repository-owned coverage script; args point at temp test files.
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Dir = repoRoot(t)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
