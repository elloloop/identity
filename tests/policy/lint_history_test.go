package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const lintQueueHistoryFixture = `set -euo pipefail
git init --initial-branch=main seed
cd seed
git config user.name Fixture
git config user.email fixture@example.test
git config commit.gpgsign false
printf 'base\n' > source.txt
git add source.txt
git commit -m 'Base fixture'
base=$(git rev-parse HEAD)
printf 'queued feature\n' > source.txt
git commit -am 'Queued fixture'
remote="file://$PWD"
cd ..
if [ "$LINT_FIXTURE_FULL_HISTORY" = 1 ]; then
  git clone --no-tags --single-branch "$remote" checkout
else
  git clone --no-tags --single-branch --depth=1 "$remote" checkout
fi
cd checkout
git diff --no-ext-diff "$base" -- source.txt
`

func TestLintCheckoutRetainsExactQueueComparisonBase(t *testing.T) {
	workflow := readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	lint := workflowJobs(t, workflow)["lint"]
	checkout := regexp.MustCompile(`(?m)^      - uses: actions/checkout@[^\n]+\n(?: {8,}[^\n]*\n)*`).FindString(lint)
	if checkout == "" {
		t.Fatal("lint checkout step is missing")
	}
	fullHistory := strings.Contains(checkout, "fetch-depth: 0")
	for _, c := range []struct {
		name           string
		full, wantBase bool
	}{
		{"configured checkout", fullHistory, true},
		{"default shallow negative control", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "bash", "-c", lintQueueHistoryFixture)
			cmd.Dir = t.TempDir()
			depth := "0"
			if c.full {
				depth = "1"
			}
			cmd.Env = append(os.Environ(), "LINT_FIXTURE_FULL_HISTORY="+depth)
			output, err := cmd.CombinedOutput()
			if c.wantBase {
				if err != nil {
					t.Fatalf("lint cannot compare the exact queue base: %v\n%s", err, output)
				}
				if !strings.Contains(string(output), "+queued feature") {
					t.Fatal("comparison did not include the queued change")
				}
			} else if err == nil || !strings.Contains(string(output), "bad object") {
				t.Fatalf("shallow negative control did not reproduce missing base: %v\n%s", err, output)
			}
		})
	}
}
