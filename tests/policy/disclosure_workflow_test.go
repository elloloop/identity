package policy

import (
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	jobLine        = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):$`)
	permissionLine = regexp.MustCompile(`^ {6}([a-z-]+): ([a-z]+)$`)
	runLine        = regexp.MustCompile(`^( *)(?:- )?run:(.*)$`)
	checkoutRef    = regexp.MustCompile(`(?m)^\s+ref:`)
	termsName      = regexp.MustCompile(`(?i)confidential_terms`)
	termsBinding   = regexp.MustCompile(`^ {10}CONFIDENTIAL_TERMS: \$\{\{ secrets\.CONFIDENTIAL_TERMS \}\}$`)

	labelArm = regexp.MustCompile(`\n {12}([a-z-]+)\) item=`)

	// collectArms are the case arms a workflow's collect step must have, by
	// the collect script's exit status.
	collectArms = map[string]*regexp.Regexp{
		"0": regexp.MustCompile(`(?m)^\s+0\) echo "check=true" >> "\$GITHUB_OUTPUT" ;;$`),
		"2": regexp.MustCompile(`(?s)\n\s+2\)\n\s+echo "::error::[^"]*[Rr]e-run[^"]*"\n\s+exit 1\n`),
		// The author alone decides, so the notice says so, never "sent".
		"10": regexp.MustCompile(`(?m)^\s+10\) echo "::notice::Not checked: the item's author has no write access\.[^"]*" ;;$`),
		"11": regexp.MustCompile(`(?s)\n\s+11\)\n\s+echo "::error::[^"]*"\n\s+exit 1\n`),
		"*":  regexp.MustCompile(`(?m)^\s+\*\) exit "\$status" ;;$`),
	}
)

func disclosureWorkflow(t *testing.T, name string) string {
	t.Helper()
	return readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", name))
}

// The Disclosure workflow runs with secrets on pull_request_target, so the
// guarantees that make that safe are pinned here: it triggers only where
// its one job reports the required check, it starts from no permissions and
// the job holds only what it needs, it never checks out anything but the
// base branch's scripts, it never reads the PR head or any event text by
// expression, and the term list never enters its own shell.
func TestDisclosureWorkflowNeverRunsPullRequestCode(t *testing.T) {
	wf := disclosureWorkflow(t, "disclosure.yml")

	// Any other trigger would attach a skipped "Disclosure" job to the PR
	// head, which GitHub counts as a pass for the required check.
	if got, want := workflowTriggers(wf), map[string]string{
		"pull_request_target": "[opened, edited, synchronize, reopened]",
		"merge_group":         "[checks_requested]",
	}; !maps.Equal(got, want) {
		t.Errorf("disclosure.yml triggers = %v, want exactly %v", got, want)
	}
	jobs := workflowJobs(t, wf)
	if got := slices.Sorted(maps.Keys(jobs)); !slices.Equal(got, []string{"disclosure"}) {
		t.Fatalf("disclosure.yml jobs = %v, want only disclosure", got)
	}
	job := jobs["disclosure"]
	if got, want := jobPermissions(job), map[string]string{"contents": "read", "pull-requests": "read"}; !maps.Equal(got, want) {
		t.Errorf("disclosure permissions = %v, want exactly %v", got, want)
	}
	if !strings.Contains(job, "    name: Disclosure\n") {
		t.Error("the disclosure job must report the Disclosure check")
	}
	if strings.Contains(job, "\n    if:") {
		t.Error("the Disclosure job must run on every event of its workflow, never skip")
	}
	assertCollectOutcomes(t, "disclosure.yml", wf, map[string]string{
		"merge_group": "merge-group", "pull_request_target": "pr",
	}, "11")
	// A match in the merge queue is a queued PR's squash, not a branch to
	// rewrite: the message says which.
	for _, want := range []string{
		`if [ "$EVENT_NAME" = "merge_group" ]; then`,
		`echo "::error::A queued PR's squash commit message`,
		`echo "::error::The title, description, branch name`,
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("disclosure.yml lacks %q", want)
		}
	}
	assertDisclosureWorkflowBasics(t, "disclosure.yml", wf)
}

// No workflow runs on review events: they would run the PR branch's copy of
// the workflow with the repository's secrets.
func TestNoDisclosureWorkflowRunsOnReviewEvents(t *testing.T) {
	for _, name := range []string{"disclosure.yml", "disclosure-discussion.yml"} {
		for event := range workflowTriggers(disclosureWorkflow(t, name)) {
			if strings.HasPrefix(event, "pull_request_review") {
				t.Errorf("%s listens for %s", name, event)
			}
		}
	}
}

// Issues and comments are checked by a workflow of their own, under
// another check name, so none of their runs touches the required check.
func TestDisclosureDiscussionWorkflow(t *testing.T) {
	wf := disclosureWorkflow(t, "disclosure-discussion.yml")

	if got, want := workflowTriggers(wf), map[string]string{
		"issues":        "[opened, edited]",
		"issue_comment": "[created, edited]",
	}; !maps.Equal(got, want) {
		t.Errorf("disclosure-discussion.yml triggers = %v, want exactly %v", got, want)
	}
	jobs := workflowJobs(t, wf)
	if got := slices.Sorted(maps.Keys(jobs)); !slices.Equal(got, []string{"discussion"}) {
		t.Fatalf("disclosure-discussion.yml jobs = %v, want only discussion", got)
	}
	if got, want := jobPermissions(jobs["discussion"]), map[string]string{"contents": "read", "issues": "write"}; !maps.Equal(got, want) {
		t.Errorf("discussion permissions = %v, want exactly %v", got, want)
	}
	if strings.Contains(jobs["discussion"], "    name: Disclosure\n") {
		t.Error("the discussion job must not report the required Disclosure check")
	}
	// The redaction request names the author whose text was checked: the
	// item's author, the one the collect step's gate read, never the sender.
	if !strings.Contains(wf, "          AUTHOR: ${{ github.event.comment.user.login || github.event.issue.user.login }}\n") ||
		strings.Contains(wf, "github.event.sender") {
		t.Error("the redaction request must @mention the item's author")
	}
	label := ""
	for _, run := range runBlocks(wf) {
		if strings.Contains(run, "needs-redaction") {
			label = run
		}
	}
	var arms []string
	for _, m := range labelArm.FindAllStringSubmatch(label, -1) {
		arms = append(arms, m[1])
	}
	if !slices.Equal(arms, []string{"issue", "comment"}) {
		t.Errorf("the label step's kinds = %v, want exactly issue and comment", arms)
	}
	if !strings.Contains(label, "\n            *) echo \"::error::Unexpected kind $KIND.\"; exit 1 ;;\n") {
		t.Error("the label step must fail on a kind it does not know")
	}
	assertCollectOutcomes(t, "disclosure-discussion.yml", wf, map[string]string{
		"issues": "issue", "issue_comment": "comment",
	})
	assertDisclosureWorkflowBasics(t, "disclosure-discussion.yml", wf)
}

// assertCollectOutcomes pins how a workflow acts on what the collect script
// returns: each event maps to its kind, collected text (0) is checked, a
// failed read (2) fails the job with a re-run hint, no writer (10) is a
// notice, and every other status fails the job. extra lists the statuses a
// workflow handles beyond those: disclosure.yml passes 11 (too big), which
// fails the job. The check step runs only on collected text.
func assertCollectOutcomes(t *testing.T, name, wf string, kinds map[string]string, extra ...string) {
	t.Helper()
	collect := ""
	for _, run := range runBlocks(wf) {
		if strings.Contains(run, "bash scripts/disclosure-collect.sh") {
			collect = run
		}
	}
	if collect == "" {
		t.Fatalf("%s never runs the collect script", name)
	}
	for event, kind := range kinds {
		if !strings.Contains(collect, "\n            "+event+") kind="+kind+" ;;\n") {
			t.Errorf("%s does not map %s to kind %s", name, event, kind)
		}
	}
	if !strings.Contains(collect, "\n            *) echo \"::error::Unexpected event $EVENT_NAME.\"; exit 1 ;;\n") {
		t.Errorf("%s must fail on an event it does not map", name)
	}
	for _, code := range append([]string{"0", "2", "10", "*"}, extra...) {
		if !collectArms[code].MatchString(collect) {
			t.Errorf("%s: the collect step does not handle status %s as it must", name, code)
		}
	}
	if strings.Count(wf, "        if: steps.collect.outputs.check == 'true'\n") != 1 {
		t.Errorf("%s: the check step must run only on collected text", name)
	}
}

// assertDisclosureWorkflowBasics pins what both Disclosure workflows share:
// no permissions by default, a checkout of only the two scripts with no ref
// and no credentials, no event text read by expression, and the term list
// confined to one env binding per check step.
func assertDisclosureWorkflowBasics(t *testing.T, name, wf string) {
	t.Helper()
	if !strings.Contains(wf, "\npermissions: {}\n") {
		t.Errorf("%s must start from no permissions", name)
	}

	checkouts := strings.Count(wf, "uses: actions/checkout@")
	if checkouts == 0 {
		t.Fatalf("%s has no checkout of the scripts", name)
	}
	for _, want := range []string{
		"persist-credentials: false",
		"sparse-checkout: |\n            scripts/disclosure-collect.sh\n            scripts/disclosure-check.sh\n",
	} {
		if got := strings.Count(wf, want); got != checkouts {
			t.Errorf("%s: %d checkout(s) but %q appears %d time(s)", name, checkouts, want, got)
		}
	}
	if checkoutRef.MatchString(wf) {
		t.Errorf("%s must not set a checkout ref", name)
	}
	for _, forbidden := range []string{
		"github.event.pull_request.head",  // the PR head by expression
		"github.event.pull_request.title", // event text interpolated into a step
		"github.event.pull_request.body",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.comment.body",
		"github.event.review.body",
		"head_commit",
		"pull-requests: write",
		"contents: write",
	} {
		if strings.Contains(wf, forbidden) {
			t.Errorf("%s must not contain %q", name, forbidden)
		}
	}

	// No run block takes anything by expression: event text reaches a
	// script only as env or the event file. And the term list reaches only
	// the matcher, through one env binding per check step: it is never named
	// in a run block, in any spelling.
	for _, run := range runBlocks(wf) {
		if strings.Contains(run, "${{") {
			t.Errorf("%s: a run block interpolates an expression:\n%s", name, run)
		}
		if termsName.MatchString(run) {
			t.Errorf("%s: a run block names the term list:\n%s", name, run)
		}
	}
	bindings := 0
	for _, line := range strings.Split(wf, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !termsName.MatchString(line), strings.HasPrefix(trimmed, "#"):
		case termsBinding.MatchString(line):
			bindings++
		default:
			t.Errorf("%s: the term list appears outside its env binding: %q", name, trimmed)
		}
	}
	if checks := strings.Count(wf, "- name: Check for confidential terms\n"); bindings != 1 || checks != 1 {
		t.Errorf("%s: %d env binding(s) of the term list for %d check step(s), want one of each", name, bindings, checks)
	}
}

// workflowTriggers reads a workflow's `on:` block as event -> types.
func workflowTriggers(wf string) map[string]string {
	_, block, ok := strings.Cut(wf, "\non:\n")
	if !ok {
		return nil
	}
	triggers := map[string]string{}
	event := ""
	for _, line := range strings.Split(block, "\n") {
		switch {
		case line == "":
		case !strings.HasPrefix(line, " "):
			return triggers
		case strings.HasPrefix(line, "    types: "):
			triggers[event] = strings.TrimPrefix(line, "    types: ")
		default:
			event = strings.TrimSuffix(strings.TrimSpace(line), ":")
			triggers[event] = ""
		}
	}
	return triggers
}

// workflowJobs splits a workflow's jobs block into each job's text, keyed by
// job id. It relies on the two-space indentation every workflow here uses.
func workflowJobs(t *testing.T, wf string) map[string]string {
	t.Helper()
	_, body, ok := strings.Cut(wf, "\njobs:\n")
	if !ok {
		t.Fatal("workflow has no jobs block")
	}
	jobs := map[string]string{}
	id := ""
	for _, line := range strings.Split(body, "\n") {
		if m := jobLine.FindStringSubmatch(line); m != nil {
			id = m[1]
		}
		if id != "" {
			jobs[id] += line + "\n"
		}
	}
	return jobs
}

// jobPermissions reads a job's permissions block as a map.
func jobPermissions(job string) map[string]string {
	_, block, ok := strings.Cut(job, "\n    permissions:\n")
	if !ok {
		return nil
	}
	perms := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		m := permissionLine.FindStringSubmatch(line)
		if m == nil {
			break
		}
		perms[m[1]] = m[2]
	}
	return perms
}

// runBlocks returns the body of every `run: |` block and every one-line
// `run:` in a workflow.
func runBlocks(wf string) []string {
	var blocks []string
	lines := strings.Split(wf, "\n")
	for i := 0; i < len(lines); i++ {
		m := runLine.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		if rest := strings.TrimSpace(m[2]); rest != "|" && rest != ">" {
			blocks = append(blocks, rest)
			continue
		}
		var body []string
		for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || indent(lines[i+1]) > len(m[1])) {
			i++
			body = append(body, lines[i])
		}
		blocks = append(blocks, strings.Join(body, "\n"))
	}
	return blocks
}

func indent(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }
