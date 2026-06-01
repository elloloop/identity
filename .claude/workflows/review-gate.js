export const meta = {
  name: 'review-gate',
  description: 'Four-reviewer PR gate: security, performance, product, and code-quality principals review a PR in parallel, then synthesize one consolidated verdict and post it to the PR',
  whenToUse: 'Run on every PR before merge (AGENTS.md §11). Pass the PR number as args, e.g. Workflow({name: "review-gate", args: 167}).',
  phases: [
    { title: 'Gather' },
    { title: 'Review' },
    { title: 'Synthesize' },
  ],
}

// PR number comes in via args (number or string). Required.
const pr = String(args ?? '').trim()
if (!pr || !/^\d+$/.test(pr)) {
  throw new Error('review-gate: pass the PR number as args, e.g. Workflow({name: "review-gate", args: 167})')
}

const FINDING_SCHEMA = {
  type: 'object',
  properties: {
    dimension: { type: 'string' },
    verdict: { type: 'string', enum: ['approve', 'approve_with_nits', 'request_changes'] },
    summary: { type: 'string', description: 'One-paragraph assessment from this reviewer’s lens' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          title: { type: 'string' },
          location: { type: 'string', description: 'file:line or area' },
          detail: { type: 'string' },
          suggestion: { type: 'string' },
        },
        required: ['severity', 'title', 'detail'],
      },
    },
  },
  required: ['dimension', 'verdict', 'summary', 'findings'],
}

phase('Gather')
// Pull the PR diff + metadata once, so each reviewer works from identical context.
const context = await agent(
  `Gather everything needed to review PR #${pr} of the repo at the current working directory. Use the gh CLI and git. Produce a single plain-text bundle containing, clearly delimited:

1. PR metadata: title, body, author, base/head branch, additions/deletions, changed-file list. (gh pr view ${pr} --json title,body,author,baseRefName,headRefName,additions,deletions,files)
2. The FULL unified diff of the PR. (gh pr diff ${pr})  — if it is very large (> ~1500 changed lines), include the complete diff for non-generated files and, for generated files (gen/go/**, lockfiles), include only a one-line note naming them and their +/- counts instead of the body.
3. The list of changed files annotated as: production code / tests / generated / config / docs / CI.
4. Any linked issue numbers from the PR body.

Do not review anything — just collect and return the bundle verbatim. Be complete; the reviewers see only what you return.`,
  { label: `gather:pr-${pr}`, phase: 'Gather' },
)

phase('Review')
const REVIEWERS = [
  {
    key: 'security',
    label: 'security-principal',
    prompt: `You are a PRINCIPAL SECURITY ENGINEER reviewing a pull request. Focus EXCLUSIVELY on security; ignore style/perf/product unless they create a security risk. Scrutinise: authentication & authorization (who can call this, is the gate correct), input validation & injection (SQL, command, path, template, header), secrets/key/credential handling, cryptography (algorithms, randomness, constant-time compares, token/code entropy & hashing at rest), data exposure & PII in logs/responses/errors, enumeration & timing oracles, abuse/rate-limiting/DoS, SSRF/outbound-request safety, supply-chain (new deps, pinning), authz on new RPCs/endpoints, and the blast radius if this code is compromised. Flag missing security tests. For each issue give severity (blocker/major/minor/nit), a precise location, why it's exploitable, and a concrete fix.`,
  },
  {
    key: 'performance',
    label: 'performance-principal',
    prompt: `You are a PRINCIPAL PERFORMANCE ENGINEER reviewing a pull request. Focus EXCLUSIVELY on performance & scalability. Scrutinise: algorithmic complexity (hidden O(n^2), full scans), N+1 queries and per-item round-trips, DB query and index shape (does a new filter hit an index; is a new column/table indexed where queried), unbounded result sets / missing pagination/limits, hot-path allocations and avoidable copies, lock scope & contention, goroutine/connection lifecycle and leaks, payload size and over-fetching, synchronous calls to slow external services on a request path (timeouts, retries, circuit-breaking), and behaviour under concurrency and load. Flag missing load/bench coverage where it matters. For each issue give severity, location, the expected impact (and at what scale), and a concrete fix.`,
  },
  {
    key: 'product',
    label: 'product-manager',
    prompt: `You are a PRINCIPAL PRODUCT MANAGER reviewing a pull request. Focus on user/product value and correctness of behaviour, NOT code style. Scrutinise: does the change actually deliver the intended outcome and match the request/linked issue; are the semantics and defaults right; are error messages, status codes, and edge-case behaviour sensible for the consumer; is the public API (proto/RPCs/config) coherent and forward-compatible; is anything half-finished, stubbed, or silently scoped down; is there an UNFLAGGED breaking change or migration risk; is configurability appropriate for an OSS server others deploy (this repo ships a Docker image, not a service we operate); is documentation/changelog needed. For each issue give severity, what user-facing problem it causes, and what should change.`,
  },
  {
    key: 'quality',
    label: 'code-quality-principal',
    prompt: `You are a PRINCIPAL SOFTWARE ENGINEER reviewing a pull request for code quality, standards, and maintainability against this repo's AGENTS.md rules. Scrutinise: root-cause fixes vs shims/patches/compat layers (a §1 violation is a blocker), dead code left behind (§2), changes made at the wrong level / premature abstractions (§3,§4), comments explaining what instead of why (§5), half-finished work — impl without tests/wiring (§6), tests that actually prove the new behaviour and extend conformance rather than bypass it (§7), naming and readability, DRY-about-knowledge, error handling (no swallowed errors), hardcoded values that should be named/config, and that generated code came from the generator not hand edits. For each issue give severity, location, which rule/principle it breaks, and the concrete change.`,
  },
]

const reviews = await parallel(
  REVIEWERS.map((r) => () =>
    agent(
      `${r.prompt}

Review ONLY the changes in this PR. Be concrete and cite file:line from the diff. If the change is clean from your lens, say so and approve — do not invent findings. Set verdict to "request_changes" only if there is at least one blocker or major issue from YOUR dimension.

=== PR #${pr} CONTEXT (metadata + diff) ===
${context}`,
      { label: r.label, phase: 'Review', schema: FINDING_SCHEMA },
    ),
  ),
).then((rs) => rs.filter(Boolean))

phase('Synthesize')
// Decide the overall gate result and post a single consolidated review.
const overallBlockers = reviews
  .flatMap((r) => (r.findings || []).map((f) => ({ ...f, dimension: r.dimension })))
  .filter((f) => f.severity === 'blocker' || f.severity === 'major')
const anyRequestChanges = reviews.some((r) => r.verdict === 'request_changes')
const gatePass = !anyRequestChanges && overallBlockers.length === 0

const synthesis = await agent(
  `You are the review-gate synthesizer. Four principal reviewers (security, performance, product, code-quality) reviewed PR #${pr}. Produce ONE consolidated review as GitHub-flavored markdown and POST it to the PR.

Their structured verdicts:
${JSON.stringify(reviews, null, 2)}

Computed gate: ${gatePass ? 'PASS' : 'CHANGES REQUESTED'} (request_changes from any reviewer = ${anyRequestChanges}; blocker/major findings = ${overallBlockers.length}).

Write the consolidated review with:
- A top line: "## Four-reviewer gate: ${gatePass ? '✅ PASS' : '❌ CHANGES REQUESTED'}"
- A per-dimension table: Dimension | Verdict | Blockers/Majors count, one row each for Security, Performance, Product, Code Quality.
- A "### Must fix (blockers & majors)" section listing every blocker/major finding grouped by dimension, each with location and the concrete fix. Omit the section if there are none.
- A "### Minors & nits" section (collapsed feel — keep terse) listing the rest. Omit if none.
- A one-paragraph overall recommendation.
- A footer line: "_Generated by the four-reviewer gate (AGENTS.md §11)._"

Then post it with:  gh pr review ${pr} --comment --body-file <tmpfile>
(Use --comment, NOT --approve/--request-changes, so the agent gate never auto-approves or blocks the human merge; it advises.) Write the markdown to a temp file and pass it via --body-file to avoid shell-quoting issues. Confirm the post succeeded (print the review URL) and return the consolidated markdown verbatim as your final output.`,
  { label: `synthesize:pr-${pr}`, phase: 'Synthesize' },
)

return {
  pr,
  gate: gatePass ? 'PASS' : 'CHANGES_REQUESTED',
  verdicts: reviews.map((r) => ({ dimension: r.dimension, verdict: r.verdict, findings: (r.findings || []).length })),
  blockersAndMajors: overallBlockers.length,
  consolidated: synthesis,
}
