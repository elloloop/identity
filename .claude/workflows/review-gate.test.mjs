// Stubbed-harness tests for the review-gate decision logic.
//
// The gate's agent() calls hit the Claude Code harness at runtime, but the
// gate-decision branches (self-gate SKIPPED handling, blocking-finding
// arithmetic, fail-closed dropped-reviewer handling, PR vs issue mode) are
// pure control flow we CAN test by stubbing the harness globals.
// Run: `node .claude/workflows/review-gate.test.mjs`.
//
// These guard the safety-critical property that the gate FAILS CLOSED. The
// pass condition reads exactly one signal — `blocking: true` on a finding —
// so each case below is a way a reviewer could disagree with that signal and
// still be counted as a pass. A SKIPPED reviewer must not block (self-gating
// is a clean outcome); everything self-contradictory must.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import assert from 'node:assert/strict'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'review-gate.js'), 'utf8').replace(/^export\s+const\s+meta\s*=/, 'const meta =')

const ROSTER_SIZE = 9
// Roster slots 0 (Correctness), 1 (Security & Auth) and 2 (Neutrality &
// Disclosure) are declared alwaysApplies — they may never return SKIPPED.
const NEUTRALITY = 2
const FIRST_SKIPPABLE = 3

// run executes the gate against stubbed harness globals. It returns the
// gate's result plus every prompt the gate sent, keyed by agent label, so
// tests can assert what each reviewer and the synthesizer were told.
async function run({ reviewerVerdict, dropReviewer, postFail, postNull, args = 154 }) {
  let reviewIdx = 0
  const prompts = {}
  const harness = {
    args,
    phase: () => {},
    log: () => {},
    parallel: async (thunks) => Promise.all(thunks.map((t) => t())),
    agent: async (prompt, opts) => {
      prompts[opts.label] = prompt
      if (opts?.schema?.properties?.verdict?.enum?.includes('SKIPPED')) {
        const i = reviewIdx++
        if (dropReviewer === i) return null
        return reviewerVerdict(i)
      }
      if (postNull) return null
      return postFail ? 'POST_FAILED: gh err' : 'https://gh/review\n## md'
    },
  }
  const fn = new Function(...Object.keys(harness), `return (async () => { ${src}\n })()`)
  const result = await fn(...Object.values(harness))
  return { ...result, prompts }
}

const approveAll = () => ({ verdict: 'APPROVE', summary: 's', findings: [] })
const skipped = (extra = {}) => ({ verdict: 'SKIPPED', skipReason: 'lens does not apply', findings: [], ...extra })
const only = (idx, result) => (i) => (i === idx ? result : approveAll())

const skipSome = (i) => (i >= FIRST_SKIPPABLE && i % 2 === 0 ? skipped() : approveAll())
const blockingFinding = {
  verdict: 'REQUEST_CHANGES',
  summary: 's',
  findings: [{ severity: 'blocker', blocking: true, title: 't', detail: 'a production hostname in the PR body' }],
}
const blockOne = only(FIRST_SKIPPABLE, {
  verdict: 'REQUEST_CHANGES',
  summary: 's',
  findings: [{ severity: 'blocker', blocking: true, title: 't', detail: 'd' }],
})
const nonBlockingOnly = only(FIRST_SKIPPABLE, {
  verdict: 'APPROVE',
  summary: 's',
  findings: [{ severity: 'major', blocking: false, title: 't', detail: 'd' }],
})
const malformedOne = only(3, { verdict: 'APPROVE' }) // findings array missing

// The self-contradiction cases: each resolves to "no blocking finding" and
// would pass the gate if it were not caught structurally.
const changesWithoutBlocking = only(3, {
  verdict: 'REQUEST_CHANGES',
  summary: 's',
  findings: [{ severity: 'major', blocking: false, title: 't', detail: 'd' }],
})
const blockerSeverityNotBlocking = only(3, {
  verdict: 'APPROVE',
  summary: 's',
  findings: [{ severity: 'blocker', blocking: false, title: 't', detail: 'd' }],
})
const skippedWithFindings = only(3, skipped({
  findings: [{ severity: 'major', blocking: false, title: 't', detail: 'd' }],
}))
const nonSkippableSkipped = only(0, skipped())
const neutralitySkipped = only(NEUTRALITY, skipped())
const skippedWithoutReason = only(3, { verdict: 'SKIPPED', findings: [] })

const tests = {
  async 'all approve -> APPROVED with full roster'() {
    const r = await run({ reviewerVerdict: approveAll })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.roster.length, ROSTER_SIZE)
    assert.equal(r.blockingFindings, 0)
    assert.equal(r.structuralGaps, 0)
  },
  async 'roster is the nine fixed lenses, Neutrality & Disclosure third'() {
    const r = await run({ reviewerVerdict: approveAll })
    assert.deepEqual(r.roster, [
      'Correctness', 'Security & Auth', 'Neutrality & Disclosure', 'API Contract',
      'Data & Migrations', 'Config & Operability', 'Maintainability & Tests',
      'Performance & Concurrency', 'Product & Docs',
    ])
    assert.equal(r.target, 'pr')
    assert.equal(r.number, '154')
  },
  async 'self-gated skips do not block'() {
    const r = await run({ reviewerVerdict: skipSome })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.skipped.length, 3) // slots 4, 6, 8
    assert.ok(r.verdicts.some((v) => v.verdict === 'SKIPPED'))
  },
  async 'one blocking finding -> BLOCKED'() {
    const r = await run({ reviewerVerdict: blockOne })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.blockingFindings, 1)
  },
  async 'non-blocking findings alone -> APPROVED'() {
    const r = await run({ reviewerVerdict: nonBlockingOnly })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.blockingFindings, 0)
  },
  async 'dropped reviewer -> fail closed (structural gap)'() {
    const r = await run({ reviewerVerdict: approveAll, dropReviewer: 4 })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'malformed reviewer (no findings array) -> fail closed'() {
    const r = await run({ reviewerVerdict: malformedOne })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'REQUEST_CHANGES with no blocking finding -> fail closed'() {
    const r = await run({ reviewerVerdict: changesWithoutBlocking })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async "severity 'blocker' not marked blocking -> fail closed"() {
    const r = await run({ reviewerVerdict: blockerSeverityNotBlocking })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'SKIPPED while reporting findings -> fail closed'() {
    const r = await run({ reviewerVerdict: skippedWithFindings })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'SKIPPED without a reason -> fail closed'() {
    const r = await run({ reviewerVerdict: skippedWithoutReason })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'SKIPPED from a non-skippable lens -> fail closed'() {
    const r = await run({ reviewerVerdict: nonSkippableSkipped })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
    assert.equal(r.skipped.length, 0)
  },
  async 'SKIPPED from Neutrality & Disclosure -> fail closed'() {
    const r = await run({ reviewerVerdict: neutralitySkipped })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
    assert.equal(r.verdicts[NEUTRALITY].dimension, 'Neutrality & Disclosure')
    assert.equal(r.verdicts[NEUTRALITY].verdict, 'BLOCKED')
  },
  async 'a Neutrality & Disclosure blocking finding blocks the PR'() {
    const r = await run({ reviewerVerdict: only(NEUTRALITY, blockingFinding) })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.blockingFindings, 1)
    assert.equal(r.structuralGaps, 0)
  },
  async 'only Neutrality & Disclosure reads the submitter-authored text'() {
    const r = await run({ reviewerVerdict: approveAll })
    const neutrality = r.prompts['neutrality-disclosure']
    assert.match(neutrality, /MATERIAL TO REVIEW/)
    assert.match(neutrality, /--json commits/)
    assert.match(neutrality, /closingIssuesReferences/)
    assert.match(neutrality, /never repeat a sensitive value verbatim/i)
    // What GitHub keeps public after a fix is material too: the edit
    // history of the description and comments, and force-pushed commits.
    assert.match(neutrality, /pullRequest\(number:\$n\)\{userContentEdits/)
    assert.match(neutrality, /comments\(first:100\)\{nodes\{userContentEdits/)
    assert.match(neutrality, /HEAD_REF_FORCE_PUSHED_EVENT[^`]*beforeCommit/)
    assert.match(neutrality, /-F n=154 /)
    assert.doesNotMatch(neutrality, /MUST NOT influence this decision/)
    // Every self-gating lens still decides relevance from the file list
    // alone, with the submitter-authored text kept out of that decision.
    for (const label of ['api-contract', 'data-migrations', 'config-operability',
      'maintainability-tests', 'performance-concurrency', 'product-docs']) {
      assert.match(r.prompts[label], /FROM THAT CHANGED-FILE LIST ALONE/, label)
      assert.match(r.prompts[label], /MUST NOT influence this decision/, label)
      assert.doesNotMatch(r.prompts[label], /MATERIAL TO REVIEW/, label)
    }
  },
  async 'PR mode posts a --comment review and keeps findings undisclosed'() {
    const r = await run({ reviewerVerdict: approveAll })
    const synth = r.prompts['synthesize:pr-154']
    assert.match(synth, /gh pr review 154 --comment --body-file/)
    assert.doesNotMatch(synth, /gh issue comment/)
    assert.match(synth, /never quote a hostname, domain, product or client name/)
    assert.match(synth, /fixed 9-reviewer roster/)
  },
  async 'issue mode runs Neutrality & Disclosure alone and comments on the issue'() {
    const r = await run({ reviewerVerdict: approveAll, args: 'issue:42' })
    assert.equal(r.target, 'issue')
    assert.equal(r.number, '42')
    assert.deepEqual(r.roster, ['Neutrality & Disclosure'])
    assert.equal(r.gate, 'CLEAN')
    assert.equal(r.posted, true)
    assert.deepEqual(Object.keys(r.prompts).sort(), ['neutrality-disclosure', 'synthesize:issue-42'])
    assert.match(r.prompts['neutrality-disclosure'], /gh issue view 42 --comments/)
    assert.match(r.prompts['neutrality-disclosure'], /issue\(number:\$n\)\{userContentEdits[^`]*comments\(first:100\)\{nodes\{userContentEdits/)
    assert.match(r.prompts['neutrality-disclosure'], /-F n=42 /)
    assert.doesNotMatch(r.prompts['neutrality-disclosure'], /gh pr /)
    const synth = r.prompts['synthesize:issue-42']
    assert.match(synth, /gh issue comment 42 --body-file/)
    assert.doesNotMatch(synth, /gh pr review/)
  },
  async 'issue mode: a blocking finding flags the issue'() {
    const r = await run({ reviewerVerdict: () => blockingFinding, args: 'issue:42' })
    assert.equal(r.gate, 'FLAGGED')
    assert.equal(r.blockingFindings, 1)
  },
  async 'issue mode: SKIPPED fails closed'() {
    const r = await run({ reviewerVerdict: () => skipped(), args: 'issue:42' })
    assert.equal(r.gate, 'FLAGGED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'issue mode: a dropped reviewer fails closed'() {
    const r = await run({ reviewerVerdict: approveAll, dropReviewer: 0, args: 'issue:42' })
    assert.equal(r.gate, 'FLAGGED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'malformed args are refused'() {
    for (const args of [null, '', 'abc', 'issue:', 'issue:4x', 'pr:12', '-1', 'issue: 12']) {
      await assert.rejects(run({ reviewerVerdict: approveAll, args }), /review-gate: pass a PR number/, String(args))
    }
  },
  async 'failed post is surfaced (posted=false), gate still computed'() {
    const r = await run({ reviewerVerdict: approveAll, postFail: true })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.posted, false)
  },
  async 'null synthesis is not a successful post'() {
    const r = await run({ reviewerVerdict: approveAll, postNull: true })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.posted, false)
  },
}

let failed = 0
for (const [name, fn] of Object.entries(tests)) {
  try {
    await fn()
    console.log(`ok   - ${name}`)
  } catch (e) {
    failed++
    console.error(`FAIL - ${name}\n       ${e.message}`)
  }
}
console.log(`\n${Object.keys(tests).length - failed}/${Object.keys(tests).length} passed`)
process.exit(failed ? 1 : 0)
