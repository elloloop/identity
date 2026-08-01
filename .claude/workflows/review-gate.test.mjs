// Stubbed-harness tests for the review-gate decision logic.
//
// The gate's agent() calls hit the Claude Code harness at runtime, but the
// gate-decision branches (self-gate SKIPPED handling, blocking-finding
// arithmetic, fail-closed dropped-reviewer handling) are pure control flow
// we CAN test by stubbing the harness globals.
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

const ROSTER_SIZE = 8
// Roster slots 0 (Correctness) and 1 (Security & Auth) are declared
// alwaysApplies — they may never return SKIPPED.
const FIRST_SKIPPABLE = 2

async function run({ reviewerVerdict, dropReviewer, postFail, postNull }) {
  let reviewIdx = 0
  const harness = {
    args: 154,
    phase: () => {},
    log: () => {},
    parallel: async (thunks) => Promise.all(thunks.map((t) => t())),
    agent: async (_prompt, opts) => {
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
  return fn(...Object.values(harness))
}

const approveAll = () => ({ verdict: 'APPROVE', summary: 's', findings: [] })
const skipped = (extra = {}) => ({ verdict: 'SKIPPED', skipReason: 'lens does not apply', findings: [], ...extra })
const only = (idx, result) => (i) => (i === idx ? result : approveAll())

const skipSome = (i) => (i >= FIRST_SKIPPABLE && i % 2 === 0 ? skipped() : approveAll())
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

const tests = {
  async 'all approve -> APPROVED with full roster'() {
    const r = await run({ reviewerVerdict: approveAll })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.roster.length, ROSTER_SIZE)
    assert.equal(r.blockingFindings, 0)
    assert.equal(r.structuralGaps, 0)
  },
  async 'self-gated skips do not block'() {
    const r = await run({ reviewerVerdict: skipSome })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.skipped.length, 3) // slots 2, 4, 6
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
  async 'SKIPPED from a non-skippable lens -> fail closed'() {
    const r = await run({ reviewerVerdict: nonSkippableSkipped })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
    assert.equal(r.skipped.length, 0)
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
