// Stubbed-harness tests for the review-gate decision logic.
//
// The gate's agent() calls hit the Claude Code harness at runtime, but the
// gate-decision branches (self-gate SKIPPED handling, blocking-finding
// arithmetic, fail-closed dropped-reviewer handling) are pure control flow
// we CAN test by stubbing the harness globals.
// Run: `node .claude/workflows/review-gate.test.mjs`.
//
// These guard the safety-critical properties: a SKIPPED reviewer must not
// block (self-gating is a clean outcome), a blocking finding from any
// proceeding reviewer must block, and a dropped/malformed reviewer must
// fail closed.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import assert from 'node:assert/strict'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'review-gate.js'), 'utf8').replace(/^export\s+const\s+meta\s*=/, 'const meta =')

const ROSTER_SIZE = 8

async function run({ reviewerVerdict, dropReviewer, postFail }) {
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
      return postFail ? 'POST_FAILED: gh err' : 'https://gh/review\n## md'
    },
  }
  const fn = new Function(...Object.keys(harness), `return (async () => { ${src}\n })()`)
  return fn(...Object.values(harness))
}

const approveAll = () => ({ verdict: 'APPROVE', summary: 's', findings: [] })
const skipSome = (i) =>
  i % 2 === 0 ? { verdict: 'SKIPPED', skipReason: 'lens does not apply', findings: [] } : approveAll()
const blockOne = (i) =>
  i === 1
    ? { verdict: 'REQUEST_CHANGES', summary: 's', findings: [{ severity: 'blocker', blocking: true, title: 't', detail: 'd' }] }
    : approveAll()
const nonBlockingOnly = (i) =>
  i === 2
    ? { verdict: 'APPROVE', summary: 's', findings: [{ severity: 'major', blocking: false, title: 't', detail: 'd' }] }
    : approveAll()
const malformedOne = (i) => (i === 3 ? { verdict: 'APPROVE' } : approveAll()) // findings array missing

const tests = {
  async 'all approve -> APPROVED with full roster'() {
    const r = await run({ reviewerVerdict: approveAll })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.roster.length, ROSTER_SIZE)
    assert.equal(r.confirmedBlockers, 0)
  },
  async 'self-gated skips do not block'() {
    const r = await run({ reviewerVerdict: skipSome })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.skipped.length, ROSTER_SIZE / 2)
    assert.ok(r.verdicts.some((v) => v.verdict === 'SKIPPED'))
  },
  async 'one blocking finding -> BLOCKED'() {
    const r = await run({ reviewerVerdict: blockOne })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.confirmedBlockers, 1)
  },
  async 'non-blocking findings alone -> APPROVED'() {
    const r = await run({ reviewerVerdict: nonBlockingOnly })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.confirmedBlockers, 0)
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
  async 'failed post is surfaced (posted=false), gate still computed'() {
    const r = await run({ reviewerVerdict: approveAll, postFail: true })
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
