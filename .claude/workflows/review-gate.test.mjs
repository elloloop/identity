// Stubbed-harness tests for the review-gate decision logic.
//
// The gate's agent() calls hit the Claude Code harness at runtime, but the
// gate-decision branches (conditional-reviewer selection, adversarial-verify
// outcome, fail-open/fail-closed) are pure control flow we CAN test by
// stubbing the harness globals. Run: `node .claude/workflows/review-gate.test.mjs`.
//
// These guard the safety-critical properties: a refuted sole-blocker must
// flip the gate to APPROVED (the whole point of Verify), and a dropped
// reviewer / crashed-or-malformed verifier must fail closed.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import assert from 'node:assert/strict'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'review-gate.js'), 'utf8').replace(/^export\s+const\s+meta\s*=/, 'const meta =')

async function run({ triage, reviewerVerdict, verify, dropReviewer, postFail }) {
  let reviewIdx = 0
  const harness = {
    args: 154,
    phase: () => {},
    log: () => {},
    parallel: async (thunks) => Promise.all(thunks.map((t) => t())),
    agent: async (_prompt, opts) => {
      const label = opts?.label || ''
      if (label.startsWith('triage')) return triage
      if (label.startsWith('gather')) return 'DIFF BUNDLE'
      if (opts?.schema?.properties?.verdict?.enum?.includes('APPROVE')) {
        const i = reviewIdx++
        if (dropReviewer === i) return null
        return reviewerVerdict(i)
      }
      if (opts?.schema?.properties?.confirmed) return verify
      return postFail ? 'POST_FAILED: gh err' : 'https://gh/review\n## md'
    },
  }
  const fn = new Function(...Object.keys(harness), `return (async () => { ${src}\n })()`)
  return fn(...Object.values(harness))
}

const approveAll = () => ({ verdict: 'APPROVE', summary: 's', findings: [] })
const blockOne = (i) =>
  i === 1
    ? { verdict: 'REQUEST_CHANGES', summary: 's', findings: [{ severity: 'blocker', blocking: true, title: 't', detail: 'd' }] }
    : approveAll()

const tests = {
  async 'clean backend diff -> 5 reviewers, APPROVED'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: approveAll, verify: { confirmed: false } })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.selectedReviewers.length, 5)
  },
  async 'contract+UI diff -> 7 reviewers'() {
    const r = await run({ triage: { touchesContract: true, touchesUI: true }, reviewerVerdict: approveAll, verify: { confirmed: false } })
    assert.equal(r.selectedReviewers.length, 7)
  },
  async 'sole blocker REFUTED -> APPROVED (the Verify-phase promise)'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: blockOne, verify: { confirmed: false } })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.confirmedBlockers, 0)
    const sec = r.verdicts.find((v) => v.dimension === 'Security')
    assert.equal(sec.rawVerdict, 'REQUEST_CHANGES')
    assert.equal(sec.effectiveVerdict, 'APPROVE')
  },
  async 'blocker CONFIRMED -> BLOCKED'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: blockOne, verify: { confirmed: true } })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.confirmedBlockers, 1)
  },
  async 'dropped reviewer -> fail closed (structural gap)'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: approveAll, verify: { confirmed: false }, dropReviewer: 2 })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.structuralGaps, 1)
  },
  async 'crashed verifier (null) -> fail closed, blocker survives'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: blockOne, verify: null })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.confirmedBlockers, 1)
  },
  async 'malformed verifier (confirmed missing) -> fail closed, blocker survives'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: blockOne, verify: { reasoning: 'no confirmed field' } })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.confirmedBlockers, 1)
  },
  async 'triage fails -> fail open to 7 reviewers'() {
    const r = await run({ triage: null, reviewerVerdict: approveAll, verify: { confirmed: false } })
    assert.equal(r.selectedReviewers.length, 7)
  },
  async 'failed post is surfaced (posted=false)'() {
    const r = await run({ triage: { touchesContract: false, touchesUI: false }, reviewerVerdict: approveAll, verify: { confirmed: false }, postFail: true })
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
