// Stubbed-harness tests for the review-gate decision logic.
//
// The gate's agent() calls hit the Claude Code harness at runtime, but the
// gate-decision branches (the two stages and when each runs, blocking-finding
// arithmetic, fail-closed dropped-reviewer handling, PR vs issue mode) are
// pure control flow we CAN test by stubbing the harness globals.
// Run: `node .claude/workflows/review-gate.test.mjs`.
//
// These guard the safety-critical property that the gate FAILS CLOSED. The
// pass condition reads exactly one signal — `blocking: true` on a finding —
// so each self-contradiction case below is a way a reviewer could disagree
// with that signal and still be counted as a pass.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import assert from 'node:assert/strict'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'review-gate.js'), 'utf8').replace(/^export\s+const\s+meta\s*=/, 'const meta =')

const SYNTH = 'synthesize:pr-154'

// run executes the gate against stubbed harness globals. `results` maps a
// reviewer label to what that reviewer returns (default: a clean APPROVE).
// It returns the gate's result plus every agent call in order, with its
// prompt and options, so tests can assert who ran and what each was told.
async function run({ results = {}, postFail, postNull, args = 154 } = {}) {
  const calls = []
  const harness = {
    args,
    phase: () => {},
    log: () => {},
    agent: async (prompt, opts) => {
      calls.push({ label: opts.label, prompt, opts })
      if (opts.schema) return opts.label in results ? results[opts.label] : approve
      if (postNull) return null
      return postFail ? 'POST_FAILED: gh err' : 'https://gh/review\n## md'
    },
  }
  const fn = new Function(...Object.keys(harness), `return (async () => { ${src}\n })()`)
  const result = await fn(...Object.values(harness))
  const by = Object.fromEntries(calls.map((c) => [c.label, c]))
  return { ...result, calls, labels: calls.map((c) => c.label), by }
}

// The review data the synthesizer was handed, parsed back out of its prompt.
function synthData(r, label = SYNTH) {
  const m = /=== BEGIN UNTRUSTED REVIEW DATA ===\n([\s\S]*?)\n=== END UNTRUSTED REVIEW DATA ===/.exec(r.by[label].prompt)
  return JSON.parse(m[1])
}

const approve = { verdict: 'APPROVE', summary: 's', findings: [] }
const finding = (blocking, severity = blocking ? 'blocker' : 'major') => ({ severity, blocking, title: 't', detail: 'd' })
const blocked = { verdict: 'REQUEST_CHANGES', summary: 's', findings: [finding(true)] }
const nonBlockingOnly = { verdict: 'APPROVE', summary: 's', findings: [finding(false)] }

// Each resolves to "no blocking finding" and would pass the gate if it were
// not caught structurally.
const SELF_CONTRADICTIONS = {
  'no result': null,
  'no findings array': { verdict: 'APPROVE' },
  'REQUEST_CHANGES with nothing blocking': { verdict: 'REQUEST_CHANGES', summary: 's', findings: [finding(false)] },
  "a 'blocker' not marked blocking": { verdict: 'APPROVE', summary: 's', findings: [finding(false, 'blocker')] },
  'SKIPPED': { verdict: 'SKIPPED', skipReason: 'lens does not apply', findings: [] },
}

const tests = {
  async 'both stages clean -> APPROVED, Stage 1 runs before Stage 2'() {
    const r = await run()
    assert.equal(r.gate, 'APPROVED')
    assert.deepEqual(r.labels, ['security', 'general', SYNTH])
    assert.deepEqual(r.ran, ['Security & Auth', 'General'])
    assert.deepEqual(r.verdicts.map((v) => v.stage), [1, 2])
    assert.equal(r.blockingFindings, 0)
    assert.equal(r.structuralGaps, 0)
    assert.equal(r.target, 'pr')
    assert.equal(r.number, '154')
    assert.equal(r.nextStep, 'Merge once CI is green.')
  },
  async 'each agent runs at its effort'() {
    const r = await run()
    assert.equal(r.by.security.opts.effort, 'high')
    assert.equal(r.by.general.opts.effort, 'medium')
    assert.equal(r.by[SYNTH].opts.effort, 'low')
    const issue = await run({ args: 'issue:42' })
    assert.equal(issue.by['issue-disclosure'].opts.effort, 'low')
  },
  async 'non-blocking findings alone -> APPROVED'() {
    const r = await run({ results: { security: nonBlockingOnly, general: nonBlockingOnly } })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.blockingFindings, 0)
  },
  async 'a Stage 1 blocking finding -> BLOCKED, Stage 2 does not run, re-run the gate'() {
    const r = await run({ results: { security: blocked } })
    assert.equal(r.gate, 'BLOCKED')
    assert.equal(r.blockingFindings, 1)
    assert.deepEqual(r.labels, ['security', SYNTH])
    assert.match(r.nextStep, /re-run Workflow\(\{name: 'review-gate', args: 154\}\)/)
    assert.match(r.nextStep, /Stage 2 runs once it does/)
    assert.match(r.by[SYNTH].prompt, /\*\*Next step:\*\* Fix each Stage 1 blocking finding/)
  },
  async 'a Stage 2 blocking finding -> FIX_AND_RECORD, never a Stage 2 re-run'() {
    const r = await run({ results: { general: blocked } })
    assert.equal(r.gate, 'FIX_AND_RECORD')
    assert.equal(r.blockingFindings, 1)
    assert.equal(r.structuralGaps, 0)
    assert.match(r.nextStep, /record on the PR how each was fixed; Stage 2 is not re-run/)
    assert.match(r.nextStep, /args: 'security:154'/)
    assert.doesNotMatch(r.nextStep, /general:154/)
    assert.match(r.by[SYNTH].prompt, /## PR review gate: ⚠️ FIX AND RECORD/)
  },
  async 'a self-contradictory Stage 1 fails closed and stops the gate'() {
    for (const [name, result] of Object.entries(SELF_CONTRADICTIONS)) {
      const r = await run({ results: { security: result } })
      assert.equal(r.gate, 'BLOCKED', name)
      assert.equal(r.structuralGaps, 1, name)
      assert.equal(r.verdicts[0].verdict, 'BLOCKED', name)
      assert.deepEqual(r.labels, ['security', SYNTH], name)
    }
  },
  async 'a self-contradictory Stage 2 fails closed and is replaced with general:<n>'() {
    for (const [name, result] of Object.entries(SELF_CONTRADICTIONS)) {
      const r = await run({ results: { general: result } })
      assert.equal(r.gate, 'BLOCKED', name)
      assert.equal(r.structuralGaps, 1, name)
      assert.equal(r.verdicts[1].dimension, 'General', name)
      assert.equal(r.verdicts[1].verdict, 'BLOCKED', name)
      assert.match(r.nextStep, /args: 'general:154'/, name)
    }
  },
  async 'a self-contradictory reviewer keeps what it did report'() {
    const r = await run({ results: { security: { verdict: 'REQUEST_CHANGES', summary: 's', findings: [null, finding(false)] } } })
    const sec = synthData(r).reviews[0]
    assert.equal(sec.verdict, 'BLOCKED')
    assert.equal(sec.findings.length, 2)
    assert.equal(sec.findings[1].severity, 'major')
  },
  async 'security:<n> runs Stage 1 alone'() {
    const clean = await run({ args: 'security:154' })
    assert.equal(clean.gate, 'APPROVED')
    assert.deepEqual(clean.labels, ['security', SYNTH])
    assert.match(clean.nextStep, /every blocking finding of the one Stage 2 run is fixed and recorded/)
    const again = await run({ args: 'security:154', results: { security: blocked } })
    assert.equal(again.gate, 'BLOCKED')
    assert.match(again.nextStep, /args: 'security:154'/)
    assert.doesNotMatch(again.nextStep, /Stage 2 runs/)
  },
  async 'general:<n> runs Stage 2 alone'() {
    const r = await run({ args: 'general:154' })
    assert.equal(r.gate, 'APPROVED')
    assert.deepEqual(r.labels, ['general', SYNTH])
    assert.deepEqual(r.ran, ['General'])
  },
  async 'only Stage 1 reads the published PR text and its history'() {
    const r = await run()
    const security = r.by.security.prompt
    assert.match(security, /MATERIAL TO REVIEW/)
    assert.match(security, /--json commits/)
    assert.match(security, /closingIssuesReferences/)
    assert.match(security, /never repeat a sensitive value verbatim/i)
    assert.match(security, /DISCLOSED PRIVATE DETAILS/)
    // What GitHub keeps public after a fix is material too: the edit
    // history of the description, comments, review bodies and review-thread
    // comments, and the commits each force-push replaced.
    const history = /`(gh api graphql [^`]*)`/.exec(security)?.[1] ?? ''
    assert.match(history, /-F n=154 /)
    assert.match(history, /pullRequest\(number:\$n\)\{userContentEdits\(first:100\)/)
    // The current text of every comment, review body and inline review
    // comment, not only its earlier revisions.
    assert.match(history, /comments\(first:100\)\{pageInfo\{hasNextPage\} nodes\{author\{login\} body userContentEdits/)
    assert.match(history, /reviews\(first:100\)\{pageInfo\{hasNextPage\} nodes\{author\{login\} body userContentEdits/)
    assert.match(history, /reviewThreads\(first:100\)\{pageInfo\{hasNextPage\} nodes\{comments\([^)]*\)\{pageInfo\{hasNextPage\} nodes\{author\{login\} path body userContentEdits/)
    assert.match(history, /HEAD_REF_FORCE_PUSHED_EVENT[^']*beforeCommit\{oid\} afterCommit\{oid\}/)
    assert.match(history, /RENAMED_TITLE_EVENT[^']*RenamedTitleEvent\{previousTitle\}/)
    assert.match(security, /compare\/<afterCommit>\.\.\.<beforeCommit>/)
    // A list cut short at a page cap is never read as clean.
    assert.equal((history.match(/first:/g) ?? []).length, (history.match(/pageInfo\{hasNextPage\}/g) ?? []).length)
    assert.match(security, /hasNextPage is true[^.]*finding; an unread list is never clean/)
    // Stage 2 reads the title and body for intent, and owns neutrality.
    const general = r.by.general.prompt
    assert.match(general, /gh pr view 154/)
    assert.match(general, /CLIENT- OR DEPLOYMENT-SPECIFIC/)
    assert.match(general, /never repeat a sensitive value verbatim/i)
    assert.doesNotMatch(general, /MATERIAL TO REVIEW|gh api graphql|--comments|--json commits/)
  },
  async 'every reviewer is held to the diff and a short report'() {
    const r = await run()
    const issue = await run({ args: 'issue:42' })
    for (const prompt of [r.by.security.prompt, r.by.general.prompt]) {
      assert.match(prompt, /the code it directly touches or calls/)
      assert.match(prompt, /No repo-wide exploration/)
    }
    for (const prompt of [r.by.security.prompt, r.by.general.prompt, issue.by['issue-disclosure'].prompt]) {
      assert.match(prompt, /ONLY when you have confirmed it against the code or text itself/)
      assert.match(prompt, /at most 5 non-blocking ones, most important first/)
    }
  },
  async 'non-blocking findings past the cap are dropped, blocking ones never'() {
    const many = { verdict: 'REQUEST_CHANGES', summary: 's', findings: [...Array.from({ length: 8 }, () => finding(false)), finding(true), finding(true)] }
    const r = await run({ results: { general: many } })
    const general = synthData(r).reviews[1]
    assert.equal(general.findings.length, 7)
    assert.equal(general.findings.filter((f) => f.blocking).length, 2)
    assert.equal(r.blockingFindings, 2)
  },
  async 'PR mode posts a concise --comment review and keeps findings undisclosed'() {
    const r = await run()
    const synth = r.by[SYNTH].prompt
    assert.match(synth, /gh pr review 154 --comment --body-file/)
    assert.doesNotMatch(synth, /gh issue comment/)
    assert.match(synth, /never quote a hostname, domain, product or client name/)
    assert.match(synth, /ONE CONCISE consolidated review/)
    assert.match(synth, /## PR review gate: ✅ APPROVED/)
    assert.match(synth, /Stage 1 \(Security & Auth\), Stage 2 \(General\)/)
  },
  async 'issue mode runs Neutrality & Disclosure alone and comments on the issue'() {
    const r = await run({ args: 'issue:42' })
    assert.equal(r.target, 'issue')
    assert.equal(r.number, '42')
    assert.deepEqual(r.ran, ['Neutrality & Disclosure'])
    assert.equal(r.gate, 'CLEAN')
    assert.equal(r.posted, true)
    assert.deepEqual(r.labels, ['issue-disclosure', 'synthesize:issue-42'])
    const prompt = r.by['issue-disclosure'].prompt
    assert.match(prompt, /gh issue view 42 --comments/)
    assert.match(prompt, /CLIENT- OR DEPLOYMENT-SPECIFIC/)
    assert.match(prompt, /DISCLOSED PRIVATE DETAILS/)
    const history = /`(gh api graphql [^`]*)`/.exec(prompt)?.[1] ?? ''
    assert.match(history, /-F n=42 /)
    assert.match(history, /issue\(number:\$n\)\{userContentEdits\(first:100\)[^']*comments\(first:100\)\{pageInfo\{hasNextPage\} nodes\{author\{login\} body userContentEdits/)
    assert.match(history, /timelineItems\(itemTypes:RENAMED_TITLE_EVENT,[^']*RenamedTitleEvent\{previousTitle\}/)
    assert.doesNotMatch(history, /reviews|reviewThreads|HEAD_REF_FORCE_PUSHED_EVENT/)
    assert.match(prompt, /an unread list is never clean/)
    assert.doesNotMatch(prompt, /gh pr /)
    const synth = r.by['synthesize:issue-42'].prompt
    assert.match(synth, /gh issue comment 42 --body-file/)
    assert.doesNotMatch(synth, /gh pr review/)
    assert.match(synth, /## Issue disclosure check: ✅ CLEAN/)
  },
  async 'issue mode: a blocking finding flags the issue'() {
    const r = await run({ args: 'issue:42', results: { 'issue-disclosure': blocked } })
    assert.equal(r.gate, 'FLAGGED')
    assert.equal(r.blockingFindings, 1)
  },
  async 'issue mode: a self-contradictory result flags the issue'() {
    for (const [name, result] of Object.entries(SELF_CONTRADICTIONS)) {
      const r = await run({ args: 'issue:42', results: { 'issue-disclosure': result } })
      assert.equal(r.gate, 'FLAGGED', name)
      assert.equal(r.structuralGaps, 1, name)
    }
  },
  async 'malformed args are refused'() {
    for (const args of [null, '', 'abc', 'issue:', 'issue:4x', 'pr:12', '-1', 'issue: 12', 'security:', 'general:x', 'security: 12', 'sec:12', 'security:general:12']) {
      await assert.rejects(run({ args }), /review-gate: pass a PR number/, String(args))
    }
  },
  async 'failed post is surfaced (posted=false), gate still computed'() {
    const r = await run({ postFail: true })
    assert.equal(r.gate, 'APPROVED')
    assert.equal(r.posted, false)
  },
  async 'null synthesis is not a successful post'() {
    const r = await run({ postNull: true })
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
