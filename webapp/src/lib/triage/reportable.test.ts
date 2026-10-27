/**
 * Which findings the deliverable surfaces count, after the Priority Board.
 *
 * The report, Insights and the MCP analytics tools count a finding unless a
 * PERSON judged it a false positive or a rule resolved it. An AI review alone
 * never removes one: the reviewer reads target-controlled text, so an injected
 * "this is a test key" must at most re-rank a finding, never hide it.
 *
 * The TypeScript and Cypher halves are built from the same constants; the live
 * parity check is reportable.integration.test.ts.
 */
import { describe, test, expect } from 'vitest'
import {
  RESOLVED_TRIAGE_STATES,
  isReportCountable,
  reportBucket,
  reportBucketCypher,
  reportCountable,
} from './reportable'

describe('reportBucket', () => {
  test('a finding with no triage props is counted, exactly as before the board', () => {
    expect(reportBucket({})).toBe('counted')
    expect(isReportCountable({})).toBe(true)
  })

  test("a person's False positive is excluded", () => {
    const p = { triage_status: 'likely_noise', triage_source: 'human', triage_state: 'false_positive' }
    expect(reportBucket(p)).toBe('person_false_positive')
    expect(isReportCountable(p)).toBe(false)
  })

  test.each(['fixed', 'gone', 'inactive'])('a rule-resolved %s finding is excluded', (state) => {
    expect(reportBucket({ triage_state: state })).toBe('resolved')
    expect(isReportCountable({ triage_state: state })).toBe(false)
  })

  test('an AI-only false positive stays counted, and is flagged', () => {
    const p = { triage_state: 'false_positive', triage_decided_by: 'review' }
    expect(reportBucket(p)).toBe('ai_flagged')
    expect(isReportCountable(p)).toBe(true)
  })

  test("SECURITY: a legacy AI likely_noise (triage_source 'ai') is not a person's verdict", () => {
    // v3.1 wrote the builtin reviewer's false positive into triage_status. Until
    // the next publish cleans it up, it must not hide the finding.
    const p = { triage_status: 'likely_noise', triage_source: 'ai' }
    expect(reportBucket(p)).toBe('ai_flagged')
    expect(isReportCountable(p)).toBe(true)
  })

  test('likely_noise with no source is not a decision (mirrors evidence.person_decided)', () => {
    expect(reportBucket({ triage_status: 'likely_noise' })).toBe('counted')
  })

  test('a resolved state wins over a person\'s verdict, as in combine_layers and _section_of', () => {
    const p = { triage_state: 'gone', triage_status: 'likely_noise', triage_source: 'human' }
    expect(reportBucket(p)).toBe('resolved')
  })

  test("a person's Real is counted", () => {
    expect(reportBucket({ triage_status: 'confirmed', triage_source: 'human', triage_state: 'open' }))
      .toBe('counted')
  })

  test('an unknown or legacy state reads as open, never as judged', () => {
    for (const state of ['open', 'needs_verification', 'weird', '', null, 7]) {
      expect(reportBucket({ triage_state: state }), String(state)).toBe('counted')
    }
  })
})

describe('the Cypher halves', () => {
  test('reportCountable names the resolved states and the person test', () => {
    const q = reportCountable('v')
    expect(q).toBe(
      "NOT (coalesce(v.triage_status, '') = 'likely_noise' AND coalesce(v.triage_source, '') = 'human')" +
      " AND NOT coalesce(v.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
    )
    for (const s of RESOLVED_TRIAGE_STATES) expect(q).toContain(`'${s}'`)
  })

  test('reportCountable binds only the variable it is given', () => {
    const q = reportCountable('jf')
    expect(q).not.toMatch(/\bv\./)
    expect(q).toMatch(/jf\.triage_state/)
  })

  test('the bucket CASE checks resolved first, then the person, then the AI', () => {
    const q = reportBucketCypher('n')
    const order = ['resolved', 'person_false_positive', 'ai_flagged', 'counted']
      .map((b) => q.indexOf(`'${b}'`))
    expect(order.every((i) => i >= 0)).toBe(true)
    expect([...order].sort((a, b) => a - b)).toEqual(order)
  })

  test('neither half names the Muted label or binds a parameter, so MCP Cypher can carry it', () => {
    for (const q of [reportCountable('b1'), reportBucketCypher('b1')]) {
      expect(q).not.toMatch(/Muted/)
      expect(q).not.toMatch(/\$/)
    }
  })
})
