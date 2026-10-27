/**
 * Disposition: one answer per finding to "can this go in a report?" (plan 10.1).
 *
 * The vectors are shared with disposition.integration.test.ts, which runs the
 * Cypher half over the same rows on a real Neo4j: the report and Insights group
 * in Cypher while the board and MCP decide in TypeScript, and a drift would
 * print one count and list another.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import vectors from './disposition.vectors.json'
import gateVectors from './disposition.gates.vectors.json'
import {
  BLOCKER_AI_FALSE_POSITIVE,
  BLOCKER_NOT_TRIAGED,
  DISPOSITIONS,
  DISPOSITION_LABELS,
  GATES,
  GATE_BLOCKERS,
  INFO_SEVERITIES,
  TIER_RULE_NO_IMPACT,
  TIER_RULE_PROVEN,
  TOP_BLOCKERS,
  blockerCypher,
  disposition,
  dispositionCypher,
  dispositionText,
  inSeverityBreakdown,
  queryDispositionSummary,
  readDisposition,
  readSideDisposition,
  topBlockers,
} from './disposition'
import { PUBLIC_CLIENT_KEY_TYPES } from '@/lib/secrets/publicClientKeys'
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'
import { agentCandidateConfirmedOrNA, notMuted } from '@/lib/graphMute'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

interface Vector {
  why: string
  props: Record<string, unknown>
  disposition: string
  blocker: string | null
}

describe('disposition, over the shared vectors', () => {
  test.each((vectors as Vector[]).map((v) => [v.why, v] as const))('%s', (_why, v) => {
    expect(disposition(v.props)).toEqual({ disposition: v.disposition, blocker: v.blocker })
  })

  test('the vectors reach every disposition and both fixed blockers', () => {
    const seen = new Set((vectors as Vector[]).map((v) => v.disposition))
    expect([...seen].sort()).toEqual([...DISPOSITIONS].sort())
    const blockers = new Set((vectors as Vector[]).map((v) => v.blocker))
    expect(blockers.has(BLOCKER_NOT_TRIAGED)).toBe(true)
    expect(blockers.has(BLOCKER_AI_FALSE_POSITIVE)).toBe(true)
  })
})

describe('disposition rules that matter for safety', () => {
  test('SECURITY: an AI false positive is never excluded and never reportable', () => {
    for (const p of [
      { triage_state: 'false_positive', triage_decided_by: 'review' },
      { triage_status: 'likely_noise', triage_source: 'ai' },
    ]) {
      expect(disposition(p).disposition).toBe('candidate')
      expect(disposition(p).blocker).toBe(BLOCKER_AI_FALSE_POSITIVE)
    }
  })

  test('nothing is reportable by default: missing or unknown values are candidates', () => {
    for (const p of [{}, { triage_status: 'weird' }, { triage_tier_rule: 'made up' }, { triage_source: 'human' }]) {
      expect(disposition(p).disposition).not.toBe('reportable')
    }
  })

  test('only a person\'s confirmed, never an unattributed one, makes a finding reportable', () => {
    expect(disposition({ triage_status: 'confirmed', triage_source: 'human' }).disposition).toBe('reportable')
    expect(disposition({ triage_status: 'confirmed', triage_source: 'ai' }).disposition).toBe('candidate')
    expect(disposition({ triage_status: 'confirmed' }).disposition).toBe('candidate')
  })

  test('a blocker is named for candidates only', () => {
    for (const v of vectors as Vector[]) {
      expect(v.blocker === null).toBe(v.disposition !== 'candidate')
    }
  })
})

describe('the answer a run stored (plan 10.5)', () => {
  const stored = (vectors as Vector[]).filter((v) => 'triage_disposition' in v.props)

  test('the shared vectors carry stored answers, whole and broken', () => {
    expect(stored.length).toBeGreaterThanOrEqual(8)
  })

  test('the read-side rules ignore it: they are what a stored answer is checked against', () => {
    const p = { triage_tier_rule: 'credible, with impact worth planning for',
      triage_disposition: 'candidate', triage_blocker: 'shared edge' }
    expect(disposition(p)).toEqual({ disposition: 'candidate', blocker: 'shared edge' })
    expect(readSideDisposition(p)).toEqual({ disposition: 'candidate', blocker: 'credible, with impact worth planning for' })
  })

  test('SECURITY: a stored answer never excludes, and never outlives a live exclusion', () => {
    expect(disposition({ triage_disposition: 'excluded' }).disposition).toBe('candidate')
    expect(disposition({ triage_state: 'gone', triage_disposition: 'reportable' }).disposition).toBe('excluded')
    expect(disposition({ triage_status: 'likely_noise', triage_source: 'human',
      triage_disposition: 'reportable' }).disposition).toBe('excluded')
  })
})

describe('the gates a run measured, over the shared gate vectors', () => {
  const SCORE_MODEL = join(__dirname, '../../../../agentic/cypherfix_triage/score_model.py')

  test.each((gateVectors as Vector[]).map((v) => [v.why, v] as const))('%s', (_why, v) => {
    const want = { disposition: v.disposition, blocker: v.blocker }
    expect(readSideDisposition(v.props)).toEqual(want)
    expect(disposition(v.props)).toEqual(want)
  })

  test('every gate blocker is reached, failing and unknown', () => {
    const blockers = new Set((gateVectors as Vector[]).map((v) => v.blocker))
    for (const g of GATES) {
      expect(blockers.has(GATE_BLOCKERS[g].failed)).toBe(true)
    }
    expect(blockers.has(GATE_BLOCKERS.reachable_now.unknown)).toBe(true)
    expect(blockers.has(GATE_BLOCKERS.impactful.unknown)).toBe(true)
  })

  test('the gates, their order and their words are score_model\'s', () => {
    const src = readFileSync(SCORE_MODEL, 'utf8')
    expect(src).toContain(`GATES = (${GATES.map((g) => `"${g}"`).join(', ')})`)
    for (const g of GATES) {
      expect(src).toContain(`"${g}": ("${GATE_BLOCKERS[g].failed}", "${GATE_BLOCKERS[g].unknown}")`)
    }
  })

  test('tier inputs given as an object are read like the stored JSON string', () => {
    const inputs = { proven: false, gates: { reachable_now: true, attributed: false } }
    const rule = 'credible, with impact worth planning for'
    expect(readSideDisposition({ triage_tier_rule: rule, triage_tier_inputs: inputs }).blocker)
      .toBe(GATE_BLOCKERS.attributed.failed)
    expect(readSideDisposition({ triage_tier_rule: rule, triage_tier_inputs: JSON.stringify(inputs) }).blocker)
      .toBe(GATE_BLOCKERS.attributed.failed)
  })
})

describe('readDisposition: props a reader could not read', () => {
  test('no props means no answer, never a default', () => {
    for (const bad of [null, undefined, 'x', 3, ['triage_state']]) {
      expect(readDisposition(bad)).toBeNull()
    }
  })

  test('a props object is read as disposition reads it', () => {
    expect(readDisposition({ triage_tier_rule: 'proven' })).toEqual({ disposition: 'reportable', blocker: null })
  })
})

describe('the words every surface shares', () => {
  test('one label per disposition', () => {
    expect(DISPOSITION_LABELS).toEqual({
      reportable: 'Reportable', candidate: 'Candidate', info: 'Info', excluded: 'Excluded',
    })
  })

  test('a candidate names its blocker, and an untriaged one says so plainly', () => {
    expect(dispositionText({ disposition: 'candidate', blocker: 'credible, with impact worth planning for' }))
      .toBe('Candidate, blocked by credible, with impact worth planning for')
    expect(dispositionText({ disposition: 'candidate', blocker: BLOCKER_NOT_TRIAGED }))
      .toBe('Candidate, not triaged yet')
    expect(dispositionText({ disposition: 'reportable', blocker: null })).toBe('Reportable')
    expect(dispositionText({ disposition: 'info', blocker: null })).toBe('Info')
  })
})

describe('the Cypher half', () => {
  const SCORE_MODEL = join(__dirname, '../../../../agentic/cypherfix_triage/score_model.py')

  test('the tier rules it reads are the strings score_model.tier_rule returns', () => {
    const src = readFileSync(SCORE_MODEL, 'utf8')
    expect(src).toContain(`return "T1", "${TIER_RULE_PROVEN}"`)
    expect(src).toContain(`return "T4", "${TIER_RULE_NO_IMPACT}"`)
  })

  test('the info severities are the board\'s own (triage_mixin severity rank)', () => {
    const mixin = readFileSync(join(__dirname, '../../../../graph_db/mixins/recon/triage_mixin.py'), 'utf8')
    expect(mixin).toContain(`IN [${INFO_SEVERITIES.map((s) => `'${s}'`).join(', ')}]`)
  })

  test('it checks excluded, then reportable, then info, and leaves candidate last', () => {
    const q = dispositionCypher('n')
    const order = ['excluded', 'reportable', 'info', 'candidate'].map((d) => q.indexOf(`'${d}'`))
    expect(order.every((i) => i >= 0)).toBe(true)
    expect([...order].sort((a, b) => a - b)).toEqual(order)
  })

  test('it carries every constant the TypeScript half reads', () => {
    const q = dispositionCypher('n') + blockerCypher('n')
    for (const s of [TIER_RULE_PROVEN, TIER_RULE_NO_IMPACT, BLOCKER_NOT_TRIAGED, BLOCKER_AI_FALSE_POSITIVE,
      ...INFO_SEVERITIES, PUBLIC_CLIENT_KEY_TYPES[0]]) {
      expect(q).toContain(`'${s}'`)
    }
    expect(q).toContain("coalesce(n.triage_source, '') = 'human'")
  })

  test('it binds only the variable it is given, no parameter, and never names Muted', () => {
    for (const q of [dispositionCypher('jf'), blockerCypher('jf')]) {
      expect(q).not.toMatch(/\bn\./)
      expect(q).toMatch(/jf\.triage_tier_rule/)
      expect(q).not.toMatch(/\$/)
      expect(q).not.toMatch(/Muted/)
    }
  })

  test('a variable that is not a Cypher identifier is refused', () => {
    expect(() => dispositionCypher('n) DETACH DELETE (m')).toThrow(/identifier/)
    expect(() => blockerCypher('1n')).toThrow(/identifier/)
  })

  test('the blocker is null outside candidates', () => {
    expect(blockerCypher('n')).toMatch(/^CASE WHEN .* = 'candidate' THEN .* END$/s)
  })

  test('a whole stored answer is read right after the live exclusion, with no call that can fail', () => {
    const q = dispositionCypher('n')
    const stored = "WHEN (n.triage_disposition IN ['reportable', 'info'] OR (n.triage_disposition = 'candidate' AND n.triage_blocker > '')) THEN n.triage_disposition"
    expect(q).toContain(stored)
    expect(q.indexOf(stored)).toBeLessThan(q.indexOf(`= '${TIER_RULE_PROVEN}'`))
    expect(q.indexOf("THEN 'excluded'")).toBeLessThan(q.indexOf(stored))
    // trim() on a property some writer stored as a number fails the whole query.
    expect(q + blockerCypher('n')).not.toMatch(/trim\(n\.triage_blocker/)
  })

  test('the severity breakdowns keep reportable and candidate findings only', () => {
    expect(inSeverityBreakdown('v')).toBe(`${dispositionCypher('v')} IN ['reportable', 'candidate']`)
  })
})

describe('queryDispositionSummary: the report and Insights headline', () => {
  const row = (disposition: string, blocker: string | null, total: unknown) => ({
    get: (k: string) => ({ disposition, blocker, total })[k],
  })
  const sessionReturning = (records: unknown[]) => {
    const run = vi.fn().mockResolvedValue({ records })
    return { run }
  }

  test('counts each disposition and groups candidates by blocker, largest first', async () => {
    const s = sessionReturning([
      row('reportable', null, 2),
      row('candidate', BLOCKER_NOT_TRIAGED, { low: 5, high: 0 }),
      row('candidate', 'credible, with impact worth planning for', 9),
      row('candidate', BLOCKER_AI_FALSE_POSITIVE, 1),
      row('info', null, 7),
      row('excluded', null, 3),
    ])
    expect(await queryDispositionSummary(s, 'p1')).toEqual({
      reportable: 2, candidate: 15, info: 7, excluded: 3,
      blockers: [
        { blocker: 'credible, with impact worth planning for', count: 9 },
        { blocker: BLOCKER_NOT_TRIAGED, count: 5 },
        { blocker: BLOCKER_AI_FALSE_POSITIVE, count: 1 },
      ],
    })
  })

  test('equal blocker counts are ordered by name, so two renders agree', async () => {
    const s = sessionReturning([row('candidate', 'b rule', 2), row('candidate', 'a rule', 2)])
    expect((await queryDispositionSummary(s, 'p1'))!.blockers.map((b) => b.blocker)).toEqual(['a rule', 'b rule'])
  })

  test('the query covers every finding label, unmuted, without unconfirmed serialized candidates', async () => {
    const s = sessionReturning([])
    await queryDispositionSummary(s, 'p1')
    const [query, params] = s.run.mock.calls[0]
    for (const label of MUTEABLE_FINDING_LABELS) expect(query).toContain(label)
    expect(query).toContain(notMuted('n'))
    expect(query).toContain(agentCandidateConfirmedOrNA('n'))
    expect(query).toContain(dispositionCypher('n'))
    expect(query).toContain(blockerCypher('n'))
    expect(params).toEqual({ pid: 'p1' })
  })

  test('an empty project is an honest zero', async () => {
    expect(await queryDispositionSummary(sessionReturning([]), 'p1')).toEqual({
      reportable: 0, candidate: 0, info: 0, excluded: 0, blockers: [],
    })
  })

  test('a failed read is null, never zeros: a reader must not print "0 reportable"', async () => {
    const s = { run: vi.fn().mockRejectedValue(new Error('neo4j down')) }
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(await queryDispositionSummary(s, 'p1')).toBeNull()
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  test('an unknown disposition from a drifted query is not counted anywhere', async () => {
    const s = sessionReturning([row('weird', null, 4), row('reportable', null, 1)])
    const got = (await queryDispositionSummary(s, 'p1'))!
    expect(got.reportable + got.candidate + got.info + got.excluded).toBe(1)
  })
})

describe('topBlockers', () => {
  const blockers = [9, 8, 7, 6, 5, 4, 3].map((count, i) => ({ blocker: `rule ${i}`, count }))

  test('keeps the first TOP_BLOCKERS and sums the rest', () => {
    const { top, otherCount, otherBlockers } = topBlockers(blockers)
    expect(TOP_BLOCKERS).toBe(5)
    expect(top.map((b) => b.count)).toEqual([9, 8, 7, 6, 5])
    expect(otherCount).toBe(7)
    expect(otherBlockers).toBe(2)
  })

  test('nothing left over says so', () => {
    expect(topBlockers(blockers.slice(0, 2))).toEqual({ top: blockers.slice(0, 2), otherCount: 0, otherBlockers: 0 })
  })
})
