/** @vitest-environment node */
/**
 * triageLayers.ts mirrors the triage score formula of
 * agentic/cypherfix_triage/score_model.py (drift-map #17): the tier bands of
 * tierForScore, the tier labels and order, the factor keys and names. Both sides
 * answer the same table, triageScore.vectors.json; the Python side is checked by
 * agentic/tests/test_triage_score_vectors.py, so a change to the formula there
 * moves the table and fails here until this mirror follows.
 */
import { describe, test, expect } from 'vitest'
import {
  FACTOR_KEYS,
  FACTOR_NAMES,
  TIER_LABELS,
  TIER_ORDER,
  tierForScore,
} from './triageLayers'
import vectors from './triageScore.vectors.json'

/**
 * Cases where tierForScore cannot answer the tier the score was built from.
 * 25 x level + 25 x risk puts a tier's risk-1.0 score on the next tier's floor
 * (T2 at risk 1.0 scores 75, and so does T1 at risk 0.0), so no function of the
 * score alone can name both; tierForScore names the higher. The fallback only
 * runs for a row with no stored triage_tier (the server sends it for every row
 * scored by the model), so the collision is accepted, not drift.
 */
const KNOWN_DIFFERENCES: Record<string, string> = {
  'T2@1': 'a boundary score is also T1@0',
  'T3@1': 'a boundary score is also T2@0',
  'T4@1': 'a boundary score is also T3@0',
}

const caseKey = (c: { tier: string; risk: number }) => `${c.tier}@${c.risk}`

describe('triage score formula mirror (drift-map #17)', () => {
  test('tier labels', () => {
    expect(TIER_LABELS).toEqual(vectors.tierLabels)
  })

  test('tier order is the score model\'s tier levels, highest first', () => {
    const byLevel = Object.entries(vectors.tierLevels).sort((a, b) => b[1] - a[1]).map(([tier]) => tier)
    expect(TIER_ORDER).toEqual(byLevel)
  })

  test('factor keys and the words the explanation uses for them', () => {
    expect([...FACTOR_KEYS]).toEqual(vectors.factorKeys)
    expect(FACTOR_NAMES).toEqual(vectors.factorNames)
  })

  test('tierForScore reads back the tier each score was built from', () => {
    const wrong = vectors.scores
      .filter(c => !(caseKey(c) in KNOWN_DIFFERENCES))
      .filter(c => tierForScore(c.score) !== c.tier)
      .map(c => `${caseKey(c)} score ${c.score} -> ${tierForScore(c.score)}`)
    expect(wrong).toEqual([])
  })

  test('every known difference is still one', () => {
    const fixed = Object.keys(KNOWN_DIFFERENCES).filter(key => {
      const c = vectors.scores.find(v => caseKey(v) === key)
      return !c || tierForScore(c.score) === c.tier
    })
    expect(fixed).toEqual([])
  })
})
