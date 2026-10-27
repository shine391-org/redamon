/**
 * How a secret's validation status reads, and where it sorts (plan 05.7).
 * "Rejected" is the provider's verdict; "could not check" is no verdict and
 * must never read as dead.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { validationLabel, validationRank, validationTone } from './validationStatus'

describe('validationLabel', () => {
  test.each([
    ['validated', 'LIVE'],
    ['rejected', 'rejected'],
    ['unknown', 'could not check'],
    ['format_invalid', 'malformed'],
    ['format_validated', 'format ok'],
    ['incomplete', 'incomplete'],
    ['unvalidated', 'no validator'],
    ['skipped', 'not checked'],
    ['verify_error', 'verify error'],
    ['unverified', 'not checked'],
    // Nodes written before the explicit states keep their own word.
    ['invalid', 'invalid'],
    ['error', 'error'],
  ])('%s reads "%s"', (status, label) => {
    expect(validationLabel(status)).toBe(label)
  })

  test('a TruffleHog unvalidated was a credential checked and dead', () => {
    expect(validationLabel('unvalidated', 'MultiscannerFinding')).toBe('rejected')
  })

  test('nothing stored reads as a dash, an unknown word as itself', () => {
    expect(validationLabel(null)).toBe('-')
    expect(validationLabel('')).toBe('-')
    expect(validationLabel('some_new_state')).toBe('some new state')
  })
})

describe('validationRank', () => {
  test('live first, no verdict before a dead one, a dead one before nobody looked', () => {
    const order = ['validated', 'format_validated', 'unknown', 'rejected', 'unverified', 'skipped', 'format_invalid']
    const ranks = order.map(s => validationRank(s))
    expect([...ranks].sort((a, b) => a - b)).toEqual(ranks)
    expect(validationRank('unknown')).toBe(validationRank('verify_error'))
    expect(validationRank('rejected')).toBeLessThan(validationRank('unverified'))
  })

  test('the legacy word keeps its old place', () => {
    expect(validationRank('invalid')).toBeGreaterThan(validationRank('skipped'))
  })

  test('a missing status sorts as no validator', () => {
    expect(validationRank(null)).toBe(validationRank('unvalidated'))
  })
})

describe('validationTone', () => {
  test('only a live credential is alarming, and could-not-check is never muted like dead', () => {
    expect(validationTone('validated')).toBe('live')
    expect(validationTone('unknown')).toBe('warn')
    expect(validationTone('verify_error')).toBe('warn')
    expect(validationTone('rejected')).toBe('dead')
    expect(validationTone('invalid')).toBe('dead')
    expect(validationTone('skipped')).toBe('none')
  })
})
