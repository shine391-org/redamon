/**
 * The IP attribution tag as people read it (plan 11.4): the graph drawer's
 * Ownership line and the report's Ownership column.
 */
import { describe, test, expect } from 'vitest'
import { OWNERSHIP_PROPERTIES, ownershipLabel, ownershipLine, readOwnership } from './ipOwnership'

const edge = {
  ownership: 'shared_edge',
  cdn_name: 'cloudflare',
  ownership_reasons: ['default certificate covers no target domain', 'in a published CDN edge range'],
}

describe('readOwnership', () => {
  test('reads the three tags and nothing else', () => {
    expect(readOwnership({ ownership: 'shared_edge' })).toBe('shared_edge')
    expect(readOwnership({ ownership: 'dedicated' })).toBe('dedicated')
    expect(readOwnership({ ownership: 'unknown' })).toBe('unknown')
    expect(readOwnership({ ownership: 'not ours' })).toBeNull()
    expect(readOwnership({})).toBeNull()
    expect(readOwnership(undefined)).toBeNull()
  })
})

describe('ownershipLine (the drawer)', () => {
  test('a shared edge names its CDN and every reason', () => {
    expect(ownershipLine(edge)).toBe(
      'Shared edge (Cloudflare): default certificate covers no target domain; in a published CDN edge range')
  })

  test('a dedicated IP gives its reasons and no CDN', () => {
    expect(ownershipLine({ ownership: 'dedicated', cdn_name: 'aws',
      ownership_reasons: ['default certificate covers example.com'] }))
      .toBe('Dedicated: default certificate covers example.com')
  })

  test('a tag with no reasons is just the label', () => {
    expect(ownershipLine({ ownership: 'unknown' })).toBe('Unknown')
  })

  test('an IP no run attributed yet says so', () => {
    expect(ownershipLine({})).toBe('not checked yet')
  })
})

describe('ownershipLabel (the report)', () => {
  test('labels a tag, and leaves an untagged IP empty, never "unknown"', () => {
    expect(ownershipLabel('shared_edge')).toBe('Shared edge')
    expect(ownershipLabel('dedicated')).toBe('Dedicated')
    expect(ownershipLabel('unknown')).toBe('Unknown')
    expect(ownershipLabel(null)).toBe('')
    expect(ownershipLabel('junk')).toBe('')
  })
})

test('the drawer hides the raw keys the line replaces', () => {
  expect([...OWNERSHIP_PROPERTIES]).toEqual(['ownership', 'ownership_reasons'])
})
