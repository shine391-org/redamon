/**
 * The graph cache is bounded.
 *
 * WHY: it used to be an unbounded Map keyed by project, so N projects with large
 * graphs each pinned a full payload copy for the process lifetime -- on top of
 * the live object and its JSON string. That multiplier fed the webapp OOM this
 * work came from.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { getCached, setCached, invalidateCache, cacheStats, clearCache } from './cache'

const payload = (n: number) => ({
  nodes: Array.from({ length: n }, (_, i) => ({ id: `n${i}` })),
  links: [] as { source: string; target: string }[],
})

beforeEach(() => { clearCache(); vi.useRealTimers() })
afterEach(() => { clearCache(); vi.unstubAllEnvs(); vi.useRealTimers() })

describe('bounds', () => {
  test('evicts the oldest entry past the entry limit', () => {
    for (let i = 0; i < 12; i++) setCached(`p${i}`, payload(1))
    expect(cacheStats().entries).toBeLessThanOrEqual(8)
    // p0 was first in and is long gone; the newest is still resident.
    expect(getCached('p0')).toBeNull()
    expect(getCached('p11')).not.toBeNull()
  })

  test('evicts on the ELEMENT budget even when the entry count is fine', () => {
    // Two entries, far under the 8-entry cap, but way over the element budget.
    setCached('big1', payload(150_000))
    setCached('big2', payload(150_000))
    expect(cacheStats().elements).toBeLessThanOrEqual(200_000)
    expect(cacheStats().entries).toBeLessThan(2)
  })

  test('a single oversized payload does not wedge the cache', () => {
    setCached('huge', payload(500_000))
    // It cannot fit, so it is evicted rather than pinned forever.
    expect(cacheStats().elements).toBeLessThanOrEqual(200_000)
    setCached('small', payload(1))
    expect(getCached('small')).not.toBeNull()
  })

  test('replacing a key does not double-count its elements', () => {
    setCached('p', payload(100))
    setCached('p', payload(100))
    setCached('p', payload(100))
    expect(cacheStats()).toEqual({ entries: 1, elements: 100 })
  })

  test('invalidate releases the element budget', () => {
    setCached('p', payload(1000))
    invalidateCache('p')
    expect(cacheStats()).toEqual({ entries: 0, elements: 0 })
  })

  test('LRU: reading an entry protects it from the next eviction', () => {
    for (let i = 0; i < 8; i++) setCached(`p${i}`, payload(1))
    getCached('p0')                       // touch the oldest
    setCached('p8', payload(1))           // forces one eviction
    expect(getCached('p0')).not.toBeNull() // survived because it was touched
    expect(getCached('p1')).toBeNull()     // the new oldest went instead
  })
})

describe('correctness', () => {
  test('a hit returns the same payload that was stored', () => {
    const p = payload(3)
    setCached('p', p)
    expect(getCached('p')!.data).toEqual(p)
  })

  test('truncation info round-trips, so a hit reports the same "N of M" as a miss', () => {
    const info = { truncated: true, totalNodes: 900, totalLinks: 5, returnedNodes: 10, returnedLinks: 2, limit: 10 }
    setCached('p', payload(10), info)
    expect(getCached('p')!.info).toEqual(info)
  })

  test('entries expire after the TTL and release their budget', () => {
    setCached('p', payload(5))
    vi.useFakeTimers()
    vi.advanceTimersByTime(11_000)
    expect(getCached('p')).toBeNull()
    expect(cacheStats()).toEqual({ entries: 0, elements: 0 })
  })

  test('a miss on an unknown key is null, not a throw', () => {
    expect(getCached('never-seen')).toBeNull()
  })

  test('invalidating an absent key is a no-op', () => {
    expect(() => invalidateCache('absent')).not.toThrow()
    expect(cacheStats()).toEqual({ entries: 0, elements: 0 })
  })
})

describe('the ETag', () => {
  const graph = (props: Record<string, unknown>) => ({
    nodes: [{ id: 'f1', type: 'Vulnerability', properties: { severity: 'high', ...props } }, { id: 'n2' }],
    links: [] as { source: string; target: string }[],
  })

  test('the same graph gives the same ETag', () => {
    expect(setCached('p', graph({ triage_tier_rule: 'proven' })))
      .toBe(setCached('p', graph({ triage_tier_rule: 'proven' })))
  })

  // A triage run or a verdict adds no node and no link, so a structural ETag
  // answered the browser's revalidation with a 304, and the node drawer kept
  // showing the disposition from before the run, even after a reload.
  test.each([
    ['triage_tier_rule', 'proven'],
    ['triage_state', 'gone'],
    ['triage_status', 'confirmed'],
    ['triage_source', 'human'],
    // A rescore can move the stored blocker (a gate a new run measured) and
    // leave the tier rule as it was.
    ['triage_disposition', 'reportable'],
    ['triage_blocker', 'shared edge'],
  ])('a change to %s changes it', (key, value) => {
    expect(setCached('p', graph({}))).not.toBe(setCached('p', graph({ [key]: value })))
  })

  test('two triage values cannot cancel out by swapping fields', () => {
    expect(setCached('p', graph({ triage_status: 'confirmed', triage_source: 'human' })))
      .not.toBe(setCached('p', graph({ triage_status: 'human', triage_source: 'confirmed' })))
  })

  test('any other property change keeps it, as before', () => {
    expect(setCached('p', graph({ updated_at: '2026-10-01' })))
      .toBe(setCached('p', graph({ updated_at: '2026-10-02' })))
  })
})
