/**
 * Recon coverage carried by the graph (scanCoverage.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const run = vi.fn()
const close = vi.fn()
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run, close }),
}))

import {
  currentScanRoots, gapInScope, parseCoverageGaps, parseSelectionBlock, readDegradedSourceCount,
  readSelectionCoverage, skippedHostInScope,
} from './scanCoverage'

const records = (gapsPerDomain: unknown[]) => ({
  records: gapsPerDomain.map(g => ({ get: (_k: string) => g })),
})

const selectionRecords = (rows: Array<{ selection?: unknown, plan?: unknown }>) => ({
  records: rows.map(r => ({ get: (k: string) => (k === 'plan' ? r.plan : r.selection) })),
})

describe('parseCoverageGaps', () => {
  test('parses a JSON string array of source objects', () => {
    expect(parseCoverageGaps('[{"source":"shodan"},{"source":"otx"}]'))
      .toEqual([{ source: 'shodan' }, { source: 'otx' }])
  })
  test('accepts an already-parsed array', () => {
    expect(parseCoverageGaps([{ source: 'a' }])).toEqual([{ source: 'a' }])
  })
  test('rejects malformed JSON', () => {
    expect(parseCoverageGaps('{not json')).toBeNull()
  })
  test('rejects a non-array', () => {
    expect(parseCoverageGaps('{"source":"x"}')).toBeNull()
  })
  test('rejects an entry without a string source', () => {
    expect(parseCoverageGaps([{ nope: 1 }])).toBeNull()
  })
  test('rejects a source over 64 chars', () => {
    expect(parseCoverageGaps([{ source: 'x'.repeat(65) }])).toBeNull()
  })
})

describe('readDegradedSourceCount', () => {
  beforeEach(() => {
    run.mockReset()
    close.mockReset()
  })

  test('returns null when no Domain carries a coverage record', async () => {
    run.mockResolvedValue({ records: [] })
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('counts distinct sources across every covered Domain', async () => {
    run.mockResolvedValue(records([
      '[{"source":"shodan"},{"source":"nuclei"}]',
      '[{"source":"shodan"},{"source":"otx"}]',
    ]))
    expect(await readDegradedSourceCount('p1')).toBe(3) // shodan, nuclei, otx
  })

  test('returns 0 for a clean recorded run (empty gaps)', async () => {
    run.mockResolvedValue(records(['[]']))
    expect(await readDegradedSourceCount('p1')).toBe(0)
  })

  test('fails closed to null on an unparseable record', async () => {
    run.mockResolvedValue(records(['[{"source":"ok"}]', '{bad']))
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('returns null and never throws on a query error', async () => {
    run.mockRejectedValue(new Error('neo4j down'))
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('always closes the session', async () => {
    run.mockResolvedValue({ records: [] })
    await readDegradedSourceCount('p1')
    expect(close).toHaveBeenCalledOnce()
  })
})

describe('readSelectionCoverage', () => {
  beforeEach(() => {
    run.mockReset()
    close.mockReset()
  })

  test('returns null when no Domain carries a coverage record', async () => {
    run.mockResolvedValue({ records: [] })
    expect(await readSelectionCoverage('p1')).toBeNull()
  })

  test('returns null when neither property is present', async () => {
    run.mockResolvedValue(selectionRecords([{}]))
    expect(await readSelectionCoverage('p1')).toBeNull()
  })

  test('reads the per-run record', async () => {
    run.mockResolvedValue(selectionRecords([{
      selection: JSON.stringify(
        { recorded: true, selection_unknown: false, plan_ids: ['P1'], exhaustive: false }),
    }]))
    expect(await readSelectionCoverage('p1')).toEqual(
      { recorded: true, selection_unknown: false, plan_ids: ['P1'], exhaustive: false })
  })

  test('merges the per-run record with the per-group plan write', async () => {
    run.mockResolvedValue(selectionRecords([{
      selection: JSON.stringify(
        { recorded: true, selection_unknown: false, plan_ids: ['P1'], exhaustive: false }),
      plan: JSON.stringify(
        { recorded: true, selection_unknown: false, plan_ids: ['P2'], exhaustive: true }),
    }]))
    expect(await readSelectionCoverage('p1')).toEqual(
      { recorded: true, selection_unknown: false, plan_ids: ['P1', 'P2'], exhaustive: false })
  })

  test('an unknown cut on either side makes the whole run unknown', async () => {
    run.mockResolvedValue(selectionRecords([{
      selection: JSON.stringify(
        { recorded: false, selection_unknown: true, plan_ids: [], exhaustive: false }),
    }]))
    expect(await readSelectionCoverage('p1')).toEqual(
      { recorded: false, selection_unknown: true, plan_ids: [], exhaustive: false })
  })

  test('fails closed to null on an unparseable block', async () => {
    run.mockResolvedValue(selectionRecords([{ selection: '{bad' }]))
    expect(await readSelectionCoverage('p1')).toBeNull()
  })

  test('returns null and never throws on a query error', async () => {
    run.mockRejectedValue(new Error('neo4j down'))
    expect(await readSelectionCoverage('p1')).toBeNull()
  })

  test('always closes the session', async () => {
    run.mockResolvedValue({ records: [] })
    await readSelectionCoverage('p1')
    expect(close).toHaveBeenCalledOnce()
  })
})

describe('parseSelectionBlock', () => {
  test('parses a JSON string block', () => {
    expect(parseSelectionBlock(
      '{"recorded":true,"selection_unknown":false,"plan_ids":["P1"],"exhaustive":false}'))
      .toEqual({ recorded: true, selection_unknown: false, plan_ids: ['P1'], exhaustive: false })
  })
  test('accepts an already-parsed object', () => {
    expect(parseSelectionBlock({ recorded: true, plan_ids: ['P1'] }))
      .toEqual({ recorded: true, selection_unknown: false, plan_ids: ['P1'], exhaustive: false })
  })
  test('dedupes plan ids', () => {
    const block = parseSelectionBlock({ plan_ids: ['P1', 'P1', 'P2'] })
    expect(block).not.toBeNull()
    expect(block!.plan_ids).toEqual(['P1', 'P2'])
  })
  test('rejects malformed JSON', () => {
    expect(parseSelectionBlock('{not json')).toBeNull()
  })
  test('rejects a non-object', () => {
    expect(parseSelectionBlock([])).toBeNull()
  })
  test('rejects a non-array plan_ids', () => {
    expect(parseSelectionBlock({ plan_ids: 'P1' })).toBeNull()
  })
  test('rejects a non-string plan id', () => {
    expect(parseSelectionBlock({ plan_ids: [1] })).toBeNull()
  })
})

describe('coverage of a removed scan root (§4.11.7)', () => {
  test('the current scan roots of a project', () => {
    expect([...currentScanRoots({ targetDomain: 'Api.Example.com' })!]).toEqual(['api.example.com'])
    expect(currentScanRoots({ ipMode: true, targetIps: ['10.0.0.1'] } as never)).toBeNull()
  })

  test("a gap is kept only for a current root; an untagged gap is kept", () => {
    const roots = new Set(['api.example.com'])
    expect(gapInScope({ source: 's', root: 'API.example.com' }, roots)).toBe(true)
    expect(gapInScope({ source: 's', root: 'old.example.com' }, roots)).toBe(false)
    expect(gapInScope({ source: 's' }, roots)).toBe(true)
    expect(gapInScope({ source: 's', root: 'old.example.com' }, null)).toBe(true)
  })

  test('a skipped host belongs to the longest root it sits under', () => {
    const roots = new Set(['api.example.com'])
    expect(skippedHostInScope('v1.api.example.com:443', roots)).toBe(true)
    expect(skippedHostInScope('api.example.com:80', roots)).toBe(true)
    expect(skippedHostInScope('www.example.com:443', roots)).toBe(false)
    expect(skippedHostInScope('www.example.com:443', null)).toBe(true)
  })

  test('the run-close count can drop a removed root', async () => {
    run.mockResolvedValueOnce(records([JSON.stringify([
      { source: 'a', root: 'api.example.com' }, { source: 'b', root: 'gone.example.com' }])]))
    expect(await readDegradedSourceCount('p1', new Set(['api.example.com']))).toBe(1)
  })
})
