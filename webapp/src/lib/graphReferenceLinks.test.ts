/**
 * Links to the global reference catalogue survive export, snapshot and restore
 * (plan 09.5).
 *
 * CVE, MitreData and Capec nodes are shared by every tenant and carry no
 * project_id, so exports and snapshots leave the NODES out: a project file must
 * never create or overwrite shared reference data. That used to drop every edge
 * to them too. A link record keeps the edge as the project node's export id plus
 * the reference node's natural key, and a restore MATCHes the node by that key.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import type { Session } from 'neo4j-driver'
import {
  REFERENCE_KEY_PROPERTY,
  referenceLinkOf,
  restoreReferenceLinks,
  splitCapturedRelationships,
  type ReferenceLink,
} from './graphReferenceLinks'
import { GLOBAL_REFERENCE_LABELS } from './graphRestore'

const rec = (fields: Record<string, unknown>) => ({ get: (k: string) => fields[k] })
const rel = (startId: string, endId: string, relType: string, extra: Record<string, unknown> = {}) =>
  rec({ startId, endId, relType, relProps: {}, startRefLabel: null, startRefKey: null,
        endRefLabel: null, endRefKey: null, ...extra })

const exportIds = new Map([['e1', 'x1'], ['e2', 'x2']])
const serialize = (p: Record<string, unknown>) => p

describe('splitCapturedRelationships', () => {
  test('an edge between two project nodes stays a relationship', () => {
    const { relationships, referenceLinks } = splitCapturedRelationships([rel('e1', 'e2', 'HAS_PORT')], exportIds, serialize)
    expect(relationships).toEqual([{ startExportId: 'x1', endExportId: 'x2', type: 'HAS_PORT', properties: {} }])
    expect(referenceLinks).toEqual([])
  })

  test('an edge to a CVE becomes a link record naming the CVE by id, with none of its properties', () => {
    const { relationships, referenceLinks } = splitCapturedRelationships([
      rel('e1', 'cveNode', 'INCLUDES_CVE', { endRefLabel: 'CVE', endRefKey: 'CVE-2021-44228', relProps: { w: 1 } }),
    ], exportIds, serialize)
    expect(relationships).toEqual([])
    expect(referenceLinks).toEqual([{
      startExportId: 'x1', endExportId: null, type: 'INCLUDES_CVE',
      refLabel: 'CVE', refKey: 'CVE-2021-44228', properties: { w: 1 },
    }])
  })

  test('a link that starts at the reference node keeps its direction', () => {
    const { referenceLinks } = splitCapturedRelationships([
      rel('capNode', 'e2', 'APPLIES_TO', { startRefLabel: 'Capec', startRefKey: 'CAPEC-66' }),
    ], exportIds, serialize)
    expect(referenceLinks).toEqual([{
      startExportId: null, endExportId: 'x2', type: 'APPLIES_TO',
      refLabel: 'Capec', refKey: 'CAPEC-66', properties: {},
    }])
  })

  test('an edge to a node that is neither captured nor a reference is dropped', () => {
    const { relationships, referenceLinks } = splitCapturedRelationships([
      rel('e1', 'chainNode', 'RUNS_SERVICE'),
      rel('e1', 'cveNode', 'INCLUDES_CVE', { endRefLabel: 'CVE', endRefKey: 'not-a-cve' }),
    ], exportIds, serialize)
    expect(relationships).toEqual([])
    expect(referenceLinks).toEqual([])
  })
})

describe('referenceLinkOf (input validation)', () => {
  const ok: ReferenceLink = {
    startExportId: 'x1', endExportId: null, type: 'INCLUDES_CVE',
    refLabel: 'CVE', refKey: 'CVE-2021-44228', properties: {},
  }

  test('a well-formed link passes', () => {
    expect(referenceLinkOf(ok)).toEqual(ok)
    expect(referenceLinkOf({ ...ok, refLabel: 'MitreData', refKey: 'CVE-2021-44228-CWE-502' })).not.toBeNull()
    expect(referenceLinkOf({ ...ok, refLabel: 'Capec', refKey: 'CAPEC-66' })).not.toBeNull()
  })

  test.each([
    ['an injection-shaped key', { refKey: "CVE-1' OR 1=1" }],
    ['a key of the wrong shape for its label', { refLabel: 'Capec', refKey: 'CVE-2021-44228' }],
    ['a label outside the catalogue', { refLabel: 'Subdomain' }],
    ['a relationship type that is not an identifier', { type: 'X]->(n) DETACH DELETE n//' }],
    ['no project end', { startExportId: null }],
    ['two project ends', { endExportId: 'x2' }],
    ['properties that are not an object', { properties: 'x' }],
  ])('%s is rejected', (_name, over) => {
    expect(referenceLinkOf({ ...ok, ...over })).toBeNull()
  })

  test('garbage is rejected, not thrown on', () => {
    for (const bad of [null, 1, 'x', [], {}]) expect(referenceLinkOf(bad)).toBeNull()
  })
})

describe('restoreReferenceLinks', () => {
  function fakeSession(created: (params: Record<string, unknown>) => number) {
    const calls: { cypher: string; params: Record<string, unknown> }[] = []
    const run = vi.fn(async (cypher: string, params: Record<string, unknown> = {}) => {
      calls.push({ cypher, params })
      return { records: [rec({ created: created(params) })] }
    })
    return { session: { run } as unknown as Session, calls }
  }
  const link = (over: Partial<ReferenceLink> = {}): ReferenceLink => ({
    startExportId: 'x1', endExportId: null, type: 'INCLUDES_CVE',
    refLabel: 'CVE', refKey: 'CVE-2021-44228', properties: {}, ...over,
  })

  test('it MATCHes the reference node by its natural key and never creates or changes one', async () => {
    const { session, calls } = fakeSession(() => 1)
    const res = await restoreReferenceLinks(session, [link()], 'p1')
    expect(res).toEqual({ restored: 1, skipped: 0 })
    const [{ cypher, params }] = calls
    expect(cypher).toContain('MATCH (ref:CVE {id: link.refKey})')
    expect(cypher).toContain('MATCH (local {_exportId: link.localExportId, project_id: $pid})')
    expect(cypher).not.toMatch(/MERGE|SET |apoc\.merge/)
    expect(params.pid).toBe('p1')
    expect(params.links).toEqual([{ localExportId: 'x1', refKey: 'CVE-2021-44228', type: 'INCLUDES_CVE', properties: {} }])
  })

  test('the label and key property come from the fixed catalogue, never from the file', async () => {
    const { session, calls } = fakeSession(p => (p.links as unknown[]).length)
    await restoreReferenceLinks(session, [
      link({ refLabel: 'MitreData', refKey: 'CVE-2021-44228-CWE-502' }),
      link({ refLabel: 'Capec', refKey: 'CAPEC-66' }),
      link({ startExportId: null, endExportId: 'x2' }),
    ], 'p1')
    const cyphers = calls.map(c => c.cypher)
    expect(cyphers.some(c => c.includes('(ref:MitreData {id: link.refKey})'))).toBe(true)
    expect(cyphers.some(c => c.includes('(ref:Capec {capec_id: link.refKey})'))).toBe(true)
    // An incoming link is created from the reference node to the project node.
    const incoming = calls.find(c => (c.params.links as { localExportId: string }[])[0].localExportId === 'x2')!
    expect(incoming.cypher).toContain('apoc.create.relationship(ref, link.type, link.properties, local)')
  })

  test('a link whose reference node is missing, or that fails validation, is skipped and counted', async () => {
    const { session, calls } = fakeSession(() => 0)
    const res = await restoreReferenceLinks(session, [link(), link({ refKey: "CVE-1' OR 1=1" }), 'garbage'], 'p1')
    expect(res).toEqual({ restored: 0, skipped: 3 })
    expect(calls).toHaveLength(1)
  })

  test('no links, no query', async () => {
    const { session, calls } = fakeSession(() => 0)
    expect(await restoreReferenceLinks(session, [], 'p1')).toEqual({ restored: 0, skipped: 0 })
    expect(calls).toEqual([])
  })
})

test('the catalogue this module knows is the global reference catalogue', () => {
  expect(Object.keys(REFERENCE_KEY_PROPERTY).sort()).toEqual([...GLOBAL_REFERENCE_LABELS].sort())
})
