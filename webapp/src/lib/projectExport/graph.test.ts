/**
 * The project export's graph section (plan 09.5): every project node, every
 * project-internal relationship, and a link record for each edge to a global
 * CVE / MitreData / Capec node, never the node itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import type { Session } from 'neo4j-driver'
import { exportProjectGraph } from './graph'

const rec = (fields: Record<string, unknown>) => ({ get: (k: string) => fields[k] })

function fakeSession() {
  const calls: { cypher: string; params: Record<string, unknown> }[] = []
  const run = vi.fn(async (cypher: string, params: Record<string, unknown> = {}) => {
    calls.push({ cypher, params })
    if (cypher.includes('properties(n) as props')) {
      return { records: [
        rec({ labels: ['Vulnerability'], props: { id: 'v1', project_id: 'p1' }, eid: 'e1' }),
        rec({ labels: ['Technology'], props: { name: 'nginx', project_id: 'p1' }, eid: 'e2' }),
      ] }
    }
    return { records: [
      rec({ startId: 'e2', endId: 'e1', relType: 'HAS_VULNERABILITY', relProps: {} }),
      rec({ startId: 'e1', endId: 'eCVE', relType: 'INCLUDES_CVE', relProps: {},
            endRefLabel: 'CVE', endRefKey: 'CVE-2021-23017' }),
      rec({ startId: 'e2', endId: 'eCVE', relType: 'HAS_KNOWN_CVE', relProps: { cvss: 7.7 },
            endRefLabel: 'CVE', endRefKey: 'CVE-2021-23017' }),
    ] }
  })
  return { session: { run } as unknown as Session, calls }
}

describe('exportProjectGraph', () => {
  test('carries the links to a CVE as records, with no reference-node property', async () => {
    const { session } = fakeSession()
    const out = await exportProjectGraph(session, 'p1')
    expect(out.nodes.map(n => n.labels[0])).toEqual(['Vulnerability', 'Technology'])
    expect(out.relationships.map(r => r.type)).toEqual(['HAS_VULNERABILITY'])
    expect(out.referenceLinks.map(l => [l.type, l.refLabel, l.refKey, l.endExportId])).toEqual([
      ['INCLUDES_CVE', 'CVE', 'CVE-2021-23017', null],
      ['HAS_KNOWN_CVE', 'CVE', 'CVE-2021-23017', null],
    ])
    const vuln = out.nodes.find(n => n.labels[0] === 'Vulnerability')!
    expect(out.referenceLinks[0].startExportId).toBe(vuln._exportId)
    expect(Object.keys(out.referenceLinks[1])).toEqual(
      ['startExportId', 'endExportId', 'type', 'refLabel', 'refKey', 'properties'])
  })

  test('a catalogue node is never exported, even one an old release stamped with a project id', async () => {
    const { session, calls } = fakeSession()
    await exportProjectGraph(session, 'p1')
    const nodeQuery = calls.find(c => c.cypher.includes('properties(n) as props'))!
    expect(nodeQuery.cypher).toContain('NONE(l IN labels(n) WHERE l IN $referenceLabels)')
    expect(nodeQuery.params).toMatchObject({ pid: 'p1', referenceLabels: ['CVE', 'MitreData', 'Capec'] })
  })
})
