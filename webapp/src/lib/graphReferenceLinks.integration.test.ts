/** @vitest-environment node */
/**
 * Plan 09.5 against a real Neo4j: a restore re-links a project node to an
 * EXISTING global CVE node, leaves that node's properties untouched, skips a
 * link whose CVE is not in the database without creating one, and refuses a
 * catalogue node carried inside the payload.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/graphReferenceLinks.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, afterEach } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { restoreGraph } from './graphRestore'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const tag = Math.random().toString(36).slice(2, 10)
const PID = `REFLINK_${tag}`
const UID = `reflink-${tag}`
// Ids in a year no real CVE uses, so a test can never touch a real one.
const CVE_ID = `CVE-1900-${Math.floor(10000 + Math.random() * 89999)}`
const MISSING_CVE = `CVE-1900-${Math.floor(10000 + Math.random() * 89999)}9`

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    alive = true
  } catch { alive = false }
})

afterEach(async () => {
  if (!alive || !session) return
  await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
  await session.run('MATCH (c:CVE) WHERE c.id IN $ids DETACH DELETE c', { ids: [CVE_ID, MISSING_CVE] })
})

afterAll(async () => {
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('reference links on a real Neo4j', () => {
  test('re-links to the existing CVE, skips the missing one, and changes and creates no CVE', async ({ skip }) => {
    if (!alive || !session) skip()
    await session!.run('CREATE (:CVE {id: $id, cvss: 9.8, description: "real"})', { id: CVE_ID })

    const res = await restoreGraph(session!, [
      { labels: ['Vulnerability'], properties: { id: `v-${tag}`, user_id: UID }, _exportId: 'n1' },
      // A forged copy of the catalogue node: must never be written.
      { labels: ['CVE'], properties: { id: CVE_ID, cvss: 0, description: 'forged' }, _exportId: 'n2' },
    ], [], {
      projectId: PID,
      referenceLinks: [
        { startExportId: 'n1', endExportId: null, type: 'INCLUDES_CVE', refLabel: 'CVE', refKey: CVE_ID, properties: {} },
        { startExportId: 'n1', endExportId: null, type: 'INCLUDES_CVE', refLabel: 'CVE', refKey: MISSING_CVE, properties: {} },
        { startExportId: 'n1', endExportId: null, type: 'INCLUDES_CVE', refLabel: 'CVE', refKey: "CVE-1' OR 1=1", properties: {} },
      ],
    })
    expect(res.referenceLinks).toEqual({ restored: 1, skipped: 2 })

    const linked = await session!.run(
      `MATCH (v:Vulnerability {project_id: $pid})-[:INCLUDES_CVE]->(c:CVE) RETURN c.id AS id, c.cvss AS cvss,
              c.description AS d, c.project_id AS pid`, { pid: PID })
    expect(linked.records.map(r => [r.get('id'), r.get('cvss'), r.get('d'), r.get('pid')]))
      .toEqual([[CVE_ID, 9.8, 'real', null]])
    const cves = await session!.run('MATCH (c:CVE) WHERE c.id IN $ids RETURN count(c) AS n', { ids: [CVE_ID, MISSING_CVE] })
    expect(cves.records[0].get('n').toNumber()).toBe(1)
    const stray = await session!.run('MATCH (n {project_id: $pid}) WHERE n._exportId IS NOT NULL RETURN count(n) AS n', { pid: PID })
    expect(stray.records[0].get('n').toNumber()).toBe(0)
  })
})
