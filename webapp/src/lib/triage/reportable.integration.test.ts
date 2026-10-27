/** @vitest-environment node */
/**
 * L4, real Neo4j: the Cypher and TypeScript halves of the report predicate agree.
 *
 * The report and Insights filter in Cypher; the template and any client-side
 * reader decide in TypeScript. A drift between them would print one count and
 * list another, so every row of the truth table is evaluated by both.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/triage/reportable.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { isReportCountable, reportBucket, reportBucketCypher, reportCountable } from './reportable'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `REPORTABLE_${Math.random().toString(36).slice(2, 10)}`

const ROWS: Record<string, unknown>[] = [
  {},
  { triage_state: 'open' },
  { triage_state: 'fixed' },
  { triage_state: 'gone' },
  { triage_state: 'inactive' },
  { triage_state: 'false_positive', triage_decided_by: 'review' },
  { triage_state: 'false_positive', triage_status: 'likely_noise', triage_source: 'human' },
  { triage_status: 'likely_noise', triage_source: 'human' },
  { triage_status: 'likely_noise', triage_source: 'ai' },
  { triage_status: 'likely_noise' },
  { triage_status: 'confirmed', triage_source: 'human' },
  { triage_state: 'gone', triage_status: 'likely_noise', triage_source: 'human' },
  { triage_state: 'needs_verification' },
  { triage_state: '' },
]

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    alive = true
  } catch { alive = false }
})

afterAll(async () => {
  if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('TS/Cypher parity of the report predicate', () => {
  test('every truth-table row lands in the same bucket and countability in both halves', async (ctx) => {
    if (!alive || !session) ctx.skip()
    await session!.run(
      `UNWIND range(0, size($rows) - 1) AS i
       CREATE (n:Vulnerability {id: 'row-' + toString(i), project_id: $pid, user_id: 'u'})
       SET n += $rows[i]`,
      { pid: PID, rows: ROWS },
    )
    const res = await session!.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       RETURN toInteger(substring(v.id, 4)) AS i,
              ${reportBucketCypher('v')} AS bucket,
              (${reportCountable('v')}) AS countable
       ORDER BY i`,
      { pid: PID },
    )
    const got = res.records.map((r) => ({
      bucket: r.get('bucket') as string,
      countable: r.get('countable') as boolean,
    }))
    const want = ROWS.map((p) => ({ bucket: reportBucket(p), countable: isReportCountable(p) }))
    expect(got).toEqual(want)
  })
})
