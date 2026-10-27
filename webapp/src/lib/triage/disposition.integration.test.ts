/** @vitest-environment node */
/**
 * L4, real Neo4j: the Cypher and TypeScript halves of disposition agree.
 *
 * The report and Insights group by `dispositionCypher` / `blockerCypher`; the
 * board and MCP `list_findings` decide with `disposition`. Every shared vector
 * is written as a node and evaluated by both.
 *
 * Skipped unless a Neo4j answers; the scanned-project check also needs
 * REDAMON_DISPOSITION_PROJECT (add `-e REDAMON_DISPOSITION_PROJECT=<id>`). To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/triage/disposition.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import vectors from './disposition.vectors.json'
import { blockerCypher, disposition, dispositionCypher, queryDispositionSummary, readSideDisposition } from './disposition'
import { agentCandidateConfirmedOrNA, notMuted } from '@/lib/graphMute'
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `DISPOSITION_${Math.random().toString(36).slice(2, 10)}`

const ROWS = (vectors as { props: Record<string, unknown> }[]).map((v) => v.props)

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

describe('TS/Cypher parity of disposition', () => {
  test('every vector gets the same disposition and blocker in both halves', async (ctx) => {
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
              ${dispositionCypher('v')} AS disposition,
              ${blockerCypher('v')} AS blocker
       ORDER BY i`,
      { pid: PID },
    )
    const got = res.records.map((r) => ({
      disposition: r.get('disposition') as string,
      blocker: r.get('blocker') as string | null,
    }))
    expect(got).toEqual(ROWS.map((p) => disposition(p)))
  })

  test('the project summary tallies exactly what the TypeScript half decides', async (ctx) => {
    if (!alive || !session) ctx.skip()
    const summary = await queryDispositionSummary(session!, PID)
    const want = { reportable: 0, candidate: 0, info: 0, excluded: 0 }
    const blockers = new Map<string, number>()
    for (const r of ROWS.map((p) => disposition(p))) {
      want[r.disposition] += 1
      if (r.blocker) blockers.set(r.blocker, (blockers.get(r.blocker) ?? 0) + 1)
    }
    expect(summary).toMatchObject(want)
    expect(new Map(summary!.blockers.map((b) => [b.blocker, b.count]))).toEqual(blockers)
  })
})

/**
 * Plan 10.E, phase B: on a project a v3.10 Priority Board run scored (a lab
 * project, by id in REDAMON_DISPOSITION_PROJECT), what the run stored on every
 * finding is what the read-side rules compute from the same props.
 */
describe('the stored disposition equals the read-side one, on a scanned project', () => {
  const project = process.env.REDAMON_DISPOSITION_PROJECT || ''

  test('every finding the run scored', async (ctx) => {
    if (!alive || !session || !project) ctx.skip()
    const res = await session!.run(
      `MATCH (n:${MUTEABLE_FINDING_LABELS.join('|')})
       WHERE n.project_id = $pid AND ${notMuted('n')} AND n.triage_run_id IS NOT NULL
       RETURN coalesce(n.id, n.finding_id) AS id, properties(n) AS props`,
      { pid: project },
    )
    expect(res.records.length).toBeGreaterThan(0)
    const differ: unknown[] = []
    for (const r of res.records) {
      const props = r.get('props') as Record<string, unknown>
      const stored = { disposition: props.triage_disposition, blocker: props.triage_blocker ?? null }
      const { triage_disposition: _d, triage_blocker: _b, ...rest } = props
      if (JSON.stringify(readSideDisposition(rest)) !== JSON.stringify(stored) ||
          JSON.stringify(disposition(props)) !== JSON.stringify(stored)) {
        differ.push({ id: r.get('id'), stored, readSide: readSideDisposition(rest) })
      }
    }
    console.info(`[disposition] ${res.records.length} findings of ${project} compared`)
    expect(differ).toEqual([])
  })

  test('the report and Insights headline counts what the board and MCP show', async (ctx) => {
    if (!alive || !session || !project) ctx.skip()
    const res = await session!.run(
      `MATCH (n:${MUTEABLE_FINDING_LABELS.join('|')})
       WHERE n.project_id = $pid AND ${notMuted('n')} AND ${agentCandidateConfirmedOrNA('n')}
       RETURN properties(n) AS props`,
      { pid: project },
    )
    const want = { reportable: 0, candidate: 0, info: 0, excluded: 0 }
    const blockers = new Map<string, number>()
    for (const r of res.records) {
      const d = disposition(r.get('props') as Record<string, unknown>)
      want[d.disposition] += 1
      if (d.blocker) blockers.set(d.blocker, (blockers.get(d.blocker) ?? 0) + 1)
    }
    const summary = await queryDispositionSummary(session!, project)
    console.info(`[disposition] headline ${JSON.stringify(summary)}`)
    expect(summary).toMatchObject(want)
    expect(new Map(summary!.blockers.map((b) => [b.blocker, b.count]))).toEqual(blockers)
  })
})
