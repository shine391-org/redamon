/** @vitest-environment node */
/**
 * L4, real Neo4j: the report counts a person's, an agent's and a rule's mutes
 * apart.
 *
 * An agent's (MCP) mute carries its token owner's user id in `muted_by`, the
 * same as that person's own mute. Only `muted_channel` tells them apart, and
 * the split is Cypher the unit tests never run (they mock the session). Were
 * the channel check wrong, the report would present an unattended agent's
 * suppressions as findings a person reviewed.
 *
 * A Multi mute is a person's mute too (it stays inside the people's count) but
 * was chosen in bulk from AI suggestions, so it also gets its own line, and is
 * never counted as an agent's or a rule's.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/report/reportData.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { queryGraphOverview, querySecrets, queryVulnerabilities } from './reportData'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `REPORT_MUTES_${Math.random().toString(36).slice(2, 10)}`
const UID = `report-mutes-${Math.random().toString(36).slice(2, 10)}`
const PID_MULTI = `REPORT_MM_${Math.random().toString(36).slice(2, 10)}`

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
  if (alive && session) {
    await session.run('MATCH (n) WHERE n.project_id IN $pids DETACH DELETE n', { pids: [PID, PID_MULTI] })
  }
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('the suppressed-findings line', () => {
  test('a person\'s, an agent\'s and a rule\'s mute are counted 1/1/1 in separate fields', async (ctx) => {
    if (!alive || !session) ctx.skip()
    await session!.run(
      `UNWIND $rows AS row
       CREATE (n:Vulnerability:Muted {id: row.id, user_id: $uid, project_id: $pid, severity: 'info',
                                      muted: true, muted_at: datetime(), muted_by: row.by,
                                      muted_reason: row.reason})
       SET n.muted_channel = row.channel, n.muted_token = row.token`,
      {
        uid: UID, pid: PID,
        rows: [
          { id: 'v-person', by: UID, reason: 'noise', channel: null, token: null },
          { id: 'v-agent', by: UID, reason: 'dev-only banner', channel: 'mcp', token: 'rdmn_mcp_ab12cd34' },
          { id: 'v-rule', by: 'rule:vuln.nuclei/k3f9a2', reason: 'Filter rule: Informational templates',
            channel: null, token: null },
        ],
      },
    )

    const overview = await queryGraphOverview(session, PID)

    expect({
      people: overview.suppressedByPeople,
      agents: overview.suppressedByAgents,
      rules: overview.suppressedByRules,
      total: overview.suppressedCount,
    }).toEqual({ people: 1, agents: 1, rules: 1, total: 3 })
    expect(overview.suppressedRules).toEqual([{ name: 'Informational templates', count: 1 }])
  })

  test('a Multi mute is a person\'s, counted on its own line, never an agent\'s or a rule\'s', async (ctx) => {
    if (!alive || !session) ctx.skip()
    // Two person mutes, three Multi mutes from two batches, one agent mute, two
    // rule mutes, and one visible finding that counts nowhere.
    await session!.run(
      `UNWIND $rows AS row
       CREATE (n:Vulnerability:Muted {id: row.id, user_id: $uid, project_id: $pid, severity: 'info',
                                      muted: true, muted_at: datetime(), muted_by: row.by,
                                      muted_reason: row.reason})
       SET n.muted_channel = row.channel, n.muted_token = row.token`,
      {
        uid: UID, pid: PID_MULTI,
        rows: [
          { id: 'p1', by: UID, reason: 'noise', channel: null, token: null },
          { id: 'p2', by: UID, reason: 'noise', channel: null, token: null },
          { id: 'm1', by: UID, reason: 'Multi mute mm-0000000a · x', channel: 'multi', token: 'mm-0000000a' },
          { id: 'm2', by: UID, reason: 'Multi mute mm-0000000a · x', channel: 'multi', token: 'mm-0000000a' },
          { id: 'm3', by: UID, reason: 'Multi mute mm-0000000b · x', channel: 'multi', token: 'mm-0000000b' },
          { id: 'a1', by: UID, reason: 'agent', channel: 'mcp', token: 'rdmn_mcp_ab12cd34' },
          { id: 'r1', by: 'rule:vuln.nuclei/k3f9a2', reason: 'Filter rule: Info', channel: null, token: null },
          { id: 'r2', by: 'rule:vuln.nuclei/k3f9a2', reason: 'Filter rule: Info', channel: null, token: null },
        ],
      },
    )
    await session!.run(
      `CREATE (:Vulnerability {id: 'visible', user_id: $uid, project_id: $pid, severity: 'high'})`,
      { uid: UID, pid: PID_MULTI },
    )

    const overview = await queryGraphOverview(session, PID_MULTI)

    expect({
      people: overview.suppressedByPeople,
      multi: overview.suppressedByMultiMute,
      agents: overview.suppressedByAgents,
      rules: overview.suppressedByRules,
      total: overview.suppressedCount,
    }).toEqual({ people: 5, multi: 3, agents: 1, rules: 2, total: 8 })
  })
})

describe('the board verdict in the report counts', () => {
  const PID_JUDGED = `REPORT_JUDGED_${Math.random().toString(36).slice(2, 10)}`

  afterAll(async () => {
    if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID_JUDGED })
  })

  test('a person excludes, a rule resolves, an AI review only flags', async (ctx) => {
    if (!alive || !session) ctx.skip()
    await session!.run(
      `UNWIND $rows AS row
       CREATE (n:Vulnerability {id: row.id, user_id: $uid, project_id: $pid, severity: 'high',
                                name: row.id, source: 'nuclei'})
       SET n += row.props`,
      {
        uid: UID, pid: PID_JUDGED,
        rows: [
          { id: 'plain', props: {} },
          { id: 'person-fp', props: { triage_status: 'likely_noise', triage_source: 'human',
                                      triage_state: 'false_positive', triage_decided_by: 'person' } },
          { id: 'inactive', props: { triage_state: 'inactive', triage_decided_by: 'rules' } },
          { id: 'ai-fp', props: { triage_state: 'false_positive', triage_decided_by: 'review' } },
        ],
      },
    )
    // A person's False positive that is ALSO muted: counted only as suppressed.
    await session!.run(
      `CREATE (:Vulnerability:Muted {id: 'muted-fp', user_id: $uid, project_id: $pid, severity: 'high',
                                     muted: true, muted_by: $uid, triage_status: 'likely_noise',
                                     triage_source: 'human', triage_state: 'false_positive'})`,
      { uid: UID, pid: PID_JUDGED },
    )
    await session!.run(
      `CREATE (:Secret {id: 's-person', user_id: $uid, project_id: $pid, severity: 'high',
                        triage_status: 'likely_noise', triage_source: 'human'}),
              (:Secret {id: 's-open', user_id: $uid, project_id: $pid, severity: 'high'})`,
      { uid: UID, pid: PID_JUDGED },
    )

    const vulns = await queryVulnerabilities(session, PID_JUDGED)
    const high = vulns.severityDistribution.find((d: { severity: string }) => d.severity === 'high')?.count
    expect(high).toBe(2)
    expect(vulns.findings.map((f: { name: string }) => f.name).sort()).toEqual(['ai-fp', 'plain'])

    const secrets = await querySecrets(session, PID_JUDGED)
    expect(secrets.total).toBe(1)

    const overview = await queryGraphOverview(session, PID_JUDGED)
    expect(overview.judged).toEqual({ personFalsePositive: 2, resolved: 1, aiFlagged: 1 })
    expect(overview.suppressedByPeople).toBe(1)
  })
})

describe('keys that are public by design, on a real graph (plan 05.2)', () => {
  const PID_PUBLIC = `REPORT_PUBLIC_${Math.random().toString(36).slice(2, 10)}`

  afterAll(async () => {
    if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID_PUBLIC })
  })

  test('flagged, legacy-named and secret keys are counted where the readers say', async (ctx) => {
    if (!alive || !session) ctx.skip()
    await session!.run(
      `CREATE (:Secret {id: 'flagged', user_id: $uid, project_id: $pid, severity: 'info',
                        secret_type: 'GCP API Key', public_client_key: true, source: 'js_recon'}),
              (:Secret {id: 'legacy', user_id: $uid, project_id: $pid, severity: 'critical',
                        secret_type: 'Sentry DSN', source: 'js_recon'}),
              (:Secret {id: 'real', user_id: $uid, project_id: $pid, severity: 'critical',
                        secret_type: 'Stripe Secret Key', public_client_key: false, source: 'js_recon'})`,
      { uid: UID, pid: PID_PUBLIC },
    )
    const secrets = await querySecrets(session, PID_PUBLIC)
    expect(secrets.total).toBe(1)
    expect(secrets.bySeverity).toEqual([{ severity: 'critical', count: 1 }])
    expect(secrets.findings.map((f: { secretType: string }) => f.secretType)).toEqual(['Stripe Secret Key'])
    expect(secrets.publicClientKeys?.total).toBe(2)
    expect(secrets.publicClientKeys?.byType.map((t: { secretType: string }) => t.secretType).sort())
      .toEqual(['GCP API Key', 'Sentry DSN'])
  })
})
