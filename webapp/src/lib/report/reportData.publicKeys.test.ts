/** @vitest-environment node */
/**
 * Plan 05.2: keys that are public by design (a browser key, a DSN, a
 * publishable key) are left out of the Secret severity counts and the
 * per-secret risk weight, and listed on their own "Expected-public client
 * keys" line. A node written before `public_client_key` existed is judged by
 * its pattern name.
 *
 * Run: npx vitest run src/lib/report/reportData.publicKeys.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { queryCveIntelligence, querySecrets } from './reportData'
import { publicClientKeyCypher } from '@/lib/secrets/publicClientKeys'

function int(n: number) { return { low: n, high: 0 } }

function rec(values: Record<string, unknown>) {
  return { get: (k: string) => values[k] }
}

function fakeSession() {
  const queries: string[] = []
  return {
    queries,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    run: vi.fn(async (cypher: string, _params: any) => {
      queries.push(cypher)
      if (cypher.includes('AS publicType')) {
        return { records: [rec({ publicType: 'GCP API Key', count: int(3) }),
                           rec({ publicType: 'Sentry DSN', count: int(1) })] }
      }
      if (cypher.includes('count(s) AS total')) return { records: [rec({ total: int(2) })] }
      if (cypher.includes('AS severity, count(s)')) return { records: [rec({ severity: 'high', count: int(2) })] }
      if (cypher.includes('AS sensitiveFiles')) {
        return { records: [rec({ repos: int(2), secrets: int(5), publicClientKeys: int(4), sensitiveFiles: int(1) })] }
      }
      return { records: [] }
    }),
  }
}

const PUBLIC = publicClientKeyCypher('s')

describe('querySecrets', () => {
  test('every count and the detail list leave public client keys out', async () => {
    const s = fakeSession()
    await querySecrets(s, 'p1')
    const counted = s.queries.filter(q => q.includes('MATCH (s:Secret') && !q.includes('AS publicType'))
    expect(counted.length).toBe(5)
    for (const q of counted) expect(q).toContain(`AND NOT ${PUBLIC}`)
  })

  test('public client keys are counted apart, by type', async () => {
    const s = fakeSession()
    const secrets = await querySecrets(s, 'p1')
    const q = s.queries.find(c => c.includes('AS publicType'))!
    expect(q).toContain(`AND ${PUBLIC}`)
    expect(secrets.total).toBe(2)
    expect(secrets.publicClientKeys).toEqual({
      total: 4,
      byType: [{ secretType: 'GCP API Key', count: 3 }, { secretType: 'Sentry DSN', count: 1 }],
    })
  })
})

describe('queryCveIntelligence: GitHub-hunt secrets', () => {
  test('a public client key found in a repository is not an exposed secret', async () => {
    const s = fakeSession()
    const intel = await queryCveIntelligence(s, 'p1')
    const q = s.queries.find(c => c.includes('AS sensitiveFiles'))!
    expect(q).toContain(`count(DISTINCT CASE WHEN NOT ${publicClientKeyCypher('sec')} THEN sec END) AS secrets`)
    expect(q).toContain(`count(DISTINCT CASE WHEN ${publicClientKeyCypher('sec')} THEN sec END) AS publicClientKeys`)
    expect(intel.githubSecrets).toEqual({ repos: 2, secrets: 5, publicClientKeys: 4, sensitiveFiles: 1 })
  })
})
