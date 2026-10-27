/** @vitest-environment node */
/**
 * Plan 09.2: the report's JavaScript section reads the BaseURL coverage stamps,
 * so a run that analyzed hosts and found nothing says so instead of dropping
 * the section, and hosts JS Recon never read are named as not analyzed.
 *
 * Run: npx vitest run src/lib/report/reportData.jsCoverage.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { queryJsRecon } from './reportData'

const int = (n: number) => ({ low: n, high: 0 })
const rec = (values: Record<string, unknown>) => ({ get: (k: string) => values[k] })

function fakeSession(coverageRows: Record<string, unknown>[]) {
  const queries: string[] = []
  return {
    queries,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    run: vi.fn(async (cypher: string, _params: any) => {
      queries.push(cypher)
      if (cypher.includes('js_recon_status')) return { records: coverageRows.map(rec) }
      return { records: [] }
    }),
  }
}

describe('queryJsRecon coverage', () => {
  test('host counts per state, and the reasons hosts were cut', async () => {
    const s = fakeSession([
      { status: 'complete', reason: null, live: false, hosts: int(3) },
      { status: 'no_input', reason: null, live: false, hosts: int(1) },
      { status: 'partial', reason: 'file cap', live: false, hosts: int(1) },
      { status: 'failed', reason: 'host unreachable', live: false, hosts: int(2) },
      { status: null, reason: null, live: true, hosts: int(4) },
      { status: null, reason: null, live: false, hosts: int(9) },
    ])
    const js = await queryJsRecon(s, 'p1')
    expect(js.totalFindings).toBe(0)
    expect(js.coverage).toEqual({
      recorded: true, complete: 3, partial: 1, noInput: 1, failed: 2, notScanned: 4,
      failedReasons: [{ reason: 'host unreachable', hosts: 2 }],
      partialReasons: [{ reason: 'file cap', hosts: 1 }],
    })
  })

  test('a host cut for several reasons counts under each', async () => {
    const js = await queryJsRecon(fakeSession([
      { status: 'partial', reason: 'file cap, host unreachable', live: false, hosts: int(2) },
      { status: 'partial', reason: 'file cap', live: false, hosts: int(1) },
    ]), 'p1')
    expect(js.coverage?.partialReasons).toEqual([
      { reason: 'file cap', hosts: 3 }, { reason: 'host unreachable', hosts: 2 }])
  })

  test('a project with no stamp at all records nothing, whatever its hosts', async () => {
    const js = await queryJsRecon(fakeSession([{ status: null, reason: null, live: true, hosts: int(6) }]), 'p1')
    expect(js.coverage).toEqual({
      recorded: false, complete: 0, partial: 0, noInput: 0, failed: 0, notScanned: 0,
      failedReasons: [], partialReasons: [],
    })
  })

  test('the query is scoped to the project and reads only the stamp, never a URL', async () => {
    const s = fakeSession([])
    await queryJsRecon(s, 'p1')
    const q = s.queries.find(c => c.includes('js_recon_status'))!
    expect(q).toContain('(bu:BaseURL {project_id: $pid})')
    expect(q).not.toContain('bu.url')
  })
})
