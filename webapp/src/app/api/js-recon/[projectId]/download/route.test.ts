/**
 * A failed JS Recon read answers a fixed sentence and the Neo4j code, never the
 * driver's message, which can quote the Cypher and the project's target data.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/js-recon/[projectId]/download/route.test.ts"
 * @vitest-environment node
 */
import { test, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ run: vi.fn(), close: vi.fn() }))

vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: h.run, close: h.close }) }))

import { GET } from './route'

test('a Neo4j failure answers its code, not its message', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.run.mockRejectedValue(Object.assign(
    new Error('Database unavailable while running MATCH (jf:JsReconFinding {project_id: "p1"}) secret-target.example'),
    { code: 'Neo.TransientError.General.DatabaseUnavailable', name: 'Neo4jError' },
  ))
  const res = await GET(new NextRequest('http://localhost/api/js-recon/p1/download?fresh=1'), { params: Promise.resolve({ projectId: 'p1' }) })
  expect(res.status).toBe(500)
  const body = await res.json()
  expect(body).toEqual({ error: 'JS Recon query failed', code: 'Neo.TransientError.General.DatabaseUnavailable' })
  expect(h.close).toHaveBeenCalled()
})
