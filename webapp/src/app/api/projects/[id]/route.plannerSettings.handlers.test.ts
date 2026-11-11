/** @vitest-environment node */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  update: vi.fn(),
  updateMany: vi.fn(),
  seed: vi.fn(),
  scanWriters: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      update: (...a: unknown[]) => h.update(...a),
      updateMany: (...a: unknown[]) => h.updateMany(...a),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/graphSeedDomains', () => ({
  seedDomainNames: () => [],
  seedProjectDomains: (...a: unknown[]) => h.seed(...a),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.scanWriters(...a) }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner', isAdmin: false }),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { PUT } from './route'

const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test',
  ipMode: false, domainBatchMode: false,
  updatedAt: new Date('2026-09-29T10:00:00.000Z'),
}
const params = { params: Promise.resolve({ id: 'proj-1' }) }

function put(body: Record<string, unknown>) {
  return PUT(new NextRequest('http://localhost/api/projects/proj-1', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }), params)
}

const updateData = () => h.update.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  h.findUnique.mockImplementation(async () => ({ ...STORED }))
  h.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...STORED, ...data }))
  h.updateMany.mockResolvedValue({ count: 1 })
  h.seed.mockResolvedValue(undefined)
  h.scanWriters.mockResolvedValue(null)
})


const invalids = [
  ...['bogus', 'SHADOW', '', null, 1, false, [], {}].map(value => ['plannerMode', value]),
  ...['plannerManifestEnabled', 'plannerConsumerAiTags', 'plannerConsumerTargetSelection', 'plannerConsumerTwoPass',
      'cveLookupEnabled', 'mitreEnabled', 'securityCheckEnabled'].flatMap(key =>
        ['false', 'true', 0, 1, null, [], {}].map(value => [key, value])),
  ['plannerUnknown', false], ['PLANNER_MODE', 'shadow'],
] as [string, unknown][]
const valid = { plannerMode: 'shadow', plannerManifestEnabled: false, plannerConsumerAiTags: false,
  plannerConsumerTargetSelection: false, plannerConsumerTwoPass: false,
  cveLookupEnabled: false, mitreEnabled: false, securityCheckEnabled: false }

async function call(patch: Record<string, unknown>) { return put(patch) }

test.each(invalids)('refuses %s=%j atomically before persistence', async (key, value) => {
  const res = await call({ description: 'must not write', [key]: value })
  expect(res.status).toBe(400)
  expect((await res.json()).error).toContain(key)
  expect(h.update).not.toHaveBeenCalled()
  expect(h.updateMany).not.toHaveBeenCalled()
})

test.each(['off', 'shadow', 'enforce'])('persists exact mode %s and all false values', async mode => {
  const res = await call({ ...valid, plannerMode: mode, description: 'unchanged unrelated', nucleiRateLimit: 42 })
  expect(res.status).toBeLessThan(400)
  expect(h.update).toHaveBeenCalledTimes(1)
  expect(updateData()).toMatchObject({ ...valid, plannerMode: mode, description: 'unchanged unrelated', nucleiRateLimit: 42 })
})
test('absent planner keys never become overrides', async () => {
  const res = await call({ description: 'ordinary edit' })
  expect(res.status).toBeLessThan(400)
  for (const key of Object.keys(valid)) expect(updateData()).not.toHaveProperty(key)
})

test('valid partial update preserves saved unrelated settings and CAS refuses stale writes', async () => {
  let row: Record<string, unknown> = { ...STORED, plannerMode: 'shadow', nucleiRateLimit: 42, httpxCustomHeaders: ['X-Test: fixture'] }
  h.findUnique.mockImplementation(async () => ({ ...row }))
  h.update.mockImplementation(async ({ data }) => (row = { ...row, ...data }))
  expect((await call({ plannerConsumerTwoPass: false })).status).toBe(200)
  expect(row).toMatchObject({ plannerMode: 'shadow', nucleiRateLimit: 42, httpxCustomHeaders: ['X-Test: fixture'], plannerConsumerTwoPass: false })
  h.updateMany.mockResolvedValue({ count: 0 })
  expect((await call({ plannerMode: 'enforce', updatedAt: '2026-01-01T00:00:00Z' })).status).toBe(409)
  expect(row.plannerMode).toBe('shadow')
})
