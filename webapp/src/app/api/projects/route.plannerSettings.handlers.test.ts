/** @vitest-environment node */
import { qualitySettings, invalidQualitySettings } from '@/lib/reconSettings/qualitySettings.testFixtures'
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  userFindUnique: vi.fn(),
  projectCreate: vi.fn(),
  projectUpdate: vi.fn(),
  run: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => h.userFindUnique(...a) },
    project: {
      create: (...a: unknown[]) => h.projectCreate(...a),
      update: (...a: unknown[]) => h.projectUpdate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => h.run(...a), close: vi.fn() }),
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { NextRequest } from 'next/server'
import { POST } from './route'

function postReq(body: Record<string, unknown>) {
  return new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const base = { name: 'test', targetDomain: 'example.invalid', targetGuardrailEnabled: false }
const createdData = () => h.projectCreate.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  h.userFindUnique.mockResolvedValue({ id: 'user-1' })
  h.projectCreate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'p1', ...data }))
  h.projectUpdate.mockResolvedValue({})
  h.run.mockResolvedValue({ records: [] })
})


const invalids = [
  ...invalidQualitySettings,
  ...['bogus', 'SHADOW', '', null, 1, false, [], {}].map(value => ['plannerMode', value]),
  ...['plannerManifestEnabled', 'plannerConsumerAiTags', 'plannerConsumerTargetSelection', 'plannerConsumerTwoPass',
      'cveLookupEnabled', 'mitreEnabled', 'securityCheckEnabled'].flatMap(key =>
        ['false', 'true', 0, 1, null, [], {}].map(value => [key, value])),
  ['plannerUnknown', false], ['PLANNER_MODE', 'shadow'],
] as [string, unknown][]
const valid = { ...qualitySettings, plannerMode: 'shadow', plannerManifestEnabled: false, plannerConsumerAiTags: false,
  plannerConsumerTargetSelection: false, plannerConsumerTwoPass: false,
  cveLookupEnabled: false, mitreEnabled: false, securityCheckEnabled: false }

async function call(patch: Record<string, unknown>) { return POST(postReq({ ...base, ...patch })) }

test.each(invalids)('refuses %s=%j atomically before persistence', async (key, value) => {
  const res = await call({ description: 'must not write', [key]: value })
  expect(res.status).toBe(400)
  expect((await res.json()).error).toContain(key)
  expect(h.projectCreate).not.toHaveBeenCalled()
})

test.each(['off', 'shadow', 'enforce'])('persists exact mode %s and all false values', async mode => {
  const res = await call({ ...valid, plannerMode: mode, description: 'unchanged unrelated', nucleiRateLimit: 42 })
  expect(res.status).toBeLessThan(400)
  expect(h.projectCreate).toHaveBeenCalledTimes(1)
  expect(createdData()).toMatchObject({ ...valid, plannerMode: mode, description: 'unchanged unrelated', nucleiRateLimit: 42 })
})
test('absent planner keys never become overrides', async () => {
  const res = await call({ description: 'ordinary edit' })
  expect(res.status).toBeLessThan(400)
  for (const key of Object.keys(valid)) expect(createdData()).not.toHaveProperty(key)
})
