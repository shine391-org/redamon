/** @vitest-environment node */
import { qualitySettings, invalidQualitySettings } from '@/lib/reconSettings/qualitySettings.testFixtures'
import { beforeEach, expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ create: vi.fn(), findUnique: vi.fn() }))
vi.mock('@/lib/prisma', () => ({ default: { userProjectPreset: h } }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  assertOwner: vi.fn(() => null),
  ownerScope: vi.fn(() => ({ userId: 'u1' })),
}))

import { POST } from './route'
import { GET } from './[id]/route'


beforeEach(() => {
  vi.clearAllMocks()
  h.create.mockImplementation(async ({ data }) => ({ id: 'preset-1', ...data }))
})
const valid = { ...qualitySettings, plannerMode: 'shadow', plannerManifestEnabled: false, plannerConsumerAiTags: false,
  plannerConsumerTargetSelection: false, plannerConsumerTwoPass: false,
  cveLookupEnabled: false, mitreEnabled: false, securityCheckEnabled: false }
const save = (settings: Record<string, unknown>) => POST(new NextRequest('http://x/api/presets', {
  method: 'POST', body: JSON.stringify({ name: 'fixture', settings }),
}))
test.each([
  ...invalidQualitySettings,  ['plannerMode', 'SHADOW'], ['plannerMode', null], ['plannerMode', 1],
  ...Object.keys(valid).filter(k => k !== 'plannerMode' && !(k in qualitySettings)).flatMap(key =>
    ['false', 1, null].map(value => [key, value])),
  ['plannerUnknown', false], ['PLANNER_MODE', 'shadow'],
] as [string, unknown][])('preset refuses %s=%j before storage', async (key, value) => {
  const res = await save({ katanaDepth: 3, [key as string]: value })
  expect(res.status).toBe(400)
  expect((await res.json()).error).toContain(key)
  expect(h.create).not.toHaveBeenCalled()
})
test.each(['off', 'shadow', 'enforce'])('preset stores %s and exact false values', async mode => {
  const res = await save({ ...valid, plannerMode: mode, katanaDepth: 3 })
  expect(res.status).toBe(201)
  expect(h.create.mock.calls[0][0].data.settings).toMatchObject({ ...valid, plannerMode: mode, katanaDepth: 3 })
})
