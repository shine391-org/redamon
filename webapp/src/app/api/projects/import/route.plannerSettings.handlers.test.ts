/** @vitest-environment node */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn(), createPreset: vi.fn() }))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    userProjectPreset: { create: (...a: unknown[]) => h.createPreset(...a) },
    engagementAuthorization: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

async function bundle(project: Record<string, unknown>, presetSettings?: Record<string, unknown>): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.invalid',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    ...project,
  }))
  if (presetSettings) zip.file('presets/user_project_presets.json', JSON.stringify([{ name: 'fixture preset', settings: presetSettings }]))
  const buf = await zip.generateAsync({ type: 'arraybuffer' })
  const fd = new FormData()
  fd.set('file', new File([buf], 'p.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

const createdData = () => h.createProject.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  h.createProject.mockResolvedValue({ id: 'new', name: 'imported' })
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

async function call(patch: Record<string, unknown>) { return POST(await bundle(patch)) }

test.each(invalids)('refuses %s=%j atomically before persistence', async (key, value) => {
  const res = await call({ description: 'must not write', [key]: value })
  expect(res.status).toBe(400)
  expect((await res.json()).error).toContain(key)
  expect(h.createProject).not.toHaveBeenCalled()
})

test.each(['off', 'shadow', 'enforce'])('persists exact mode %s and all false values', async mode => {
  const res = await call({ ...valid, plannerMode: mode, description: 'unchanged unrelated', nucleiRateLimit: 42 })
  expect(res.status).toBeLessThan(400)
  expect(h.createProject).toHaveBeenCalledTimes(1)
  expect(createdData()).toMatchObject({ ...valid, plannerMode: mode, description: 'unchanged unrelated', nucleiRateLimit: 42 })
})
test('absent planner keys never become overrides', async () => {
  const res = await call({ description: 'ordinary edit' })
  expect(res.status).toBeLessThan(400)
  for (const key of Object.keys(valid)) expect(createdData()).not.toHaveProperty(key)
})
test.each(invalids)('nested preset import refuses %s=%j before ANY write', async (key, value) => {
  const res = await POST(await bundle({}, { katanaDepth: 3, [key]: value }))
  expect(res.status).toBe(400)
  expect((await res.json()).error).toContain(key)
  expect(h.createProject).not.toHaveBeenCalled()
  expect(h.createPreset).not.toHaveBeenCalled()
})
test('nested preset import retains valid false and independent project settings', async () => {
  const res = await POST(await bundle({ nucleiRateLimit: 42 }, valid))
  expect(res.status).toBe(200)
  expect(createdData().nucleiRateLimit).toBe(42)
  expect(h.createPreset.mock.calls[0][0].data.settings).toMatchObject(valid)
})

