/** @vitest-environment node */
import { qualitySettings, invalidQualitySettings } from '@/lib/reconSettings/qualitySettings.testFixtures'
import { beforeEach, expect, test, vi } from 'vitest'
const h = vi.hoisted(() => ({
  project: {} as Record<string, unknown>, preset: {} as Record<string, unknown>,
  creates: vi.fn(), writes: vi.fn(), presetCreate: vi.fn(), presetWrite: vi.fn(),
  busy: null as string | null,
}))
vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      findUnique: async () => ({ ...h.project }),
      create: async ({ data }: { data: Record<string, unknown> }) => { h.creates(data); h.project = { ...data, id: 'p1' }; return h.project },
      updateMany: async ({ where, data }: { where: { updatedAt?: Date }; data: Record<string, unknown> }) => {
        h.writes({ where, data })
        if (where.updatedAt && +new Date(where.updatedAt) !== +new Date(h.project.updatedAt as Date)) return { count: 0 }
        Object.assign(h.project, data); return { count: 1 }
      },
    },
    userProjectPreset: {
      findFirst: async () => ({ ...h.preset }), findMany: async () => [], count: async () => 0,
      create: async ({ data }: { data: Record<string, unknown> }) => { h.presetCreate(data); h.preset = { ...h.preset, ...data }; return h.preset },
      updateMany: async ({ data }: { data: Record<string, unknown> }) => { h.presetWrite(data); Object.assign(h.preset, data); return { count: 1 } },
    },
    userSettings: { findUnique: async () => null }, userLlmProvider: { count: async () => 0 },
    fireteamSettingsAudit: { createMany: async () => ({ count: 0 }) },
    jobQueue: { findMany: async () => [] }, scanSchedule: { findMany: async () => [] },
    projectAuthProfile: { findUnique: async () => null },
    engagementAuthorization: { create: vi.fn(), count: async () => 0, findFirst: async () => null },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }; return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => h.busy, describeLiveGraphWriters: async () => h.busy }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/reconPresets/badges', () => ({ renamePresetBadges: vi.fn(), clearPresetBadges: vi.fn() }))
vi.mock('@/lib/reconPresets/server', async () => {
  const actual = await vi.importActual<typeof import('@/lib/reconPresets/server')>('@/lib/reconPresets/server')
  return { ...actual, fetchBackendDefaults: async () => ({}) }
})
import { createProject } from '@/lib/mcp/engagementTools'
import { updateReconSettings } from '@/lib/mcp/writeTools'
import { createReconPreset, updateReconPreset, applyReconPreset } from '@/lib/mcp/presetTools'
import { __resetRateLimiter } from '@/lib/mcpAuth'
import type { McpContext } from '@/lib/mcp/tools'
import { extractPresetSettings } from '@/lib/project-preset-utils'
const ctx = (): McpContext => ({ token: { tokenId: 'fixture', userId: 'owner', name: 'fixture', tokenPrefix: 'rdmn_mcp_fixture',
  scopes: ['recon:read','recon:settings','project:create','preset:write','preset:apply'] as never } })
const at = new Date('2026-01-01T00:00:00Z')
const valid = { ...qualitySettings, plannerMode: 'shadow', plannerManifestEnabled: false, plannerConsumerAiTags: false,
  plannerConsumerTargetSelection: false, plannerConsumerTwoPass: false,
  cveLookupEnabled: false, mitreEnabled: false, securityCheckEnabled: false }
beforeEach(() => {
  vi.clearAllMocks(); __resetRateLimiter(); h.busy = null
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    expect(String(url)).toContain('/guardrail/check-target')
    return new Response(JSON.stringify({ allowed: true }), { status: 200 })
  }))
  h.project = { ...extractPresetSettings({}), id: 'p1', userId: 'owner', updatedAt: at,
    name: 'fixture', targetDomain: 'example.test', ipMode: false, domainBatchMode: false,
    nucleiRateLimit: 42, engagementIdentityHeader: 'X-Test: fixture', plannerMode: 'shadow' }
  h.preset = { id: 'preset1', userId: 'owner', name: 'fixture', description: '', settings: valid,
    updatedAt: at, createdVia: 'ui', updatedVia: 'ui', lastWriterTokenPrefix: null }
})
const writers = {
  create: (settings: Record<string, unknown>) => createProject(ctx(), { name: 'fixture', targetDomain: 'example.test', engagementKind: 'internal', settings }),
  update: (settings: Record<string, unknown>) => updateReconSettings(ctx(), 'p1', settings),
  presetCreate: (settings: Record<string, unknown>) => createReconPreset(ctx(), { name: 'new fixture', settings }),
  presetUpdate: (settings: Record<string, unknown>) => updateReconPreset(ctx(), { presetId: 'preset1', description: 'updated fixture', settings }),
  presetApply: (settings: Record<string, unknown>) => { h.preset.settings = settings; return applyReconPreset(ctx(), { projectId: 'p1', presetId: 'preset1' }) },
  presetCopy: (settings: Record<string, unknown>) => { h.preset.settings = settings; return createReconPreset(ctx(), { name: 'copied fixture', fromPresetId: 'preset1' }) },
}
const invalid = [
  ...invalidQualitySettings,
  ...['bad', 'SHADOW', '', null, 1, false, [], {}].map(v => ['plannerMode', v]),
  ...Object.keys(valid).filter(k => k !== 'plannerMode' && !(k in qualitySettings)).flatMap(k => ['false', 'true', 0, 1, null, [], {}].map(v => [k, v])),
  ['plannerUnknown', false], ['PLANNER_MODE', 'shadow'],
] as [string, unknown][]
for (const [name, write] of Object.entries(writers)) {
  test.each(invalid)(`${name} refuses %s=%j atomically`, async (key, value) => {
    const before = { ...h.project }
    await expect(write({ katanaDepth: 3, [key]: value })).rejects.toMatchObject({ code: 'setting_rejected' })
    expect(h.creates).not.toHaveBeenCalled(); expect(h.writes).not.toHaveBeenCalled()
    expect(h.presetCreate).not.toHaveBeenCalled(); expect(h.presetWrite).not.toHaveBeenCalled()
    expect(h.project).toEqual(before)
  })
  test.each(['off','shadow','enforce'])(`${name} persists %s and false without coercion`, async mode => {
    await write({ ...valid, plannerMode: mode })
    const saved = name.startsWith('preset') && name !== 'presetApply' ? h.preset.settings : h.project
    expect(saved).toMatchObject({ ...valid, plannerMode: mode })
    if (name !== 'create') expect(h.project.engagementIdentityHeader).toBe('X-Test: fixture')
    if (name === 'update') expect(h.project.nucleiRateLimit).toBe(42)
  })
}
test('MCP settings CAS and busy guards remain effective', async () => {
  await expect(updateReconSettings(ctx(), 'p1', { plannerMode: 'enforce' }, '2025-01-01T00:00:00Z')).rejects.toMatchObject({ code: 'conflict' })
  expect(h.project.plannerMode).toBe('shadow')
  h.writes.mockClear(); h.busy = 'a scan is running'
  await expect(writers.update({ plannerMode: 'off' })).rejects.toMatchObject({ code: 'busy' })
  expect(h.writes).not.toHaveBeenCalled()
})
