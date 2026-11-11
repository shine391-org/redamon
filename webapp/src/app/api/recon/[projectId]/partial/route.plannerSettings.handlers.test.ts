/** @vitest-environment node */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  findUnique: vi.fn(),
  orchestratorFetch: vi.fn(),
  recordScanStart: vi.fn(),
  legacy: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'u1' }) }))
vi.mock('@/lib/scanTimeline', () => ({ recordScanStart: (...a: unknown[]) => h.recordScanStart(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
}))

import { POST } from './route'

function post(body: unknown) {
  return POST(
    new NextRequest('http://x/api/recon/p1/partial', { method: 'POST', body: JSON.stringify(body) }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  h.guard.mockResolvedValue(null)
  h.findUnique.mockResolvedValue({ id: 'p1', userId: 'u1', targetDomain: '' })
  h.legacy.mockResolvedValue([])
  h.orchestratorFetch.mockResolvedValue({
    ok: true,
    json: async () => ({ run_id: 'r1', status: 'running', roots: ['alpha.test', 'beta.test'] }),
  })
})


// This is the webapp transport contract. Strict admission is separately
// executed in test_planner_settings_boundary.py, not mocked into a validation proof.
test.each([false, true])('forwards modal booleans %s exactly, without widening saved planner settings', async value => {
  const settings_overrides = { CVE_LOOKUP_ENABLED: value, MITRE_ENABLED: value, SECURITY_CHECK_ENABLED: value }
  h.findUnique.mockResolvedValue({ id: 'p1', userId: 'u1', targetDomain: 'example.test', plannerMode: 'shadow' })
  const res = await post({ tool_id: 'Nuclei', settings_overrides })
  expect(res.status).toBe(200)
  expect(JSON.parse(h.orchestratorFetch.mock.calls[0][1].body).settings_overrides).toEqual(settings_overrides)
})
test('an absent override object stays empty, rather than injecting planner defaults', async () => {
  const res = await post({ tool_id: 'Nuclei' })
  expect(res.status).toBe(200)
  expect(JSON.parse(h.orchestratorFetch.mock.calls[0][1].body).settings_overrides).toEqual({})
})
test('delegated admission refusal remains observable and creates no scan-history write', async () => {
  h.orchestratorFetch.mockResolvedValue({ ok: false, status: 400, json: async () => ({ detail: 'PLANNER_MODE is not a supported override' }) })
  const res = await post({ tool_id: 'Nuclei', settings_overrides: { PLANNER_MODE: 'enforce' } })
  expect(res.status).toBe(400)
  expect((await res.json()).error).toContain('PLANNER_MODE')
  expect(h.recordScanStart).not.toHaveBeenCalled()
})
