/**
 * PUT /api/projects/[id] (the whole-row update route): the engagement
 * identity header is fail-closed at the write. An invalid value (any
 * checkIdentityHeader rule, or a present null/non-string) is a 400 and
 * neither prisma.project.update nor updateMany is called. Absent leaves
 * the column untouched, '' passes through as the clearing value, and a
 * valid line is persisted. Generic custom-header fields keep the shared
 * contract.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/projects/[id]/route.identityHeader.test.ts"
 * @vitest-environment node
 */
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

describe('PUT: a valid, empty or absent identity header writes', () => {
  test('valid line is persisted', async () => {
    const res = await put({ engagementIdentityHeader: 'X-Bug-Bounty: researcher-7f3a' })
    expect(res.status).toBe(200)
    expect(h.update).toHaveBeenCalledTimes(1)
    expect(updateData().engagementIdentityHeader).toBe('X-Bug-Bounty: researcher-7f3a')
  })

  test('empty string passes through as the clearing value', async () => {
    const res = await put({ engagementIdentityHeader: '' })
    expect(res.status).toBe(200)
    expect(updateData().engagementIdentityHeader).toBe('')
  })

  test('omitted field is not written (partial save unaffected)', async () => {
    const res = await put({ name: 'renamed' })
    expect(res.status).toBe(200)
    expect(updateData()).not.toHaveProperty('engagementIdentityHeader')
    expect(updateData().name).toBe('renamed')
  })
})

describe('PUT: an invalid identity header never reaches the write', () => {
  test.each([
    'Host: evil',
    'Content-Length: 5',
    'X-Redamon-Ctx: forged',
    'Proxy-Anything: x',
    'X-BB: a;;X-B: 2',
    'X-BB: a\x0bb',
    'X-BB: a\x7fb',
    'X-BB: a\r\nInjected: 1',
    'X-BB: a\nInjected: 1',
    `X-BB: ${'a'.repeat(4096)}`,
    `${'X' + 'a'.repeat(256)}: v`,
    'X-BB:',
    'not-a-header',
  ])('%j -> 400 and no update/updateMany', async (value: string) => {
    const res = await put({ engagementIdentityHeader: value })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/engagementIdentityHeader/)
    expect(h.update).not.toHaveBeenCalled()
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test.each([null, 42, true, { name: 'X-BB' }, ['X-BB: v']])(
    'present non-string %j -> 400 and no update', async (value: unknown) => {
      const res = await put({ engagementIdentityHeader: value })
      expect(res.status).toBe(400)
      expect(h.update).not.toHaveBeenCalled()
      expect(h.updateMany).not.toHaveBeenCalled()
    },
  )
})

describe('PUT: generic custom headers keep the shared contract', () => {
  test('a framing header in a generic custom-header field is not identity-checked', async () => {
    const res = await put({ httpxCustomHeaders: ['Content-Length: 3'] })
    expect(res.status).toBe(200)
    expect(h.update).toHaveBeenCalledTimes(1)
    expect(updateData().httpxCustomHeaders).toEqual(['Content-Length: 3'])
  })
})
