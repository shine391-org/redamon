/**
 * POST /api/projects/import: the engagement identity header in a bundle is
 * fail-closed before the first production write. An invalid value (any
 * checkIdentityHeader rule, or a present null/non-string) is a 400 and
 * prisma.project.create is never called — the import has no transaction
 * wrapping the create and what follows, so refusing here is what keeps a
 * bad bundle from writing anything. Absent leaves the column to its
 * default, '' passes through as the clearing value, a valid line is
 * persisted, and generic custom-header fields keep the shared contract.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/projects/import/route.identityHeader.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn() }))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    engagementAuthorization: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

async function bundle(project: Record<string, unknown>): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.invalid',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    ...project,
  }))
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

describe('import: a valid, empty or absent identity header creates', () => {
  test('valid line is persisted', async () => {
    const res = await POST(await bundle({ engagementIdentityHeader: 'X-Bug-Bounty: researcher-7f3a' }))
    expect(res.status).toBe(200)
    expect(h.createProject).toHaveBeenCalledTimes(1)
    expect(createdData().engagementIdentityHeader).toBe('X-Bug-Bounty: researcher-7f3a')
  })

  test('empty string passes through as the clearing value', async () => {
    const res = await POST(await bundle({ engagementIdentityHeader: '' }))
    expect(res.status).toBe(200)
    expect(createdData().engagementIdentityHeader).toBe('')
  })

  test('omitted field leaves the column to its schema default (not written)', async () => {
    const res = await POST(await bundle({}))
    expect(res.status).toBe(200)
    expect(h.createProject).toHaveBeenCalledTimes(1)
    expect(createdData()).not.toHaveProperty('engagementIdentityHeader')
  })
})

describe('import: an invalid identity header never reaches the create', () => {
  test.each([
    'Host: evil',
    'Content-Length: 5',
    'X-Redamon-Ctx: forged',
    'Proxy-Connection: x',
    'X-BB: a;;X-B: 2',
    'X-BB: a\x0bb',
    'X-BB: a\x7fb',
    'X-BB: a\r\nInjected: 1',
    'X-BB: a\nInjected: 1',
    `X-BB: ${'a'.repeat(4096)}`,
    `${'X' + 'a'.repeat(256)}: v`,
    'X-BB:',
    'not-a-header',
  ])('%j -> 400 and no create', async (value: string) => {
    const res = await POST(await bundle({ engagementIdentityHeader: value }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/engagementIdentityHeader/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test.each([null, 42, true, { name: 'X-BB' }, ['X-BB: v']])(
    'present non-string %j -> 400 and no create', async (value: unknown) => {
      const res = await POST(await bundle({ engagementIdentityHeader: value }))
      expect(res.status).toBe(400)
      expect(h.createProject).not.toHaveBeenCalled()
    },
  )
})

describe('import: generic custom headers keep the shared contract', () => {
  test('a framing header in a generic custom-header field is not identity-checked', async () => {
    const res = await POST(await bundle({ httpxCustomHeaders: ['Content-Length: 3'] }))
    expect(res.status).toBe(200)
    expect(h.createProject).toHaveBeenCalledTimes(1)
    expect(createdData().httpxCustomHeaders).toEqual(['Content-Length: 3'])
  })
})
