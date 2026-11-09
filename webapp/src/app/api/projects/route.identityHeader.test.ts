/**
 * POST /api/projects: the engagement identity header is fail-closed at the
 * write. An invalid value (any checkIdentityHeader rule, or a present
 * null/non-string) is a 400 and prisma.project.create is never called.
 * Absent leaves the column to its default, '' passes through as the
 * clearing value, and a valid line is persisted. Generic custom-header
 * fields keep the shared contract: no identity-only rule is applied to
 * them, so this file also proves no general filter tightening rode along.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/projects/route.identityHeader.test.ts
 * @vitest-environment node
 */
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

describe('POST: a valid, empty or absent identity header creates', () => {
  test('valid line is persisted', async () => {
    const res = await POST(postReq({ ...base, engagementIdentityHeader: 'X-Bug-Bounty: researcher-7f3a' }))
    expect(res.status).toBeLessThan(400)
    expect(h.projectCreate).toHaveBeenCalledTimes(1)
    expect(createdData().engagementIdentityHeader).toBe('X-Bug-Bounty: researcher-7f3a')
  })

  test('empty string passes through as the clearing value', async () => {
    const res = await POST(postReq({ ...base, engagementIdentityHeader: '' }))
    expect(res.status).toBeLessThan(400)
    expect(h.projectCreate).toHaveBeenCalledTimes(1)
    expect(createdData().engagementIdentityHeader).toBe('')
  })

  test('omitted field leaves the column to its schema default (not written)', async () => {
    const res = await POST(postReq(base))
    expect(res.status).toBeLessThan(400)
    expect(h.projectCreate).toHaveBeenCalledTimes(1)
    expect(createdData()).not.toHaveProperty('engagementIdentityHeader')
  })
})

describe('POST: an invalid identity header never reaches the create', () => {
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
    const res = await POST(postReq({ ...base, engagementIdentityHeader: value }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/engagementIdentityHeader/)
    expect(h.projectCreate).not.toHaveBeenCalled()
  })

  test.each([null, 42, true, { name: 'X-BB' }, ['X-BB: v']])(
    'present non-string %j -> 400 and no create', async (value: unknown) => {
      const res = await POST(postReq({ ...base, engagementIdentityHeader: value }))
      expect(res.status).toBe(400)
      expect(h.projectCreate).not.toHaveBeenCalled()
    },
  )
})

describe('POST: generic custom headers keep the shared contract', () => {
  test('a framing header in a generic custom-header field is not identity-checked', async () => {
    const res = await POST(postReq({
      ...base,
      httpxCustomHeaders: ['Content-Length: 3', 'X-Redamon-Ctx: abc'],
    }))
    expect(res.status).toBeLessThan(400)
    expect(h.projectCreate).toHaveBeenCalledTimes(1)
    expect(createdData().httpxCustomHeaders).toEqual(['Content-Length: 3', 'X-Redamon-Ctx: abc'])
  })
})
