/**
 * S2/E2 — POST /api/users write-bypass removal (mint-admin closure).
 *
 * Before: `if (!isInternalRequest(request))` let any X-Internal-Key holder
 * create users — including an admin (role from body). After: creating a user
 * requires an admin SESSION; key possession alone is rejected.
 *
 * Run: npx vitest run src/app/api/users/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockCreate = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { user: { findMany: vi.fn(), create: (...a: unknown[]) => mockCreate(...a) } },
}))
vi.mock('@/lib/session', () => ({
  getSession: (...a: unknown[]) => mockGetSession(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
}))
vi.mock('@/lib/auth', () => ({ hashPassword: async (p: string) => `hashed:${p}` }))

import { POST } from './route'

function postReq(body: unknown, headers: Record<string, string> = {}) {
  return new NextRequest('http://localhost/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

beforeEach(() => {
  mockCreate.mockReset()
  mockCreate.mockResolvedValue({ id: 'u1', name: 'x', email: 'x@y.z', role: 'admin' })
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
})

const NEW_ADMIN = { name: 'evil', email: 'evil@x.z', password: 'pw', role: 'admin' }

describe('POST /api/users — S2/E2 write-bypass removal', () => {
  test('EXPLOIT: internal key mints an admin → now 403, no write', async () => {
    mockIsInternal.mockReturnValue(true) // key present — but bypass is gone
    mockGetSession.mockResolvedValue(null)
    const res = await POST(postReq(NEW_ADMIN, { 'x-internal-key': 'the-key' }))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('standard-user session cannot create users → 403', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'u', role: 'standard' })
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('admin session CAN create a user → 201 (preserved)', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalled()
  })
})

describe('POST /api/users — a database failure', () => {
  test('answers its Prisma code beside the fixed sentence', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    mockCreate.mockRejectedValue(Object.assign(new Error('Timed out fetching a new connection'), { code: 'P2024' }))
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to create user', code: 'P2024' })
  })

  test('a duplicate email is still a 409 with its own sentence', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    mockCreate.mockRejectedValue(Object.assign(new Error('Unique constraint failed'), { code: 'P2002' }))
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(409)
    expect((await res.json()).error).toBe('A user with this email already exists')
  })
})
