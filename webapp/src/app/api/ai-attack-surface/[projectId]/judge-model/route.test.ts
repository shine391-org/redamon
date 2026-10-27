/**
 * drift-map #16: the judge model comes from the orchestrator's /local-llm/status
 * (LOCAL_LLM_MODEL), behind the project guard, and only its name leaves the route.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextResponse } from 'next/server'

const guardProject = vi.fn()
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => guardProject(...a) }))

import { GET } from './route'

const fetchMock = vi.fn()
const call = () => GET({} as never, { params: Promise.resolve({ projectId: 'proj1' }) } as never)

const STATUS = {
  available: true, running: true, containerId: 'c0ffee', baseUrl: 'http://127.0.0.1:11434',
  model: 'judge-under-test:7b', modelPresent: true, leases: 0, models: ['judge-under-test:7b'], warning: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  guardProject.mockResolvedValue(null)
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockResolvedValue(new Response(JSON.stringify(STATUS), { status: 200 }))
})
afterEach(() => vi.unstubAllGlobals())

describe('GET judge-model', () => {
  test('returns the orchestrator\'s model, and nothing else from its status', async () => {
    const res = await call()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ model: 'judge-under-test:7b' })
  })

  test('asks the orchestrator\'s status route with the orchestrator key', async () => {
    await call()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toMatch(/\/local-llm\/status$/)
    expect((init.headers as Record<string, string>)['X-Orchestrator-Key']).toBeTruthy()
    expect(init.method ?? 'GET').toBe('GET')
  })

  test('the project guard runs first; a denied caller reaches no orchestrator', async () => {
    guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await call()
    expect(res.status).toBe(404)
    expect(guardProject).toHaveBeenCalledWith('proj1')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test.each([
    ['the orchestrator answers 503', () => new Response('{"detail":"Local LLM manager not initialized"}', { status: 503 })],
    ['the status has no model', () => new Response(JSON.stringify({ ...STATUS, model: '' }), { status: 200 })],
  ])('503 with no model when %s', async (_name, reply) => {
    fetchMock.mockResolvedValue(reply())
    const res = await call()
    expect(res.status).toBe(503)
    expect((await res.json()).model).toBeNull()
  })

  test('503 with no model when the orchestrator is down', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed'))
    const res = await call()
    expect(res.status).toBe(503)
    expect((await res.json()).model).toBeNull()
  })
})
