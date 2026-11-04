/**
 * Graph views say why a call failed (G-13, G-25, G-26, P-27).
 *
 * Save and delete answered only null / false and logged the cause to the
 * console, so the button just stopped spinning; a failed execute or generate
 * read `data.error` from a body that might not be JSON, and never the status.
 *
 * Run: npx vitest run src/app/graph/hooks/useGraphViews.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import { useGraphViews } from './useGraphViews'

const fetchMock = vi.fn()

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

beforeEach(() => {
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string) => (url.startsWith('/api/graph-views?') ? json(200, []) : json(200, {})))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function mounted() {
  const hook = renderHook(() => useGraphViews('p1'))
  await waitFor(() => expect(hook.result.current.isLoading).toBe(false))
  return hook
}

describe('useGraphViews failures', () => {
  test('a refused save keeps null but records why', async () => {
    const { result } = await mounted()
    fetchMock.mockResolvedValueOnce(json(400, { error: 'name is required' }))
    let view: unknown
    await act(async () => { view = await result.current.createView('', '', 'MATCH (n) RETURN n') })
    expect(view).toBeNull()
    expect(result.current.actionError).toBe('name is required (HTTP 400)')
  })

  test('a refused delete keeps false but records why', async () => {
    const { result } = await mounted()
    fetchMock.mockResolvedValueOnce(json(500, { error: 'Failed to delete graph view', code: 'P1001' }))
    let ok: unknown
    await act(async () => { ok = await result.current.deleteView('v1') })
    expect(ok).toBe(false)
    expect(result.current.actionError).toBe('Failed to delete graph view (P1001 · HTTP 500)')
  })

  test('a failed execute answers the route text with its code and status', async () => {
    const { result } = await mounted()
    fetchMock.mockResolvedValueOnce(json(400, { error: 'Write operations are not allowed in data filters' }))
    const out = await result.current.executeCypher('MATCH (n) DELETE n')
    expect(out).toEqual({ error: 'Write operations are not allowed in data filters (HTTP 400)', status: 400 })
  })

  test('a non-JSON execute failure still names its status', async () => {
    const { result } = await mounted()
    fetchMock.mockResolvedValueOnce(new Response('<html>502</html>', { status: 502 }))
    const out = await result.current.executeCypher('MATCH (n) RETURN n')
    expect(out).toEqual({ error: 'Failed to execute query (non_json_response · HTTP 502)', status: 502,
      code: 'non_json_response' })
  })

  test('a failed generate carries the agent sentence and the provider facts', async () => {
    const { result } = await mounted()
    fetchMock.mockResolvedValueOnce(json(502, {
      error: 'The AI model call failed. Try again in a moment.', code: 'model_call_failed',
      upstreamStatus: 502, errorClass: 'RateLimitError', providerStatus: 429,
    }))
    const out = await result.current.generateCypher('q', 'u1')
    expect('error' in out && out.error).toBe(
      'The AI model call failed. Try again in a moment. (model_call_failed · HTTP 502 · upstream HTTP 502) ' +
      '[RateLimitError · provider HTTP 429]')
  })

  test('no answer at all is a network error', async () => {
    const { result } = await mounted()
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    const out = await result.current.executeCypher('MATCH (n) RETURN n')
    expect(out).toEqual({ error: 'Failed to execute query (network_error)', status: 0, code: 'network_error' })
  })
})
