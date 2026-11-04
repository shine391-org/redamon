/**
 * Following an apply run until it ends.
 *
 * Run: npx vitest run src/app/graph/components/NodeFilters/useApplyRun.test.ts
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useApplyRun, POLL_MS } from './useApplyRun'

const answer = (status: number, body: unknown = {}) =>
  Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })

beforeEach(() => { vi.useFakeTimers() })
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('useApplyRun', () => {
  test('run_poll_never_stops_on_error: a run that is gone stops the polling and frees the page', async () => {
    // A deleted project (or a run id that is not this project's) answers 404
    // for good. Polling on meant Save, Apply and the mode stayed locked until
    // a reload.
    const fetchMock = vi.fn(() => answer(404, { error: 'Not found' }))
    vi.stubGlobal('fetch', fetchMock)
    const { result } = renderHook(() => useApplyRun('p1', 'run1', vi.fn()))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(result.current.running).toBe(false)
    const calls = fetchMock.mock.calls.length
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS * 5) })
    expect(fetchMock.mock.calls.length).toBe(calls)
  })

  test('a server error is a blip: it keeps following the run', async () => {
    const answers = [answer(502), answer(200, { id: 'run1', status: 'completed' })]
    vi.stubGlobal('fetch', vi.fn(() => answers.shift() ?? answer(200, { status: 'completed' })))
    const onFinished = vi.fn()
    const { result } = renderHook(() => useApplyRun('p1', 'run1', onFinished))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(result.current.running).toBe(true)
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS) })
    expect(result.current.running).toBe(false)
    expect(onFinished).toHaveBeenCalledWith({ id: 'run1', status: 'completed' })
  })
})

describe('useApplyRun: a refused apply', () => {
  test("throws the agent's sentence with the code and both statuses", async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify({
      error: 'this run is already being applied', code: 'agent_error', upstreamStatus: 409,
    }), { status: 409 }))))
    const { result } = renderHook(() => useApplyRun('p1', null, vi.fn()))
    await expect(result.current.apply('current', 3, 'v7')).rejects.toThrow(
      'this run is already being applied (agent_error · HTTP 409 · upstream HTTP 409)')
  })

  test("a proxy's error page is read with its status", async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('<html>502</html>', { status: 502 }))))
    const { result } = renderHook(() => useApplyRun('p1', null, vi.fn()))
    await expect(result.current.apply('current', 3, 'v7')).rejects.toThrow('Apply failed (non_json_response · HTTP 502)')
  })
})
