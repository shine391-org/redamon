/**
 * A partial-recon stop is asynchronous (plan 12.3): the orchestrator answers
 * `stopping` while the run lands its graph writes and applies the mute rules,
 * so the hook keeps the run listed as stopping until a poll finds it gone.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, act, cleanup, waitFor } from '@testing-library/react'
import { useMultiPartialReconStatus } from './useMultiPartialReconStatus'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const run = (status: string) => ({ project_id: 'p1', run_id: 'r1', tool_id: 'Naabu', status })

function stubFetch(stopAnswer: Record<string, unknown>, listed: Array<Record<string, unknown>>) {
  const fetchMock = vi.fn(async (url: string) => {
    const body = String(url).endsWith('/stop') ? stopAnswer : { project_id: 'p1', runs: listed }
    return { ok: true, json: async () => body } as Response
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('stopPartialRecon', () => {
  test('a run answered `stopping` stays listed as stopping', async () => {
    stubFetch(run('stopping'), [run('running')])
    const { result } = renderHook(() => useMultiPartialReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.runs).toHaveLength(1))
    await act(async () => { await result.current.stopPartialRecon('r1') })
    expect(result.current.runs.map(r => r.status)).toEqual(['stopping'])
    expect(result.current.activeRuns).toHaveLength(1)
  })

  test('a run answered idle leaves the list', async () => {
    stubFetch(run('idle'), [run('running')])
    const { result } = renderHook(() => useMultiPartialReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.runs).toHaveLength(1))
    await act(async () => { await result.current.stopPartialRecon('r1') })
    expect(result.current.runs).toEqual([])
  })
})

describe('failures carry their cause', () => {
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

  test('a refused stop is still readable after the refetch that reverts the optimistic state', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => (
      String(url).endsWith('/stop')
        ? json(503, { error: 'Failed to stop partial recon', code: 'orchestrator_unreachable' })
        : json(200, { project_id: 'p1', runs: [run('running')] })
    )))
    const { result } = renderHook(() => useMultiPartialReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.runs).toHaveLength(1))
    let answer: unknown = 'not called'
    await act(async () => { answer = await result.current.stopPartialRecon('r1') })
    expect(answer).toBeNull()
    expect(result.current.runs.map(r => r.status)).toEqual(['running'])
    expect(result.current.error).toBe('Failed to stop partial recon (orchestrator_unreachable · HTTP 503)')
  })

  test('an unavailable list keeps the runs already shown', async () => {
    let down = false
    vi.stubGlobal('fetch', vi.fn(async () => (down
      ? json(503, { error: 'Partial recon list unavailable', code: 'orchestrator_unreachable' })
      : json(200, { project_id: 'p1', runs: [run('running')] }))))
    const { result } = renderHook(() => useMultiPartialReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.runs).toHaveLength(1))
    down = true
    await act(async () => { await result.current.refetch() })
    expect(result.current.runs).toHaveLength(1)
    expect(result.current.error).toBe('Partial recon list unavailable (orchestrator_unreachable · HTTP 503)')
  })

  test('a refused start keeps its code for the start-failure modal', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => (
      init?.method === 'POST' && String(url).endsWith('/partial')
        ? json(504, { error: 'unknown whether it started', code: 'orchestrator_timeout', startOutcome: 'unknown' })
        : json(200, { project_id: 'p1', runs: [] })
    )))
    const { result } = renderHook(() => useMultiPartialReconStatus({ projectId: 'p1' }))
    await act(async () => { await result.current.startPartialRecon({ tool_id: 'Naabu' } as never) })
    expect(result.current.getLastStartError()).toEqual({
      message: 'unknown whether it started', status: 504, code: 'orchestrator_timeout',
    })
    expect(result.current.error).toBe('unknown whether it started (orchestrator_timeout · HTTP 504)')
  })
})
