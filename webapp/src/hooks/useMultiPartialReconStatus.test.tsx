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
