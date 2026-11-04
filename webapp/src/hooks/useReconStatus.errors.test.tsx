/**
 * The recon status hook's `error` is what the graph page shows when a status
 * read or a stop/pause/resume fails, so it must carry the code and HTTP status
 * the route sent. A failed status read keeps the last known state: an
 * unanswered poll says nothing about the scan, and showing "idle" would enable
 * Start over a recon that may be running.
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'

import { useReconStatus } from './useReconStatus'
import type { ReconState } from '@/lib/recon-types'

const running = { project_id: 'p1', status: 'running', current_phase: null, phase_number: null,
  total_phases: 6, started_at: null, completed_at: null, error: null } as unknown as ReconState

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function stub(handler: (url: string) => Promise<Response> | Response) {
  const fetchMock = vi.fn(async (url: string) => handler(String(url)))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('status reads', () => {
  test('an unavailable orchestrator keeps the last state and says why', async () => {
    let down = false
    stub(() => (down
      ? json(503, { error: 'Recon status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
      : json(200, running)))
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.state?.status).toBe('running'))

    down = true
    await act(async () => { await result.current.refetch() })
    expect(result.current.state?.status).toBe('running')
    expect(result.current.error).toBe('Recon status unavailable (orchestrator_unreachable · HTTP 503)')
  })

  test('a read that got no answer at all is a network error, not idle', async () => {
    stub(() => { throw new TypeError('Failed to fetch') })
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.error).toBe('Recon status unavailable (network_error)'))
    expect(result.current.state).toBeNull()
  })
})

describe('actions', () => {
  test('a failed stop says why and still resolves to null', async () => {
    stub(url => (url.endsWith('/stop')
      ? json(503, { error: 'Failed to stop recon', code: 'orchestrator_unreachable' })
      : json(200, running)))
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.state?.status).toBe('running'))
    let answer: ReconState | null = running
    await act(async () => { answer = await result.current.stopRecon() })
    expect(answer).toBeNull()
    expect(result.current.error).toBe('Failed to stop recon (orchestrator_unreachable · HTTP 503)')
  })

  test('a pause answered by a proxy error page carries its status', async () => {
    stub(url => (url.endsWith('/pause')
      ? new Response('<html>Bad Gateway</html>', { status: 502 })
      : json(200, running)))
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.state?.status).toBe('running'))
    await act(async () => { await result.current.pauseRecon() })
    expect(result.current.error).toBe('Failed to pause recon (non_json_response · HTTP 502)')
  })

  test('a resume the orchestrator never got is not read as a policy refusal', async () => {
    stub(url => (url.endsWith('/resume')
      ? json(503, { error: 'Failed to resume recon', code: 'orchestrator_unreachable' })
      : json(200, { ...running, status: 'paused' })))
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.state?.status).toBe('paused'))
    await act(async () => { await result.current.resumeRecon() })
    expect(result.current.getLastResumeError()).toBe('Failed to resume recon (orchestrator_unreachable · HTTP 503)')
  })
})

describe('a refused start', () => {
  test('keeps the code, the status and the upstream status for the start-failure modal', async () => {
    stub(url => (url.endsWith('/start')
      ? json(500, { error: 'Failed to start recon', upstreamStatus: 500, scanJobId: 'job1' })
      : json(200, { ...running, status: 'idle' })))
    const onError = vi.fn()
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1', onError }))
    await waitFor(() => expect(result.current.state?.status).toBe('idle'))
    await act(async () => { await result.current.startRecon() })
    expect(result.current.getLastStartError()).toEqual({ message: 'Failed to start recon', status: 500, upstreamStatus: 500 })
    expect(result.current.error).toBe('Failed to start recon (HTTP 500 · upstream HTTP 500)')
    expect(onError).toHaveBeenCalledWith('Failed to start recon (HTTP 500 · upstream HTTP 500)')
  })

  test('an outcome-unknown timeout reaches the modal with its code', async () => {
    stub(url => (url.endsWith('/start')
      ? json(504, {
          error: 'The orchestrator did not answer, so it is unknown whether the scan started.',
          code: 'orchestrator_timeout', startOutcome: 'unknown',
        })
      : json(200, { ...running, status: 'idle' })))
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.state?.status).toBe('idle'))
    await act(async () => { await result.current.startRecon() })
    expect(result.current.getLastStartError()).toMatchObject({ code: 'orchestrator_timeout', status: 504 })
  })

  test('a start that got no answer is a network error with status 0', async () => {
    stub(url => {
      if (url.endsWith('/start')) throw new TypeError('Failed to fetch')
      return json(200, { ...running, status: 'idle' })
    })
    const { result } = renderHook(() => useReconStatus({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.state?.status).toBe('idle'))
    await act(async () => { await result.current.startRecon() })
    expect(result.current.getLastStartError()).toEqual({ message: 'Failed to start recon', status: 0, code: 'network_error' })
    expect(result.current.error).toBe('Failed to start recon (network_error)')
  })
})
