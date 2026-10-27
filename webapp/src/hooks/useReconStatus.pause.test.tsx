/**
 * Pausing a recon container goes through Docker's cgroup freeze, which can take
 * several seconds. The button has to react on click, not when the freeze lands,
 * so pauseRecon() flips the status to 'pausing' optimistically (same trick
 * stopRecon() uses for 'stopping') and status reads are ignored until the
 * request resolves.
 *
 * Run: npx vitest run src/hooks/useReconStatus.pause.test.tsx
 */

import { describe, test, expect, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'

import { useReconStatus } from './useReconStatus'
import type { ReconState } from '@/lib/recon-types'

const PROJECT_ID = 'proj-1'

function state(status: ReconState['status']): ReconState {
  return {
    project_id: PROJECT_ID,
    status,
    current_phase: 'Port Scanning',
    phase_number: 2,
    total_phases: 7,
    started_at: null,
    completed_at: null,
    error: null,
  } as ReconState
}

function jsonResponse(body: unknown) {
  return { ok: true, json: async () => body } as Response
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('useReconStatus pause transition', () => {
  test('flips to pausing on click and holds it until the freeze lands', async () => {
    let releasePause: (() => void) | null = null
    const pauseGate = new Promise<void>(resolve => { releasePause = resolve })

    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/pause')) {
        await pauseGate
        return jsonResponse(state('paused'))
      }
      return jsonResponse(state('running'))
    })
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch)

    const { result } = renderHook(() => useReconStatus({ projectId: PROJECT_ID }))
    await waitFor(() => expect(result.current.state?.status).toBe('running'))

    let pausePromise: Promise<ReconState | null> | undefined
    act(() => { pausePromise = result.current.pauseRecon() })

    // Immediately after the click, before the orchestrator answers.
    expect(result.current.state?.status).toBe('pausing')

    // A status read landing mid-freeze must not revert the button to 'running'.
    const statusCalls = () => fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/status')).length
    const before = statusCalls()
    await act(async () => { await result.current.refetch() })
    expect(statusCalls()).toBe(before)
    expect(result.current.state?.status).toBe('pausing')

    await act(async () => {
      releasePause?.()
      await pausePromise
    })

    expect(result.current.state?.status).toBe('paused')
  })

  test('a failed pause does not leave the button spinning forever', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/pause')) {
        return { ok: false, json: async () => ({ error: 'boom' }) } as Response
      }
      return jsonResponse(state('running'))
    })
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch)

    const { result } = renderHook(() => useReconStatus({ projectId: PROJECT_ID }))
    await waitFor(() => expect(result.current.state?.status).toBe('running'))

    await act(async () => { await result.current.pauseRecon() })
    expect(result.current.error).toBe('boom')

    // Status reads are unblocked again, so the next poll corrects the optimistic value.
    await act(async () => { await result.current.refetch() })
    expect(result.current.state?.status).toBe('running')
  })
})

describe('useReconStatus resume refusal (plan 12.5)', () => {
  // The orchestrator re-checks the RoE time window on resume: outside it the
  // answer is 403 with the same message a refused start gets, and the scan
  // stays paused. The page reads the message back to show it.
  const REFUSAL = 'RoE time window: current time 21:00 UTC is outside allowed window (09:00-18:00)'

  function stub(resume: Response) {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => (
      url.endsWith('/resume') ? resume : jsonResponse(state('paused'))
    )) as unknown as typeof fetch)
  }

  test('a refused resume resolves to null and keeps the refusal readable', async () => {
    stub({ ok: false, status: 403, json: async () => ({ error: REFUSAL }) } as Response)
    const { result } = renderHook(() => useReconStatus({ projectId: PROJECT_ID }))
    await waitFor(() => expect(result.current.state?.status).toBe('paused'))

    let answer: ReconState | null = state('running')
    await act(async () => { answer = await result.current.resumeRecon() })
    expect(answer).toBeNull()
    expect(result.current.getLastResumeError()).toBe(REFUSAL)
    expect(result.current.state?.status).toBe('paused')
  })

  test('a resume that goes through clears the last refusal', async () => {
    stub({ ok: false, status: 403, json: async () => ({ error: REFUSAL }) } as Response)
    const { result } = renderHook(() => useReconStatus({ projectId: PROJECT_ID }))
    await waitFor(() => expect(result.current.state?.status).toBe('paused'))
    await act(async () => { await result.current.resumeRecon() })

    stub(jsonResponse(state('running')))
    await act(async () => { await result.current.resumeRecon() })
    expect(result.current.getLastResumeError()).toBeNull()
    expect(result.current.state?.status).toBe('running')
  })
})
