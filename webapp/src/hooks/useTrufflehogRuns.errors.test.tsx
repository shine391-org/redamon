/**
 * useTrufflehogRuns feeds the Secret Multiscanner rows of Other Scans. A failed
 * run poll must keep the runs on screen (an unanswered poll says nothing about
 * them), a failed source list must not read as "no sources configured", and a
 * start or stop that failed must say why with its code and status.
 *
 * Run: npx vitest run src/hooks/useTrufflehogRuns.errors.test.tsx
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'

import { useTrufflehogRuns } from './useTrufflehogRuns'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const run = { run_id: 'r1', project_id: 'p1', source: 'github', status: 'running', error: null }
const profile = { id: 'pr1', source: 'github', label: 'GitHub', config: {} }

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function stub(handler: (url: string, init?: RequestInit) => Promise<Response> | Response) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => handler(String(url), init))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('useTrufflehogRuns failures', () => {
  test('an unreachable orchestrator keeps the runs and says why', async () => {
    let down = false
    stub(url => {
      if (url.endsWith('/profiles')) return json(200, { profiles: [profile] })
      return down
        ? json(503, { error: 'Secret Multiscanner status unavailable', code: 'orchestrator_unreachable' })
        : json(200, { runs: [run] })
    })
    const { result } = renderHook(() => useTrufflehogRuns({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.runs).toHaveLength(1))

    down = true
    await act(async () => { await result.current.refetch() })
    expect(result.current.runs).toHaveLength(1)
    expect(result.current.isAnyRunning).toBe(true)
    expect(result.current.statusError).toBe('Secret Multiscanner status unavailable (orchestrator_unreachable · HTTP 503)')
  })

  test('a failed source list is an error, not an empty list', async () => {
    stub(url => (url.endsWith('/profiles')
      ? json(500, { error: 'Failed to list sources', code: 'P1001' })
      : json(200, { runs: [] })))
    const { result } = renderHook(() => useTrufflehogRuns({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.profilesError).toBe('Failed to list sources (P1001 · HTTP 500)'))
    expect(result.current.profiles).toEqual([])
  })

  test('a source list that loads again clears the error and keeps nothing stale', async () => {
    let fail = true
    stub(url => (url.endsWith('/profiles')
      ? (fail ? json(500, { error: 'Failed to list sources', code: 'P1001' }) : json(200, { profiles: [profile] }))
      : json(200, { runs: [] })))
    const { result } = renderHook(() => useTrufflehogRuns({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.profilesError).not.toBeNull())
    fail = false
    await act(async () => { await result.current.refetchProfiles() })
    expect(result.current.profilesError).toBeNull()
    expect(result.current.profiles).toHaveLength(1)
  })

  test('a start that got no answer is recorded as a network error (it used to be lost)', async () => {
    stub(url => {
      if (url.endsWith('/start')) throw new TypeError('Failed to fetch')
      if (url.endsWith('/profiles')) return json(200, { profiles: [profile] })
      return json(200, { runs: [] })
    })
    const { result } = renderHook(() => useTrufflehogRuns({ projectId: 'p1' }))
    // The mount poll succeeding mid-start would clear `error`; let it land first.
    await waitFor(() => expect(result.current.profiles).toHaveLength(1))
    let answer: unknown = 'unset'
    await act(async () => { answer = await result.current.startTrufflehog('github') })
    expect(answer).toBeNull()
    expect(result.current.getLastStartError()).toEqual({
      message: 'Failed to start Secret Multiscanner scan', status: 0, code: 'network_error',
    })
    expect(result.current.error).toBe('Failed to start Secret Multiscanner scan (network_error)')
  })

  test('a start refusal keeps code, upstream status and the governor limit', async () => {
    const limit = { limitType: 'hard', detail: 'Limit reached' }
    stub(url => {
      if (url.endsWith('/start')) return json(409, { error: 'Limit reached', code: 'orchestrator_error', upstreamStatus: 409, limit })
      if (url.endsWith('/profiles')) return json(200, { profiles: [profile] })
      return json(200, { runs: [] })
    })
    const { result } = renderHook(() => useTrufflehogRuns({ projectId: 'p1' }))
    await act(async () => { await result.current.startTrufflehog('github') })
    expect(result.current.getLastStartError()).toEqual({
      message: 'Limit reached', status: 409, code: 'orchestrator_error', upstreamStatus: 409, limit,
    })
  })

  test('a failed stop resolves to null and keeps its reason', async () => {
    stub(url => {
      if (url.endsWith('/stop')) return new Response('Internal Server Error', { status: 500 })
      if (url.endsWith('/profiles')) return json(200, { profiles: [profile] })
      return json(200, { runs: [run] })
    })
    const { result } = renderHook(() => useTrufflehogRuns({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.runs).toHaveLength(1))
    let answer: unknown = 'unset'
    await act(async () => { answer = await result.current.stopTrufflehog('github') })
    expect(answer).toBeNull()
    expect(result.current.getLastActionError())
      .toBe('Failed to stop Secret Multiscanner scan (non_json_response · HTTP 500)')
  })
})
