/**
 * A partial recon's log stream that drops is announced while it is retried,
 * and once it cannot be reopened the error says why (the endpoint is asked
 * once with fetch, since EventSource hides the HTTP status).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { useMultiPartialReconSSE } from './useMultiPartialReconSSE'
import { STREAM_EVENT_ERROR } from './useReconSSE'

class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onerror: (() => void) | null = null
  onopen: (() => void) | null = null
  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }
  listeners: Record<string, (ev: MessageEvent) => void> = {}
  addEventListener(type: string, cb: (ev: MessageEvent) => void) { this.listeners[type] = cb }
  close() {}
}

const stream = () => MockEventSource.instances[MockEventSource.instances.length - 1]

beforeEach(() => {
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource as unknown as typeof EventSource)
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('useMultiPartialReconSSE', () => {
  test('retries are announced and cleared on reopen', () => {
    const { result } = renderHook(() => useMultiPartialReconSSE({ projectId: 'p1', activeRunId: 'r1' }))
    act(() => { stream().onerror?.() })
    expect(result.current.error).toBe('Log stream disconnected; reconnecting (attempt 1 of 5)')
    act(() => { stream().onopen?.() })
    expect(result.current.error).toBeNull()
  })

  test('a stream that cannot be reopened carries the probed code and status', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn(async () => new Response(
      JSON.stringify({ error: 'Failed to connect to partial recon log stream', code: 'orchestrator_timeout' }),
      { status: 504 },
    ))
    vi.stubGlobal('fetch', fetchMock)
    const { result } = renderHook(() => useMultiPartialReconSSE({ projectId: 'p1', activeRunId: 'r1' }))
    act(() => { stream().onerror?.() })
    for (let i = 0; i < 5; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
      act(() => { stream().onerror?.() })
    }
    await act(async () => { await vi.runOnlyPendingTimersAsync() })
    expect(fetchMock).toHaveBeenCalledWith('/api/recon/p1/partial/r1/logs', expect.anything())
    expect(result.current.error).toBe('Failed to connect to partial recon log stream (orchestrator_timeout · HTTP 504)')
  })

  test("the stream's own error event shows a fixed line, not the exception text", () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { result } = renderHook(() => useMultiPartialReconSSE({ projectId: 'p1', activeRunId: 'r1' }))
    act(() => stream().listeners.error?.({ data: JSON.stringify({ error: 'No such container: partial-r1' }) } as MessageEvent))
    expect(result.current.error).toBe(STREAM_EVENT_ERROR)
    expect(consoleError).toHaveBeenCalledWith('Partial recon log stream error event:', 'No such container: partial-r1')
    consoleError.mockRestore()
  })
})
