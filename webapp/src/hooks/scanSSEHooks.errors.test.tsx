/**
 * The GVM, GitHub Hunt, Supply-Chain and Secret Multiscanner log hooks are
 * clones whose `error` the logs drawer now shows. Two things must hold:
 * - a stream `error` event carries the orchestrator's raw exception text, which
 *   stays in the console; the drawer gets a fixed line;
 * - when the last reconnect fails, the route itself is asked why (EventSource
 *   never sees the HTTP status), so a 503 orchestrator_unreachable reads
 *   differently from a dropped connection.
 *
 * Run: npx vitest run src/hooks/scanSSEHooks.errors.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup, waitFor } from '@testing-library/react'

import { useGvmSSE } from './useGvmSSE'
import { useGithubHuntSSE } from './useGithubHuntSSE'
import { useSupplyChainSSE } from './useSupplyChainSSE'
import { useTrufflehogSSE } from './useTrufflehogSSE'
import { LOG_STREAM_EVENT_ERROR, LOG_STREAM_LOST, describeLogStreamLoss } from './logStreamError'

class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onerror: (() => void) | null = null
  onopen: (() => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  listeners: Record<string, (ev: MessageEvent) => void> = {}
  closed = false
  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }
  addEventListener(type: string, cb: (ev: MessageEvent) => void) {
    this.listeners[type] = cb
  }
  emit(type: string, data: unknown) {
    this.listeners[type]?.({ data: JSON.stringify(data) } as MessageEvent)
  }
  close() { this.closed = true }
}

const latest = () => MockEventSource.instances[MockEventSource.instances.length - 1]
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

beforeEach(() => {
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource as unknown as typeof EventSource)
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const HOOKS = [
  { name: 'GVM', url: '/api/gvm/p1/logs', fallback: 'Failed to connect to GVM log stream',
    use: () => useGvmSSE({ projectId: 'p1', enabled: true }) },
  { name: 'GitHub Hunt', url: '/api/github-hunt/p1/logs', fallback: 'Failed to connect to GitHub Hunt log stream',
    use: () => useGithubHuntSSE({ projectId: 'p1', enabled: true }) },
  { name: 'Supply-Chain', url: '/api/supply-chain/p1/logs', fallback: 'Failed to connect to Supply-Chain log stream',
    use: () => useSupplyChainSSE({ projectId: 'p1', enabled: true }) },
  { name: 'Secret Multiscanner', url: '/api/trufflehog/p1/github/logs', fallback: 'Failed to connect to Secret Multiscanner log stream',
    use: () => useTrufflehogSSE({ projectId: 'p1', source: 'github', enabled: true }) },
]

/** Fail the current stream and every reconnect until the hook gives up. */
async function exhaustReconnects() {
  for (let i = 0; i < 5; i++) {
    act(() => latest().onerror?.())
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
  }
  act(() => latest().onerror?.())
}

describe.each(HOOKS)('$name log stream', ({ url, fallback, use }) => {
  test('a stream error event shows a fixed line and keeps the raw text in the console', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { result } = renderHook(use)
    expect(latest().url).toBe(url)

    act(() => latest().emit('error', { error: '404 Client Error: No such container: redamon-scan-abc' }))
    expect(result.current.error).toBe(LOG_STREAM_EVENT_ERROR)
    expect(result.current.error).not.toContain('redamon-scan-abc')
    expect(consoleError).toHaveBeenCalledWith(expect.stringContaining('log stream error'), expect.stringContaining('redamon-scan-abc'))
  })

  test('giving up asks the route why: an unreachable orchestrator is named with its status', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn(async () => json(503, { error: fallback, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' }))
    vi.stubGlobal('fetch', fetchMock)
    const { result } = renderHook(use)

    await exhaustReconnects()
    await act(async () => { await vi.runOnlyPendingTimersAsync() })
    expect(fetchMock).toHaveBeenCalledWith(url, expect.objectContaining({ headers: { Accept: 'text/event-stream' } }))
    vi.useRealTimers()
    await waitFor(() => expect(result.current.error).toBe(`${fallback} (orchestrator_unreachable · HTTP 503)`))
  })

  test('giving up while the route answers 200 keeps "connection lost"', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 200, headers: { 'Content-Type': 'text/event-stream' } })))
    const { result } = renderHook(use)
    await exhaustReconnects()
    vi.useRealTimers()
    await waitFor(() => expect(result.current.error).toBe(LOG_STREAM_LOST))
  })
})

describe('describeLogStreamLoss', () => {
  test('a request with no answer is a network error, never a URL', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const text = await describeLogStreamLoss('/api/gvm/p1/logs', 'Failed to connect to GVM log stream')
    expect(text).toBe('Failed to connect to GVM log stream (network_error)')
  })

  test('a 404 "no scan" from the orchestrator keeps its own words and status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(404, {
      error: 'No GVM scan found for this project', code: 'orchestrator_error', upstreamStatus: 404,
    })))
    const text = await describeLogStreamLoss('/api/gvm/p1/logs', 'Failed to connect to GVM log stream')
    expect(text).toBe('No GVM scan found for this project (orchestrator_error · HTTP 404 · upstream HTTP 404)')
  })

  test('a stream that opens now is cancelled at once', async () => {
    let signal: AbortSignal | undefined
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      signal = init?.signal ?? undefined
      return new Response('', { status: 200 })
    }))
    expect(await describeLogStreamLoss('/api/gvm/p1/logs', 'x')).toBe(`${LOG_STREAM_LOST} (stream_interrupted)`)
    expect(signal?.aborted).toBe(true)
  })
})
