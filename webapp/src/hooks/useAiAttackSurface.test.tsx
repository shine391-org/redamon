/**
 * Launch-flow tests for useAiAttackSurface (fetch + EventSource mocked).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { useAiAttackSurface } from './useAiAttackSurface'

afterEach(cleanup)

class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onerror: (() => void) | null = null
  onopen: (() => void) | null = null
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
  close() {
    this.closed = true
  }
}

function routedFetch(routes: Record<string, unknown>) {
  return vi.fn(async (url: string) => {
    const key = Object.keys(routes).find((k) => url.includes(k))
    const payload = key ? routes[key] : {}
    return { ok: true, json: async () => payload } as Response
  })
}

beforeEach(() => {
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource as unknown as typeof EventSource)
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('useAiAttackSurface', () => {
  test('loadTargets populates targets', async () => {
    vi.stubGlobal('fetch', routedFetch({ '/targets': { targets: [{ baseUrl: 'http://h', path: '/c' }] } }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => { await result.current.loadTargets() })
    expect(result.current.targets).toHaveLength(1)
  })

  test('launch posts to start, opens SSE, and records phase from log events', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/start': { run_id: 'r1', status: 'running', tool: 'garak' },
      '/status': { run_id: 'r1', status: 'running' },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))

    await act(async () => {
      await result.current.launch({
        tool: 'garak', targets: [{ baseurl: 'http://h', path: '/c' }],
        bounds: { trials: 1 }, roe_confirmed: true, probes: ['dan'],
      })
    })

    expect(result.current.run?.run_id).toBe('r1')
    // SSE opened against the run's log stream
    const es = MockEventSource.instances[0]
    expect(es.url).toContain('/api/ai-attack-surface/p1/r1/logs')

    // A phase-start log event advances the tracked phase
    act(() => { es.emit('log', { log: '[Phase 2] Target loading', phase: 'Target loading', phaseNumber: 2, isPhaseStart: true, level: 'info' }) })
    expect(result.current.phase).toEqual({ name: 'Target loading', num: 2 })
    expect(result.current.logs).toHaveLength(1)
  })

  test('reconnects to an in-flight run on mount (stateful across refresh)', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/all': { runs: [{ run_id: 'r9', status: 'running', tool: 'pyrit' }] },
      '/status': { run_id: 'r9', status: 'running' },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    // the mount effect fires reconnect() -> /all -> finds the running run
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })

    expect(result.current.run?.run_id).toBe('r9')          // status restored
    const es = MockEventSource.instances.find((e) => e.url.includes('/r9/logs'))
    expect(es).toBeTruthy()                                  // log stream re-attached
    // live logs resume after reconnect
    act(() => { es!.emit('log', { log: 'resumed', level: 'info' }) })
    expect(result.current.logs.map((l) => l.log)).toContain('resumed')
  })

  test('does NOT reconnect when there is no active run', async () => {
    vi.stubGlobal('fetch', routedFetch({ '/all': { runs: [{ run_id: 'old', status: 'completed' }] } }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(result.current.run).toBeNull()
    expect(MockEventSource.instances).toHaveLength(0)
  })

  test('stream onopen resets logs so a full-history replay does not duplicate', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/all': { runs: [{ run_id: 'r9', status: 'running', tool: 'garak' }] },
      '/status': { run_id: 'r9', status: 'running' },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    const es = MockEventSource.instances.find((e) => e.url.includes('/r9/logs'))!
    act(() => { es.emit('log', { log: 'stale', level: 'info' }) })   // pre-replay line
    expect(result.current.logs).toHaveLength(1)
    // server (re)opens the stream and replays from the start -> client resets
    act(() => { es.onopen?.() })
    expect(result.current.logs).toHaveLength(0)
    act(() => { es.emit('log', { log: 'fresh', level: 'info' }) })
    expect(result.current.logs.map((l) => l.log)).toEqual(['fresh'])
  })

  test('completion stops the stream and loads findings', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/start': { run_id: 'r1', status: 'running' },
      '/status': { run_id: 'r1', status: 'completed' },
      '/findings': { findings: [{ id: 'aiatk_1', source: 'garak' }] },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => {
      await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
    })
    // advance to trigger the 3s status poll -> sees completed -> loads findings.
    // advanceTimersByTimeAsync flushes the async fetch chain, so assert directly
    // (waitFor would hang under fake timers).
    await act(async () => { await vi.advanceTimersByTimeAsync(3500) })
    expect(result.current.findings).toHaveLength(1)
    expect(MockEventSource.instances[0].closed).toBe(true)
  })

  describe('failures keep their cause', () => {
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

    function failingFetch(routes: Record<string, () => Response | Promise<Response>>) {
      return vi.fn(async (url: string) => {
        const key = Object.keys(routes).find((k) => url.includes(k))
        return key ? routes[key]() : json(200, {})
      })
    }

    test('a failed target load is an error with code and status, not "no endpoints"', async () => {
      vi.stubGlobal('fetch', failingFetch({
        '/targets': () => json(500, { error: 'Failed to load the LLM endpoints', code: 'Neo.TransientError.General.DatabaseUnavailable', targets: [] }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => { await result.current.loadTargets() })
      expect(result.current.targetsError)
        .toBe('Failed to load the LLM endpoints (Neo.TransientError.General.DatabaseUnavailable · HTTP 500)')
      expect(result.current.targets).toEqual([])
    })

    test('a failed findings load keeps the findings already shown and says why', async () => {
      let fail = false
      vi.stubGlobal('fetch', failingFetch({
        '/findings': () => fail
          ? json(500, { error: 'Failed to load AI Gauntlet findings', code: 'Neo4jError', findings: [] })
          : json(200, { findings: [{ id: 'aiatk_1', source: 'garak' }] }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => { await result.current.loadFindings() })
      fail = true
      await act(async () => { await result.current.loadFindings() })
      expect(result.current.findings).toHaveLength(1)
      expect(result.current.findingsError).toBe('Failed to load AI Gauntlet findings (Neo4jError · HTTP 500)')
    })

    test('a launch refusal keeps its code and upstream status for the start modal', async () => {
      vi.stubGlobal('fetch', failingFetch({
        '/start': () => json(500, { error: 'Failed to start AI Gauntlet scan', code: 'orchestrator_error', upstreamStatus: 500 }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      let state: unknown
      await act(async () => {
        state = await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      expect(state).toBeNull()
      expect(result.current.getLastStartError()).toEqual({
        message: 'Failed to start AI Gauntlet scan', status: 500, code: 'orchestrator_error', upstreamStatus: 500,
      })
      expect(result.current.error).toBe('Failed to start AI Gauntlet scan (orchestrator_error · HTTP 500 · upstream HTTP 500)')
    })

    test('a launch that got no answer is a network error, not "Failed to fetch"', async () => {
      vi.stubGlobal('fetch', failingFetch({ '/start': () => { throw new TypeError('Failed to fetch') } }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => {
        await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      expect(result.current.getLastStartError()).toEqual({ message: 'Failed to launch', status: 0, code: 'network_error' })
      expect(result.current.error).toBe('Failed to launch (network_error)')
    })

    test('a failed stop keeps the run live, says why, and resumes the stream', async () => {
      vi.stubGlobal('fetch', failingFetch({
        '/start': () => json(200, { run_id: 'r1', status: 'running', tool: 'garak' }),
        '/stop': () => json(503, { error: 'Failed to stop AI Gauntlet scan', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' }),
        '/findings': () => json(200, { findings: [] }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => {
        await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      await act(async () => { await result.current.stop() })
      expect(result.current.run?.status).toBe('running')
      expect(result.current.error).toBe('Failed to stop AI Gauntlet scan (orchestrator_unreachable · HTTP 503)')
      const streams = MockEventSource.instances.filter((e) => e.url.includes('/r1/logs'))
      expect(streams).toHaveLength(2)
      expect(streams[0].closed).toBe(true)
      expect(streams[1].closed).toBe(false)
    })

    test('an orchestrator refusal of the stop is prefixed so it reads as the stop failing', async () => {
      vi.stubGlobal('fetch', failingFetch({
        '/start': () => json(200, { run_id: 'r1', status: 'running', tool: 'garak' }),
        '/stop': () => json(502, { error: 'Service not initialized', code: 'orchestrator_error', upstreamStatus: 503 }),
        '/findings': () => json(200, { findings: [] }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => {
        await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      await act(async () => { await result.current.stop() })
      expect(result.current.error)
        .toBe('Stop failed: Service not initialized (orchestrator_error · HTTP 502 · upstream HTTP 503)')
    })

    test('an unreachable status poll keeps the run and says the status is unavailable', async () => {
      vi.stubGlobal('fetch', failingFetch({
        '/start': () => json(200, { run_id: 'r1', status: 'running', tool: 'garak' }),
        '/status': () => json(503, { error: 'AI Gauntlet status unavailable', code: 'orchestrator_unreachable' }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => {
        await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      await act(async () => { await vi.advanceTimersByTimeAsync(3500) })
      expect(result.current.run?.status).toBe('running')
      expect(result.current.statusError).toBe('AI Gauntlet status unavailable (orchestrator_unreachable · HTTP 503)')
    })

    test('a run list the orchestrator could not give is "status unavailable", not "no run"', async () => {
      vi.stubGlobal('fetch', failingFetch({
        '/all': () => json(503, { error: 'AI Gauntlet runs unavailable', code: 'orchestrator_unreachable' }),
      }))
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => { await vi.advanceTimersByTimeAsync(0) })
      expect(result.current.run).toBeNull()
      expect(result.current.statusError).toBe('AI Gauntlet runs unavailable (orchestrator_unreachable · HTTP 503)')
    })

    test('a dropped log stream is reported, and the run is polled at once', async () => {
      const fetchMock = failingFetch({
        '/start': () => json(200, { run_id: 'r1', status: 'running', tool: 'garak' }),
        '/status': () => json(200, { run_id: 'r1', status: 'running' }),
      })
      vi.stubGlobal('fetch', fetchMock)
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => {
        await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      const polls = () => fetchMock.mock.calls.filter(([u]) => String(u).includes('/status')).length
      expect(polls()).toBe(0)
      await act(async () => { MockEventSource.instances[0].onerror?.() })
      expect(result.current.streamError).toBe('Log stream lost')
      expect(polls()).toBe(1)
    })

    test('an orchestrator stream error is reported without its raw text', async () => {
      vi.stubGlobal('fetch', failingFetch({ '/start': () => json(200, { run_id: 'r1', status: 'running' }) }))
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const { result } = renderHook(() => useAiAttackSurface('p1'))
      await act(async () => {
        await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
      })
      act(() => { MockEventSource.instances[0].emit('error', { error: 'docker.errors.APIError: 500 Server Error' }) })
      spy.mockRestore()
      expect(result.current.streamError).toMatch(/^Log stream lost/)
      expect(result.current.streamError).not.toContain('docker')
    })
  })
})
