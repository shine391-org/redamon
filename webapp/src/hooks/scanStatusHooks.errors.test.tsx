/**
 * The GVM, GitHub Hunt and Supply-Chain status hooks are clones, and each one is
 * what the graph toolbar, the Other Scans modal and the project form show for a
 * failed status read, start, pause, resume or stop. Every failure must carry
 * the code and HTTP status the route sent, and a failed status read keeps the
 * last known state: an orchestrator that did not answer says nothing about
 * whether the scan is still running, and "idle" would enable Start over it.
 *
 * Run: npx vitest run src/hooks/scanStatusHooks.errors.test.tsx
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'

import { useGvmStatus } from './useGvmStatus'
import { useGithubHuntStatus } from './useGithubHuntStatus'
import { useSupplyChainStatus } from './useSupplyChainStatus'
import { ApiError } from '@/lib/apiError'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const html = (status: number) => new Response('<!DOCTYPE html><html>Bad Gateway</html>', { status })

const running = {
  project_id: 'p1', status: 'running', current_phase: null, phase_number: null,
  total_phases: 4, started_at: null, completed_at: null, error: null,
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function stub(handler: (url: string) => Promise<Response> | Response) {
  const fetchMock = vi.fn(async (url: string) => handler(String(url)))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

type Action = () => Promise<unknown>
interface Bundle {
  state: { status: string } | null
  error: string | null
  statusError: string | null
  startError: string | null
  refetch: () => Promise<void>
  start: Action
  stop: Action
  pause: Action
  resume: Action
  getLastStartError: () => { message: string; status?: number; code?: string; upstreamStatus?: number } | null
  getLastActionError: () => string | null
}

const HOOKS = [
  {
    name: 'GVM', seg: 'gvm', statusReason: 'GVM status unavailable', startReason: 'Failed to start GVM scan',
    stopReason: 'Failed to stop GVM scan', startThrows: false,
    use: () => {
      const h = useGvmStatus({ projectId: 'p1' })
      return { ...h, start: h.startGvm, stop: h.stopGvm, pause: h.pauseGvm, resume: h.resumeGvm } as unknown as Bundle
    },
  },
  {
    name: 'GitHub Hunt', seg: 'github-hunt', statusReason: 'GitHub Hunt status unavailable',
    startReason: 'Failed to start GitHub Secret Hunt', stopReason: 'Failed to stop GitHub Secret Hunt', startThrows: true,
    use: () => {
      const h = useGithubHuntStatus({ projectId: 'p1' })
      return { ...h, start: h.startGithubHunt, stop: h.stopGithubHunt, pause: h.pauseGithubHunt, resume: h.resumeGithubHunt } as unknown as Bundle
    },
  },
  {
    name: 'Supply-Chain', seg: 'supply-chain', statusReason: 'Supply-Chain status unavailable',
    startReason: 'Failed to start Supply-Chain scan', stopReason: 'Failed to stop Supply-Chain scan', startThrows: true,
    use: () => {
      const h = useSupplyChainStatus({ projectId: 'p1' })
      return { ...h, start: h.startSupplyChain, stop: h.stopSupplyChain, pause: h.pauseSupplyChain, resume: h.resumeSupplyChain } as unknown as Bundle
    },
  },
]

/** Runs a start and returns what it threw (two hooks rethrow), or null. */
async function attempt(call: Action): Promise<unknown> {
  try {
    await call()
    return null
  } catch (err) {
    return err
  }
}

describe.each(HOOKS)('$name status hook', ({ seg, statusReason, startReason, stopReason, startThrows, use }) => {
  test('an unreachable orchestrator keeps the last state and says why', async () => {
    let down = false
    stub(() => (down
      ? json(503, { error: statusReason, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
      : json(200, running)))
    const { result } = renderHook(use)
    await waitFor(() => expect(result.current.state?.status).toBe('running'))

    down = true
    await act(async () => { await result.current.refetch() })
    expect(result.current.state?.status).toBe('running')
    expect(result.current.statusError).toBe(`${statusReason} (orchestrator_unreachable · HTTP 503)`)
    expect(result.current.error).toBe(result.current.statusError)

    down = false
    await act(async () => { await result.current.refetch() })
    expect(result.current.statusError).toBeNull()
  })

  test('a proxy error page is read as non-JSON with its status, not a SyntaxError', async () => {
    stub(() => html(502))
    const { result } = renderHook(use)
    await waitFor(() => expect(result.current.statusError).toBe(`${statusReason} (non_json_response · HTTP 502)`))
    expect(result.current.state).toBeNull()
  })

  test('a start refused with a non-JSON body keeps the status and says so', async () => {
    stub(url => (url.endsWith('/start') ? html(502) : json(200, { ...running, status: 'idle' })))
    const { result } = renderHook(use)
    let thrown: unknown
    await act(async () => { thrown = await attempt(result.current.start) })

    expect(result.current.getLastStartError()).toEqual({ message: startReason, status: 502, code: 'non_json_response' })
    expect(result.current.startError).toBe(`${startReason} (non_json_response · HTTP 502)`)
    if (startThrows) {
      expect(thrown).toBeInstanceOf(ApiError)
      expect((thrown as ApiError).message).toBe(`${startReason} (non_json_response · HTTP 502)`)
    } else {
      expect(thrown).toBeNull()
    }
  })

  test('a start refusal keeps the route code, upstream status and limit', async () => {
    const limit = { limitType: 'ram', detail: 'Not enough memory' }
    stub(url => (url.endsWith('/start')
      ? json(409, { error: 'Not enough memory. This is a RAM limit', code: 'orchestrator_error', upstreamStatus: 409, limit })
      : json(200, { ...running, status: 'idle' })))
    const { result } = renderHook(use)
    await act(async () => { await attempt(result.current.start) })
    expect(result.current.getLastStartError()).toEqual({
      message: 'Not enough memory. This is a RAM limit', status: 409, code: 'orchestrator_error', upstreamStatus: 409, limit,
    })
  })

  test('a start that got no answer is a network error with status 0', async () => {
    stub(url => {
      if (url.endsWith('/start')) throw new TypeError('Failed to fetch')
      return json(200, { ...running, status: 'idle' })
    })
    const { result } = renderHook(use)
    await act(async () => { await attempt(result.current.start) })
    expect(result.current.getLastStartError()).toEqual({ message: startReason, status: 0, code: 'network_error' })
    expect(result.current.startError).toBe(`${startReason} (network_error)`)
  })

  test('a failed stop resolves to null and keeps its reason for the caller', async () => {
    stub(url => (url.endsWith('/stop')
      ? json(502, { error: 'No running scan for this project', code: 'orchestrator_error', upstreamStatus: 500 })
      : json(200, running)))
    const { result } = renderHook(use)
    await waitFor(() => expect(result.current.state?.status).toBe('running'))

    let answer: unknown = 'unset'
    await act(async () => { answer = await result.current.stop() })
    expect(answer).toBeNull()
    expect(result.current.getLastActionError())
      .toBe('No running scan for this project (orchestrator_error · HTTP 502 · upstream HTTP 500)')
    expect(result.current.error).toBe(result.current.getLastActionError())
    // A failed stop is not a failed status read.
    expect(result.current.statusError).toBeNull()
  })

  test('a stop that got no answer names the action, not "Unknown error"', async () => {
    stub(url => {
      if (url.endsWith('/stop')) throw new TypeError('Failed to fetch')
      return json(200, running)
    })
    const { result } = renderHook(use)
    await waitFor(() => expect(result.current.state?.status).toBe('running'))
    await act(async () => { await result.current.stop() })
    expect(result.current.getLastActionError()).toBe(`${stopReason} (network_error)`)
  })

  test('a successful pause clears the previous action error', async () => {
    let fail = true
    stub(url => {
      if (url.endsWith('/pause')) return fail ? json(503, { error: 'x', code: 'orchestrator_unreachable' }) : json(200, { ...running, status: 'paused' })
      return json(200, running)
    })
    const { result } = renderHook(use)
    await waitFor(() => expect(result.current.state?.status).toBe('running'))
    await act(async () => { await result.current.pause() })
    expect(result.current.getLastActionError()).toBe('x (orchestrator_unreachable · HTTP 503)')

    fail = false
    await act(async () => { await result.current.pause() })
    expect(result.current.getLastActionError()).toBeNull()
  })

  test(`polls /api/${seg}/status`, async () => {
    const fetchMock = stub(() => json(200, running))
    renderHook(use)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/${seg}/p1/status`))
  })
})
