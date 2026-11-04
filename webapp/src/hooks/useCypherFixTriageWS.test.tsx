/**
 * The triage socket's terminal states and the publishing refusal.
 *
 * Run: npx vitest run src/hooks/useCypherFixTriageWS.test.tsx
 *
 * Two defects pinned here:
 *  - U4: a `stopped` message set the status back to `connected`, so nothing
 *    downstream could tell a stopped run from an idle socket: the board never
 *    reloaded on it and the progress panel had no way to close.
 *  - A Stop the agent refuses because the run is publishing arrives as an
 *    `error` with `code: 'publishing'`. It is not a failed run, and treating
 *    it as one flipped a still-running run to "failed".
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'

vi.mock('./agentWsUrl', () => ({ buildAgentWsUrl: () => 'ws://agent.test/ws/cypherfix-triage' }))

import { useCypherFixTriageWS } from './useCypherFixTriageWS'

class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  readyState = 1
  sent: Array<{ type: string }> = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null

  constructor(public url: string) {
    FakeSocket.instances.push(this)
  }
  send(data: string) { this.sent.push(JSON.parse(data)) }
  close() { /* the hook detaches handlers before calling this */ }
  receive(msg: unknown) { this.onmessage?.({ data: JSON.stringify(msg) } as MessageEvent) }
}

beforeEach(() => {
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => ({ ticket: 'tkt' }),
  }) as unknown as Response))
})
afterEach(() => { vi.unstubAllGlobals() })

async function connectedRun() {
  const hook = renderHook(() => useCypherFixTriageWS({
    userId: 'u1', projectId: 'p1', autoConnect: true,
  }))
  await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
  const sock = FakeSocket.instances[0]
  act(() => { sock.onopen?.() })
  act(() => { sock.receive({ type: 'connected', session_id: 's1' }) })
  act(() => { sock.receive({ type: 'triage_phase', payload: { phase: 'reviewing', description: '', progress: 50 } }) })
  expect(hook.result.current.status).toBe('running')
  return { ...hook, sock }
}

describe('useCypherFixTriageWS terminal states', () => {
  test('a stopped run is `stopped`, not `connected` (U4)', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'stopped' }) })
    expect(result.current.status).toBe('stopped')
    expect(result.current.error).toBeNull()
    unmount()
  })

  test('a Stop refused while publishing leaves the run running and says why', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'triage_phase', payload: { phase: 'publishing', description: '', progress: 92 } }) })
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The run is publishing and will finish in moments.', recoverable: true, code: 'publishing',
      } })
    })
    expect(result.current.status).toBe('running')
    expect(result.current.error).toBeNull()
    expect(result.current.notice).toBe('The run is publishing and will finish in moments.')

    act(() => { sock.receive({ type: 'triage_complete', payload: { total_remediations: 1, by_severity: {}, by_type: {}, summary: '' } }) })
    expect(result.current.status).toBe('completed')
    expect(result.current.notice).toBeNull()
    unmount()
  })

  test('any other error still fails the run, and says which', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'error', payload: { message: 'Triage failed', code: 'internal_error' } }) })
    expect(result.current.status).toBe('error')
    expect(result.current.error).toBe('Triage failed (internal_error)')
    expect(result.current.notice).toBeNull()
    unmount()
  })

  test('starting again after a stop leaves the stopped state at once', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'stopped' }) })
    act(() => { result.current.startTriage() })
    expect(result.current.status).toBe('connected')
    expect(sock.sent.map(m => m.type)).toContain('start_triage')
    unmount()
  })
})

describe('useCypherFixTriageWS says why it failed (G-3, G-6, G-33, G-34, G-35, G-49)', () => {
  test('a refused ticket shows the refusal and its status, and dials nothing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'A version activation is in progress for this project.' }),
      { status: 409, headers: { 'Content-Type': 'application/json' } })))
    const { result, unmount } = renderHook(() => useCypherFixTriageWS({ userId: 'u1', projectId: 'p1', autoConnect: true }))
    await waitFor(() => expect(result.current.status).toBe('error'))
    expect(result.current.error).toBe(
      'Triage authentication failed (could not obtain a ticket): ' +
      'A version activation is in progress for this project. (HTTP 409)')
    expect(FakeSocket.instances).toHaveLength(0)
    unmount()
  })

  test('a deployment without ticket signing still connects', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ticket: null }) }) as unknown as Response))
    const { result, unmount } = renderHook(() => useCypherFixTriageWS({ userId: 'u1', projectId: 'p1', autoConnect: true }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    expect(result.current.error).toBeNull()
    unmount()
  })

  test('a close the page did not ask for shows its code and the agent reason', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.onclose?.({ code: 1008, reason: 'missing or invalid ticket' } as CloseEvent) })
    expect(result.current.status).toBe('error')
    expect(result.current.error).toBe(
      'The connection to the triage agent closed (code 1008: missing or invalid ticket)')
    unmount()
  })

  test('a dropped connection without a reason still says 1006', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.onclose?.({ code: 1006, reason: '' } as CloseEvent) })
    expect(result.current.error).toMatch(/code 1006: no reason given/)
    unmount()
  })

  test('a Stop while disconnected is refused visibly, not dropped', async () => {
    const { result, sock, unmount } = await connectedRun()
    sock.readyState = 3
    act(() => { result.current.stopTriage() })
    expect(sock.sent.map(m => m.type)).not.toContain('stop')
    expect(result.current.notice).toMatch(/Stop was not sent/)
    unmount()
  })

  test('a run whose reviews failed completes with a notice naming the provider status', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => {
      sock.receive({ type: 'triage_complete', payload: {
        total_remediations: 1, by_severity: {}, by_type: {}, summary: '',
        review_failed: 12, error_class: 'RateLimitError', provider_status: 429,
      } })
    })
    expect(result.current.status).toBe('completed')
    expect(result.current.notice).toBe(
      'The AI review failed for 12 findings (RateLimitError · provider HTTP 429). ' +
      'They keep their rules-only ranking; run triage again to review them.')
    unmount()
  })

  test('a refused start shows the webapp reason, the code and the status', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The triage run could not be authorised and did not start. A triage run is already in progress for this project.',
        code: 'authorize_failed', upstream_status: 409,
      } })
    })
    expect(result.current.error).toBe(
      'The triage run could not be authorised and did not start. A triage run is already in progress ' +
      'for this project. (authorize_failed · upstream HTTP 409)')
    unmount()
  })

  test('an internal error names its class and phase; free text in a code field is dropped', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The triage run stopped because of an internal error.',
        code: 'internal_error', error_class: 'KeyError', phase: 'reviewing',
        step: 'DROP TABLE x; select',
      } })
    })
    expect(result.current.error).toBe(
      'The triage run stopped because of an internal error. (internal_error · KeyError · in reviewing)')
    unmount()
  })
})
