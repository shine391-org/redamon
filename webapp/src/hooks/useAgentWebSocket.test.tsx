/**
 * Unit tests for the agent WebSocket connection lifecycle.
 *
 * Issue #173 (second symptom): the agent FAILS CLOSED on the init frame and
 * closes the socket with 1008 when the ws-ticket is missing or does not verify
 * (agentic/websocket_api.py). The hook treated that like any other drop and
 * reconnected, so a stack whose .env predates AGENT_WS_TICKET_SECRET showed
 * "Connecting..." forever with nothing to act on. A 1008 must stop the loop and
 * name the cause.
 *
 * Run: npx vitest run src/hooks/useAgentWebSocket.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { ConnectionStatus } from '@/lib/websocket-types'

vi.mock('./agentWsUrl', () => ({ buildAgentWsUrl: () => 'ws://agent.test/ws/agent' }))

import { useAgentWebSocket } from './useAgentWebSocket'

// Minimal WebSocket stand-in: records what was sent and lets a test drive the
// close event with a specific code.
class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  readyState = 1
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null

  constructor(public url: string) {
    FakeSocket.instances.push(this)
  }
  send(data: string) { this.sent.push(data) }
  close() { /* the hook detaches handlers before calling this */ }
  fireClose(code: number) { this.onclose?.({ code, reason: '', wasClean: false } as CloseEvent) }
}

const config = {
  userId: 'u1',
  projectId: 'p1',
  sessionId: 's1',
  maxReconnectAttempts: 5,
  reconnectInterval: 10,
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

describe('useAgentWebSocket auth rejection (#173)', () => {
  test('close 1008 → FAILED with an actionable error, and NO reconnect', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]

    await act(async () => { sock.onopen?.() })
    act(() => { sock.fireClose(1008) })

    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toContain('authentication failed')

    // The reconnect timer must never fire for a configuration failure.
    await new Promise(r => setTimeout(r, 60))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('a ticketless init names the missing secret in the error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ ticket: null }),
    }) as unknown as Response))

    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]

    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sock.sent).toHaveLength(1))
    act(() => { sock.fireClose(1008) })

    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toContain('AGENT_WS_TICKET_SECRET')
  })

  test('an ordinary drop (1006) still reconnects', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))

    await act(async () => { FakeSocket.instances[0].onopen?.() })
    act(() => { FakeSocket.instances[0].fireClose(1006) })

    expect(result.current.status).toBe(ConnectionStatus.RECONNECTING)
    await waitFor(() => expect(FakeSocket.instances.length).toBeGreaterThan(1))
  })
})

// ---------------------------------------------------------------------------
// "Agent stuck" incident: Stop clicks that vanished while the socket was down,
// a half-open socket nobody noticed, and reconnects that dropped a live run.
// ---------------------------------------------------------------------------

function deliver(sock: FakeSocket, type: string, payload: Record<string, unknown> = {}) {
  sock.onmessage?.({ data: JSON.stringify({ type, payload, timestamp: 't' }) } as MessageEvent)
}
const sentTypes = (sock: FakeSocket) => sock.sent.map(s => JSON.parse(s).type)

async function openAndConnect(sock: FakeSocket, payload: Record<string, unknown> = {}) {
  await act(async () => { sock.onopen?.() })
  act(() => deliver(sock, 'connected', payload))
}

describe('useAgentWebSocket outbox', () => {
  test('Stop and guidance sent while not connected go out right after CONNECTED', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]
    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sentTypes(sock)).toEqual(['init']))

    act(() => { result.current.sendGuidance('is it running?'); result.current.sendStop() })
    expect(sentTypes(sock)).toEqual(['init'])   // not authenticated yet: held, not dropped

    act(() => deliver(sock, 'connected', { agent_running: true }))
    expect(sentTypes(sock)).toEqual(['init', 'guidance', 'stop'])
  })

  test('a Stop clicked during a drop is delivered on the new connection', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0])
    act(() => { FakeSocket.instances[0].fireClose(1006) })

    act(() => { result.current.sendStop() })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await openAndConnect(next)
    expect(sentTypes(next)).toContain('stop')
  })

  test('queries are never queued: a stale question must not replay later', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { result.current.sendQuery('old question') })
    await openAndConnect(FakeSocket.instances[0])
    expect(sentTypes(FakeSocket.instances[0])).not.toContain('query')
  })
})

describe('useAgentWebSocket connection truth', () => {
  test('onConnect receives the server payload with agent_running', async () => {
    const onConnect = vi.fn()
    renderHook(() => useAgentWebSocket({ ...config, onConnect }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0], { agent_running: false, session_id: 's1' })
    expect(onConnect).toHaveBeenCalledWith(expect.objectContaining({ agent_running: false }))
  })

  test('a half-open socket (pings, no pongs) is replaced instead of freezing the page', async () => {
    vi.useFakeTimers()
    try {
      renderHook(() => useAgentWebSocket(config))
      expect(FakeSocket.instances).toHaveLength(1)
      const sock = FakeSocket.instances[0]
      await openAndConnect(sock)

      act(() => { vi.advanceTimersByTime(30_000) })
      expect(sentTypes(sock).at(-1)).toBe('ping')
      act(() => deliver(sock, 'pong'))
      act(() => { vi.advanceTimersByTime(60_000) })   // 60s since the last pong: still fine
      expect(FakeSocket.instances).toHaveLength(1)

      act(() => { vi.advanceTimersByTime(30_000) })   // 90s without a pong
      expect(FakeSocket.instances).toHaveLength(2)
    } finally {
      vi.useRealTimers()
    }
  })

  test('a socket that keeps answering is never replaced', async () => {
    vi.useFakeTimers()
    try {
      renderHook(() => useAgentWebSocket(config))
      const sock = FakeSocket.instances[0]
      await openAndConnect(sock)
      for (let i = 0; i < 10; i++) {
        act(() => { vi.advanceTimersByTime(30_000) })
        act(() => deliver(sock, 'pong'))
      }
      expect(FakeSocket.instances).toHaveLength(1)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('useAgentWebSocket graph-view changes', () => {
  test('a view change during a run waits for the run to end, then reconnects with it', async () => {
    const { rerender } = renderHook(
      (p: { graphViewCypher: string; runActive: boolean }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { graphViewCypher: 'MATCH (a) RETURN a', runActive: true } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0])

    rerender({ graphViewCypher: 'MATCH (b) RETURN b', runActive: true })
    await new Promise(r => setTimeout(r, 30))
    expect(FakeSocket.instances).toHaveLength(1)   // the live run keeps its stream

    rerender({ graphViewCypher: 'MATCH (b) RETURN b', runActive: false })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await act(async () => { next.onopen?.() })
    await waitFor(() => expect(next.sent).toHaveLength(1))
    expect(JSON.parse(next.sent[0]).payload.graph_view_cypher).toBe('MATCH (b) RETURN b')
  })

  test('with no run going, a view change reconnects at once', async () => {
    const { rerender } = renderHook(
      (p: { graphViewCypher: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { graphViewCypher: 'A' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0])
    rerender({ graphViewCypher: 'B' })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
  })
})

describe('useAgentWebSocket outbox is per session', () => {
  test('a Stop queued for one session never reaches the session the page switched to', async () => {
    const { result, rerender } = renderHook(
      (p: { sessionId: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { sessionId: 's1' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { result.current.sendStop() })          // s1 not connected yet: queued
    rerender({ sessionId: 's2' })                      // operator opens another session
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const s2 = FakeSocket.instances[1]
    await openAndConnect(s2)
    expect(sentTypes(s2)).not.toContain('stop')
  })
})
