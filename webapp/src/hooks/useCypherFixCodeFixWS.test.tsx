/**
 * What the CodeFix socket tells the person when it fails (G-4, G-7, G-36, G-37, G-50).
 *
 * A refused ticket used to leave a blank panel: the hook set `error`, but nothing
 * rendered it and no log entry was written. Agent errors carried only a fixed
 * sentence, so a bad token, a missing repository and a 429 all read the same.
 *
 * Run: npx vitest run src/hooks/useCypherFixCodeFixWS.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'

vi.mock('./agentWsUrl', () => ({ buildAgentWsUrl: () => 'ws://agent.test/ws/cypherfix-codefix' }))

import { useCypherFixCodeFixWS } from './useCypherFixCodeFixWS'

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
  close() {}
  receive(msg: unknown) { this.onmessage?.({ data: JSON.stringify(msg) } as MessageEvent) }
}

beforeEach(() => {
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ticket: 'tkt' }) }) as unknown as Response))
})
afterEach(() => { vi.unstubAllGlobals() })

async function connected() {
  const hook = renderHook(() => useCypherFixCodeFixWS({ userId: 'u1', projectId: 'p1' }))
  act(() => { hook.result.current.startFix('rem-1') })
  await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
  const sock = FakeSocket.instances[0]
  act(() => { sock.onopen?.() })
  act(() => { sock.receive({ type: 'connected', session_id: 's1' }) })
  return { ...hook, sock }
}

describe('useCypherFixCodeFixWS failures', () => {
  test('a refused ticket says why, with the status, and dials nothing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } })))
    const { result, unmount } = renderHook(() => useCypherFixCodeFixWS({ userId: 'u1', projectId: 'p1' }))
    act(() => { result.current.startFix('rem-1') })
    await waitFor(() => expect(result.current.status).toBe('error'))
    expect(result.current.error).toBe('CodeFix authentication failed (could not obtain a ticket): Not found (HTTP 404)')
    expect(FakeSocket.instances).toHaveLength(0)
    unmount()
  })

  test('a clone failure names the step, the git exit code and the cause in the log', async () => {
    const { result, sock, unmount } = await connected()
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The repository could not be cloned.', code: 'clone_failed',
        step: 'clone', git_exit_code: 128, cause: 'repo_not_found',
      } })
    })
    const text = 'The repository could not be cloned. (clone_failed · step clone · git exit 128 · repo_not_found)'
    expect(result.current.error).toBe(text)
    expect(result.current.errorCode).toBe('clone_failed')
    expect(result.current.activityLog.at(-1)).toMatchObject({ type: 'error', message: text })
    unmount()
  })

  test('a model failure carries the provider class and status', async () => {
    const { result, sock, unmount } = await connected()
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The AI model call failed.', code: 'llm_error',
        error_class: 'RateLimitError', provider_status: 429,
      } })
    })
    expect(result.current.error).toBe('The AI model call failed. (llm_error · RateLimitError · provider HTTP 429)')
    unmount()
  })

  test('a pull request refusal carries GitHub status and title', async () => {
    const { result, sock, unmount } = await connected()
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The pull request could not be created.', code: 'pr_failed',
        step: 'create_pr', github_status: 403, github_message: 'Resource not accessible by integration',
      } })
    })
    expect(result.current.error).toBe('The pull request could not be created. (pr_failed · step create_pr · ' +
      'GitHub HTTP 403 · GitHub: Resource not accessible by integration)')
    unmount()
  })

  test('a close the page did not ask for shows its code and reason', async () => {
    const { result, sock, unmount } = await connected()
    act(() => { sock.onclose?.({ code: 1008, reason: 'ticket auth not configured' } as CloseEvent) })
    expect(result.current.status).toBe('error')
    expect(result.current.error).toBe('The connection to the CodeFix agent closed (code 1008: ticket auth not configured)')
    unmount()
  })

  test('our own close is not an error', async () => {
    const { result, sock, unmount } = await connected()
    act(() => { sock.onclose?.({ code: 1005, reason: '' } as CloseEvent) })
    expect(result.current.error).toBeNull()
    unmount()
  })
})
