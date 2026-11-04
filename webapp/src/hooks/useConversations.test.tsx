/**
 * useConversations: every failure reaches the drawer with its cause (G-10, G-18, G-45).
 *
 * It threw fixed `Error('Failed to X')`s into an `error` state nothing read, so
 * a failed select, list or delete did nothing visible. Each failure is now an
 * ApiError (code + HTTP status) handed to onError, the list's own failure stays
 * in `error` for the history panel, a failed delete answers false so the chat
 * is kept, and a delete that left work behind hands its warnings over.
 *
 * Run: npx vitest run src/hooks/useConversations.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'
import { useConversations } from './useConversations'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let answer: (url: string, init?: RequestInit) => Response | Promise<Response>

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => answer(url, init)))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function setup() {
  const onError = vi.fn()
  const onDeleteWarnings = vi.fn()
  const hook = renderHook(() => useConversations('p1', 'u1', { onError, onDeleteWarnings }))
  return { ...hook, onError, onDeleteWarnings }
}

describe('useConversations failures', () => {
  test('a failed list keeps its cause in `error` and answers the ApiError', async () => {
    answer = () => json(500, { error: 'Failed to fetch conversations', code: 'P1001' })
    const { result, onError } = setup()
    let out: unknown
    await act(async () => { out = await result.current.fetchConversations() })
    expect(out).toBeInstanceOf(ApiError)
    expect(result.current.error).toBe('Failed to fetch conversations (P1001 · HTTP 500)')
    expect(onError).toHaveBeenCalledWith('list', expect.objectContaining({ code: 'P1001', status: 500 }))
  })

  test('a later successful list clears the error', async () => {
    answer = () => json(503, { error: 'x' })
    const { result } = setup()
    await act(async () => { await result.current.fetchConversations() })
    answer = () => json(200, [])
    await act(async () => { await result.current.fetchConversations() })
    expect(result.current.error).toBeNull()
  })

  test('a failed load hands the cause over and does not touch the list error', async () => {
    answer = () => json(404, { error: 'Conversation not found' })
    const { result, onError } = setup()
    let out: unknown = 'unset'
    await act(async () => { out = await result.current.loadConversation('c1') })
    expect(out).toBeNull()
    expect(onError).toHaveBeenCalledWith('load', expect.objectContaining({ message: 'Conversation not found (HTTP 404)' }))
    expect(result.current.error).toBeNull()
  })

  test('a failed delete answers false and keeps the row', async () => {
    answer = (url, init) => init?.method === 'DELETE'
      ? json(500, { error: 'Failed to delete conversation', code: 'P2024' })
      : json(200, [{ id: 'c1', sessionId: 's1' }])
    const { result, onError } = setup()
    await act(async () => { await result.current.fetchConversations() })
    let ok: boolean | undefined
    await act(async () => { ok = await result.current.deleteConversation('c1') })
    expect(ok).toBe(false)
    expect(result.current.conversations).toHaveLength(1)
    expect(onError).toHaveBeenCalledWith('delete', expect.objectContaining({ message: 'Failed to delete conversation (P2024 · HTTP 500)' }))
  })

  test('no answer at all is a network error', async () => {
    answer = () => { throw new TypeError('Failed to fetch') }
    const { result, onError } = setup()
    await act(async () => { await result.current.deleteConversation('c1') })
    expect(onError).toHaveBeenCalledWith('delete', expect.objectContaining({ code: 'network_error' }))
  })

  test('a delete with warnings succeeds and hands them over', async () => {
    const warnings = [{ step: 'agent_stop', code: 'agent_unreachable' }]
    answer = () => json(200, { success: true, warnings })
    const { result, onDeleteWarnings, onError } = setup()
    let ok: boolean | undefined
    await act(async () => { ok = await result.current.deleteConversation('c1') })
    expect(ok).toBe(true)
    expect(onDeleteWarnings).toHaveBeenCalledWith(warnings)
    expect(onError).not.toHaveBeenCalled()
  })

  test('a clean delete hands no warnings over', async () => {
    answer = () => json(200, { success: true })
    const { result, onDeleteWarnings } = setup()
    await act(async () => { await result.current.deleteConversation('c1') })
    expect(onDeleteWarnings).not.toHaveBeenCalled()
  })
})
