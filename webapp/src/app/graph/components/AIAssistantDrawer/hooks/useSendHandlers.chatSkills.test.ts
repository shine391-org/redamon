/**
 * The `/skill` command and skill activation say why a Chat Skill could not be read (U-33,
 * G-52): the status tells a deleted skill (404) from a server failure (500 with its code).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import type { ChatItem } from '../types'
import { useSendHandlers } from './useSendHandlers'

let items: ChatItem[]

function makeDeps(inputValue = '') {
  const base: Record<string, unknown> = {
    inputValue, isLoading: false, chatItems: [], activeSkill: null,
    awaitingApproval: false, awaitingQuestion: false, awaitingToolConfirmation: false,
    questionRequest: null, modificationText: '', answerText: '', selectedOptions: [],
    conversationId: null, projectId: 'p1', userId: 'alice', sessionId: 's1',
    setChatItems: (update: ChatItem[] | ((prev: ChatItem[]) => ChatItem[])) => {
      items = typeof update === 'function' ? update(items) : update
    },
    updateConvMeta: vi.fn().mockResolvedValue(undefined),
    createConversation: vi.fn().mockResolvedValue(null),
  }
  for (const ref of [
    'isProcessingApproval', 'awaitingApprovalRef', 'isProcessingQuestion', 'awaitingQuestionRef',
    'isProcessingToolConfirmation', 'awaitingToolConfirmationRef', 'pendingApprovalToolId', 'pendingApprovalWaveId',
  ]) base[ref] = { current: null }
  // Every other dependency is a setter or a sender the failure paths never call.
  return new Proxy(base, {
    get: (target, key: string) => {
      if (!(key in target)) target[key] = vi.fn()
      return target[key]
    },
  }) as unknown as Parameters<typeof useSendHandlers>[0]
}

const lastMessage = () => (items.at(-1) as { content?: string } | undefined)?.content

beforeEach(() => { items = [] })
afterEach(() => { vi.unstubAllGlobals() })

describe('Chat Skill failures in the chat', () => {
  test('activating a deleted skill names the 404', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Skill not found' }), { status: 404 })))
    const { result } = renderHook(() => useSendHandlers(makeDeps()))
    await act(async () => { await result.current.activateSkill('cs1', 'Recon notes') })
    expect(lastMessage()).toBe("Failed to load Chat Skill 'Recon notes' (HTTP 404). Please try again.")
  })

  test('activating with no answer names network_error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const { result } = renderHook(() => useSendHandlers(makeDeps()))
    await act(async () => { await result.current.activateSkill('cs1') })
    expect(lastMessage()).toBe('Failed to load Chat Skill (network_error). Please try again.')
  })

  test('/skill list names the code and status of a failed read', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Failed to fetch chat skills', code: 'P1001' }), { status: 500 })))
    const { result } = renderHook(() => useSendHandlers(makeDeps('/skill list')))
    await act(async () => { await result.current.handleSend() })
    expect(lastMessage()).toBe('Failed to fetch chat skills (P1001 · HTTP 500). Please try again.')
  })
})
