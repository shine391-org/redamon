/**
 * Tool cards in the "agent stuck" incident: pairing by step_id, the
 * tool_finished state, and settling cards whose tool_complete never comes.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/hooks/toolCardState.test.ts
 */
import { describe, test, expect, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { MessageType } from '@/lib/websocket-types'
import { findToolCardIndex, settleRunningTools } from './toolCardState'
import { useWebSocketHandler } from './useWebSocketHandler'
import type { ChatItem } from '../types'
import type { PlanWaveItem, ToolExecutionItem } from '../AgentTimeline'

function card(overrides: Partial<ToolExecutionItem> = {}): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: `t-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(Date.now() - 5000),
    tool_name: 'execute_code',
    tool_args: {},
    status: 'running',
    output_chunks: [],
    ...overrides,
  }
}

describe('findToolCardIndex', () => {
  test('an event with a step_id goes to that card, never to an older ghost', () => {
    const ghost = card({ step_id: 'S1' })   // its tool_complete was lost
    const live = card({ step_id: 'S2' })
    expect(findToolCardIndex([ghost, live], 'execute_code', 'S2')).toBe(1)
  })

  test('exact match ignores status, so a late complete still lands', () => {
    const settled = card({ step_id: 'S1', status: 'error', interrupted: true })
    expect(findToolCardIndex([settled], 'execute_code', 'S1')).toBe(0)
  })

  test('legacy events without step_id keep the first-running-by-name pairing', () => {
    const done = card({ status: 'success' })
    const running = card()
    expect(findToolCardIndex([done, running], 'execute_code', undefined)).toBe(1)
  })

  test('a step_id with no card falls back only to a card not bound to another step', () => {
    const bound = card({ step_id: 'S1' })
    expect(findToolCardIndex([bound], 'execute_code', 'S9')).toBe(-1)
    const unbound = card()
    expect(findToolCardIndex([unbound], 'execute_code', 'S9')).toBe(0)
  })
})

describe('settleRunningTools', () => {
  test('a tool cut off mid-execution becomes interrupted', () => {
    const [c] = settleRunningTools([card()]) as ToolExecutionItem[]
    expect(c.status).toBe('error')
    expect(c.interrupted).toBe(true)
  })

  test('a tool that returned keeps its own verdict', () => {
    const [ok, bad] = settleRunningTools([
      card({ finished: true, finishedSuccess: true }),
      card({ finished: true, finishedSuccess: false }),
    ]) as ToolExecutionItem[]
    expect(ok.status).toBe('success')
    expect(bad.status).toBe('error')
    expect(bad.interrupted).toBeFalsy()
  })

  test('waves: running tools settle and the wave status follows them', () => {
    const wave: PlanWaveItem = {
      type: 'plan_wave', id: 'w', timestamp: new Date(), wave_id: 'w1',
      plan_rationale: '', tool_count: 2, status: 'running',
      tools: [card({ status: 'success' }), card()],
    }
    const [w] = settleRunningTools([wave]) as PlanWaveItem[]
    expect(w.tools.map(t => t.status)).toEqual(['success', 'error'])
    expect(w.status).toBe('partial')
    const empty = { ...wave, tools: [] }
    expect((settleRunningTools([empty])[0] as PlanWaveItem).status).toBe('error')
  })

  test('nothing running: the same array comes back (no re-render)', () => {
    const items: ChatItem[] = [card({ status: 'success' })]
    expect(settleRunningTools(items)).toBe(items)
  })
})

// ---------------------------------------------------------------------------
// Replay through the real live handler
// ---------------------------------------------------------------------------

function harness() {
  let items: ChatItem[] = []
  const flags: Record<string, unknown> = {}
  const setter = (name: string) => vi.fn((v: unknown) => { flags[name] = v })
  const deps = {
    setChatItems: vi.fn((v: any) => { items = typeof v === 'function' ? v(items) : v }),
    setIsLoading: setter('isLoading'),
    setIsStopped: setter('isStopped'),
    setIsStopping: setter('isStopping'),
    setCurrentPhase: vi.fn(), setIterationCount: vi.fn(), setAttackPathType: vi.fn(),
    setTodoList: vi.fn(), todoList: [], itemIdCounter: { current: 0 },
    setAwaitingApproval: vi.fn(), setApprovalRequest: vi.fn(),
    setAwaitingQuestion: vi.fn(), setQuestionRequest: vi.fn(),
    setAwaitingToolConfirmation: vi.fn(), setToolConfirmationRequest: vi.fn(),
    awaitingApprovalRef: { current: false }, isProcessingApproval: { current: false },
    awaitingQuestionRef: { current: false }, isProcessingQuestion: { current: false },
    awaitingToolConfirmationRef: { current: false }, isProcessingToolConfirmation: { current: false },
    pendingApprovalToolId: { current: null }, pendingApprovalWaveId: { current: null },
  }
  const { result } = renderHook(() => useWebSocketHandler(deps as any))
  const send = (type: MessageType, payload: any) =>
    result.current.handleWebSocketMessage({ type, payload, timestamp: new Date().toISOString() } as any)
  const cards = () => items.filter(i => (i as any).type === 'tool_execution') as ToolExecutionItem[]
  return { send, cards, flags }
}

describe('incident replay through useWebSocketHandler', () => {
  test('tool returns, its analysis never arrives: the card shows finished, not a ticking run', () => {
    const { send, cards } = harness()
    send(MessageType.TOOL_START, { tool_name: 'tradecraft_lookup', tool_args: {}, step_id: 'S1' })
    send(MessageType.TOOL_OUTPUT_CHUNK, { tool_name: 'tradecraft_lookup', chunk: 'PoC not found', is_final: true, step_id: 'S1' })
    send(MessageType.TOOL_FINISHED, { tool_name: 'tradecraft_lookup', success: true, duration_ms: 12000, step_id: 'S1' })
    const [c] = cards()
    expect(c.step_id).toBe('S1')
    expect(c.status).toBe('running')
    expect(c.finished).toBe(true)
    expect(c.duration).toBe(12000)
    expect(c.output_chunks).toEqual(['PoC not found'])
  })

  test('a lost tool_complete no longer steals the next same-name tool completion', () => {
    const { send, cards } = harness()
    send(MessageType.TOOL_START, { tool_name: 'execute_code', tool_args: { n: 1 }, step_id: 'S1' })
    // S1's tool_complete was emitted while the socket was down: lost.
    send(MessageType.TOOL_START, { tool_name: 'execute_code', tool_args: { n: 2 }, step_id: 'S2' })
    send(MessageType.TOOL_OUTPUT_CHUNK, { tool_name: 'execute_code', chunk: 'two', is_final: true, step_id: 'S2' })
    send(MessageType.TOOL_COMPLETE, { tool_name: 'execute_code', success: true, output_summary: 'ok',
      actionable_findings: [], recommended_next_steps: [], duration_ms: 900, step_id: 'S2' })
    const [s1, s2] = cards()
    expect(s1.status).toBe('running')
    expect(s1.output_chunks).toEqual([])
    expect(s2.status).toBe('success')
    expect(s2.output_chunks).toEqual(['two'])
    expect(s2.duration).toBe(900)
  })

  test('STOPPED settles every card still running', () => {
    const { send, cards, flags } = harness()
    send(MessageType.TOOL_START, { tool_name: 'execute_code', tool_args: {}, step_id: 'S1' })
    send(MessageType.STOPPED, { message: 'stopped', iteration: 1, phase: 'exploitation' })
    expect(cards()[0].status).toBe('error')
    expect(cards()[0].interrupted).toBe(true)
    expect(flags.isLoading).toBe(false)
    expect(flags.isStopping).toBe(false)
  })

  test('a recoverable error mid-run leaves live cards alone; a terminal one settles them', () => {
    const { send, cards } = harness()
    send(MessageType.TOOL_START, { tool_name: 'execute_code', tool_args: {}, step_id: 'S1' })
    send(MessageType.ERROR, { message: 'Unknown message type', recoverable: true })
    expect(cards()[0].status).toBe('running')
    send(MessageType.ERROR, { message: 'LLM failed', recoverable: false })
    expect(cards()[0].interrupted).toBe(true)
  })

  test('the final response settles cards whose analysis was lost', () => {
    const { send, cards } = harness()
    send(MessageType.TOOL_START, { tool_name: 'execute_code', tool_args: {}, step_id: 'S1' })
    send(MessageType.TOOL_FINISHED, { tool_name: 'execute_code', success: true, duration_ms: 500, step_id: 'S1' })
    send(MessageType.RESPONSE, { answer: 'done', iteration_count: 2, phase: 'exploitation', task_complete: true })
    expect(cards()[0].status).toBe('success')
  })
})
