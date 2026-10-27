/**
 * Unit tests for the Markdown session-export header.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/hooks/useDownloadMarkdown.test.ts
 *
 * Focus: the XBEN-evaluation fields added to the "# AI Agent Session Report"
 * header -- Session id, Wall time (first-to-last timestamp), and Tokens
 * (summed across root thinking deltas + fireteam member cumulative totals,
 * matching the on-screen DrawerHeader). downloadStreaming is mocked so the test
 * captures the emitted Markdown without touching browser file APIs.
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import type { ChatItem } from '../types'

// Capture whatever the hook streams to disk.
let captured = ''
vi.mock('../../../utils/exportHelpers', () => ({
  downloadStreaming: async (
    _filename: string,
    _mime: string,
    makeChunks: () => AsyncGenerator<string>,
  ) => {
    captured = ''
    for await (const chunk of makeChunks()) captured += chunk
    return true
  },
}))

import { useDownloadMarkdown } from './useDownloadMarkdown'

function run(chatItems: ChatItem[], sessionId = 'session_abc123def456') {
  const { result } = renderHook(() =>
    useDownloadMarkdown({
      chatItems,
      currentPhase: 'exploitation',
      iterationCount: 18,
      modelName: 'deepseek-v4-pro',
      todoList: [],
      sessionId,
    }),
  )
  return result.current.handleDownloadMarkdown()
}

// Minimal ChatItem factories. Only the fields the header math reads are set;
// cast keeps the test focused on header behaviour rather than full item shape.
function userMsg(atMs: number): ChatItem {
  return { type: 'message', id: `m${atMs}`, role: 'user', content: 'go', timestamp: new Date(atMs) } as unknown as ChatItem
}
function assistantMsg(atMs: number): ChatItem {
  return { type: 'message', id: `a${atMs}`, role: 'assistant', content: 'done', timestamp: new Date(atMs) } as unknown as ChatItem
}
function thinking(atMs: number, inTok: number, outTok: number): ChatItem {
  return { type: 'thinking', id: `t${atMs}`, timestamp: new Date(atMs), thought: 'x', input_tokens: inTok, output_tokens: outTok } as unknown as ChatItem
}
function fireteam(atMs: number, members: Array<{ input_tokens_used: number; output_tokens_used: number }>): ChatItem {
  const fullMembers = members.map((m, i) => ({
    name: `member-${i}`,
    member_id: `mem-${i}`,
    status: 'success',
    ...m,
  }))
  return { type: 'fireteam', id: `f${atMs}`, timestamp: new Date(atMs), status: 'success', members: fullMembers } as unknown as ChatItem
}
function latsNode(id: string, parent: string | null, depth: number, tool: string | null,
                  args: Record<string, unknown> | null, value: number, verdict: string) {
  return {
    id, parent_id: parent, depth, label: `n-${id}`, tool_name: tool, tool_args: args,
    status: 'evaluated', value, local_value: value, visits: 1, verdict, error_class: '',
    finding_confidence: 0, exploit_succeeded: false, duration_ms: 0, observation: '',
    reflection: '', is_dangerous: false, step_id: null,
  }
}
function latsSearch(atMs: number): ChatItem {
  return {
    type: 'lats_search', id: 'search_x', search_id: 'search_x', timestamp: new Date(atMs),
    objective: 'recover the flag', phase: 'exploitation', shadow_mode: false,
    status: 'complete', outcome: 'branch_collapsed',
    latest: {
      search_id: 'search_x', objective: 'recover the flag', phase: 'exploitation',
      shadow_mode: false, rollouts: 3, budget: { max_rollouts: 50, max_depth: 6 },
      active_id: null, best_trajectory: ['a1', 'b2'],
      nodes: [
        latsNode('root', null, 0, null, null, 0, ''),
        latsNode('a1', 'root', 1, 'execute_curl', { args: '-s http://t/xss?name=x' }, 0.3, 'diagnostic_progress'),
        latsNode('b2', 'a1', 2, 'execute_playwright', { url: 'http://t/#x' }, 0.1, 'no_progress'),
      ],
    },
    history: [],
  } as unknown as ChatItem
}

beforeEach(() => { captured = '' })

describe('useDownloadMarkdown header', () => {
  test('sums tokens across thinking deltas and fireteam members', async () => {
    await run([
      userMsg(0),
      thinking(1000, 700_000, 90_000),
      fireteam(2000, [
        { input_tokens_used: 30_000, output_tokens_used: 6_000 },
        { input_tokens_used: 8_000, output_tokens_used: 2_000 },
      ]),
      assistantMsg(1_960_000),
    ])
    // 700k + 30k + 8k = 738,000 ; 90k + 6k + 2k = 98,000 ; total 836,000
    expect(captured).toContain('**Tokens:** in 738,000 · out 98,000 · total 836,000')
  })

  test('wall time is last-minus-first timestamp, both pretty and seconds', async () => {
    await run([userMsg(0), thinking(500_000, 1, 1), assistantMsg(1_960_000)])
    expect(captured).toContain('**Wall time:** 32m 40s (1960s)')
  })

  test('includes the full session id for log correlation', async () => {
    await run([userMsg(0), assistantMsg(5000)], 'session_203c6e074e8ba3e0')
    expect(captured).toContain('**Session:** session_203c6e074e8ba3e0')
  })

  test('renders the LATS exploit-path search card (probes + trajectory) — regression for the dropped tree', async () => {
    await run([userMsg(0), latsSearch(1000), assistantMsg(5000)])
    expect(captured).toContain('### LATS Exploit-Path Search')
    expect(captured).toContain('[COMPLETE - branch_collapsed]')
    expect(captured).toContain('3 rollouts (max 50)')
    expect(captured).toContain('2 probes')
    expect(captured).toContain('execute_curl')
    expect(captured).toContain('value 0.30, diagnostic_progress')
    expect(captured).toContain('**Best trajectory:** a1 → b2')
  })

  test('omits Tokens line when no token data is present', async () => {
    await run([userMsg(0), assistantMsg(5000)])
    expect(captured).not.toContain('**Tokens:**')
    // wall time still present (2 timestamps exist)
    expect(captured).toContain('**Wall time:** 5s (5s)')
  })

  test('sub-minute wall time renders without a minute part', async () => {
    await run([userMsg(0), assistantMsg(89_000)])
    expect(captured).toContain('**Wall time:** 1m 29s (89s)')
  })

  test('empty session produces no output at all', async () => {
    await run([])
    expect(captured).toBe('')
  })

  test('header order: Date, Session, Phase, Step, Model, Wall time, Tokens', async () => {
    await run([userMsg(0), thinking(1000, 10, 5), assistantMsg(60_000)])
    const idx = (s: string) => captured.indexOf(s)
    expect(idx('**Date:**')).toBeGreaterThanOrEqual(0)
    expect(idx('**Date:**')).toBeLessThan(idx('**Session:**'))
    expect(idx('**Session:**')).toBeLessThan(idx('**Phase:**'))
    expect(idx('**Phase:**')).toBeLessThan(idx('**Step:**'))
    expect(idx('**Step:**')).toBeLessThan(idx('**Model:**'))
    expect(idx('**Model:**')).toBeLessThan(idx('**Wall time:**'))
    expect(idx('**Wall time:**')).toBeLessThan(idx('**Tokens:**'))
  })
})

describe('useDownloadMarkdown tool status tags', () => {
  const toolCard = (extra: any): ChatItem => ({
    type: 'tool_execution', id: `tool-${Math.random()}`, timestamp: new Date(1_000),
    tool_name: 'tradecraft_lookup', tool_args: {}, status: 'running', output_chunks: ['PoC not found'], ...extra,
  } as unknown as ChatItem)

  test('a returned tool awaiting analysis exports as ANALYZING, a cut-off one as INTERRUPTED', async () => {
    await run([toolCard({ finished: true })])
    expect(captured).toContain('[ANALYZING]')
    await run([toolCard({ status: 'error', interrupted: true })])
    expect(captured).toContain('[INTERRUPTED]')
    await run([toolCard({})])
    expect(captured).toContain('[RUNNING]')
  })
})
