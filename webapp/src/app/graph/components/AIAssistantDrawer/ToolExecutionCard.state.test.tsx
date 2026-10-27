/**
 * What a tool card tells the operator in each state of the "agent stuck"
 * incident: running, returned-and-being-analysed, cut off.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.state.test.tsx
 */
import React from 'react'
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, act } from '@testing-library/react'
import { ToolExecutionCard } from './ToolExecutionCard'
import type { ToolExecutionItem } from './AgentTimeline'

afterEach(() => { cleanup(); vi.useRealTimers() })

function item(overrides: Partial<ToolExecutionItem> = {}): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: 'tool-1',
    timestamp: new Date(Date.now() - 356_000),
    tool_name: 'tradecraft_lookup',
    tool_args: { resource_id: 'php2shell-poc' },
    status: 'running',
    output_chunks: ['PoC not found'],
    ...overrides,
  }
}

const renderCard = (it: ToolExecutionItem) =>
  render(<ToolExecutionCard item={it} isExpanded onToggleExpand={() => {}} onStop={vi.fn()} />)

describe('ToolExecutionCard states', () => {
  test('a running tool ticks and can be stopped', () => {
    vi.useFakeTimers()
    renderCard(item({ output_chunks: [] }))
    act(() => { vi.advanceTimersByTime(1100) })
    expect(screen.getByText(/^Running\.\.\. \(35\ds\)$/)).toBeTruthy()
    expect(screen.getByLabelText('Stop this tool')).toBeTruthy()
  })

  test('a returned tool shows its real duration while the agent analyses, no stop button', () => {
    vi.useFakeTimers()
    renderCard(item({ finished: true, finishedSuccess: true, duration: 12_000 }))
    act(() => { vi.advanceTimersByTime(5000) })
    expect(screen.getByText('Analyzing output (12s)')).toBeTruthy()
    expect(screen.queryByLabelText('Stop this tool')).toBeNull()
    expect(screen.queryByText('(streaming)')).toBeNull()
    expect(screen.getByText('PoC not found')).toBeTruthy()
  })

  test('a tool cut off by the end of the run says so instead of "Failed"', () => {
    renderCard(item({ status: 'error', interrupted: true }))
    expect(screen.getByText('Interrupted')).toBeTruthy()
    expect(screen.queryByText('Failed')).toBeNull()
  })

  test('a real failure still reads "Failed"', () => {
    renderCard(item({ status: 'error' }))
    expect(screen.getByText('Failed')).toBeTruthy()
  })
})
