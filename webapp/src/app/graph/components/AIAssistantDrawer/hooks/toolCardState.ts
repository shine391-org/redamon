/**
 * Tool-card bookkeeping shared by the live socket handler and session restore.
 *
 * Cards are paired with backend events by `step_id` (the ExecutionStep uuid the
 * agent repeats on tool_start, tool_output_chunk, tool_finished, tool_complete).
 * Pairing by tool name alone matched the FIRST running card of that name, so
 * one lost tool_complete left a ghost card that swallowed the next same-name
 * tool's completion, and that tool's card then stayed "Running" forever.
 */

import type { ChatItem } from '../types'
import type { PlanWaveItem, ToolExecutionItem } from '../AgentTimeline'

function isToolCard(item: ChatItem): item is ToolExecutionItem {
  return 'type' in item && item.type === 'tool_execution'
}

/**
 * Index of the standalone tool card an event belongs to, or -1.
 *
 * An event with a step_id goes to the card with that step_id, whatever its
 * status: a late tool_complete still lands on a card that was settled meanwhile.
 * Without an exact match (legacy events, restored legacy rows) it falls back to
 * the first RUNNING card of that tool that is not bound to a different step.
 */
export function findToolCardIndex(
  items: ChatItem[],
  toolName: string,
  stepId?: string | null,
): number {
  if (stepId) {
    const exact = items.findIndex(it => isToolCard(it) && it.step_id === stepId)
    if (exact !== -1) return exact
  }
  return items.findIndex(it =>
    isToolCard(it) &&
    it.tool_name === toolName &&
    it.status === 'running' &&
    (!stepId || !it.step_id),
  )
}

function settleTool(tool: ToolExecutionItem): ToolExecutionItem {
  if (tool.status !== 'running') return tool
  // The tool itself returned and only its analysis never arrived: keep the
  // tool's own verdict. Otherwise it was cut off mid-execution.
  if (tool.finished) {
    return { ...tool, status: tool.finishedSuccess === false ? 'error' : 'success' }
  }
  return { ...tool, status: 'error', interrupted: true }
}

/**
 * Close every card still marked running once the run is known to be over
 * (STOPPED, final response, server says agent_running=false). Their
 * tool_complete will never come, so leaving them "Running" with a ticking
 * stopwatch is exactly the frozen card the operator saw.
 */
export function settleRunningTools(items: ChatItem[]): ChatItem[] {
  let changed = false
  const next = items.map(item => {
    if (isToolCard(item) && item.status === 'running') {
      changed = true
      return settleTool(item)
    }
    if ('type' in item && item.type === 'plan_wave') {
      const wave = item as PlanWaveItem
      if (!wave.tools.some(t => t.status === 'running') && wave.status !== 'running') return item
      changed = true
      const tools = wave.tools.map(settleTool)
      const ok = tools.filter(t => t.status === 'success').length
      const status: PlanWaveItem['status'] = wave.status !== 'running'
        ? wave.status
        : ok === 0 ? 'error' : ok === tools.length ? 'success' : 'partial'
      return { ...wave, tools, status }
    }
    return item
  })
  return changed ? next : items
}
