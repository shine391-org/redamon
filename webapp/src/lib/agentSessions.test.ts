/**
 * C-8: a Conversation.agentRunning flag is checked against the agent's own task
 * registry instead of being obeyed blindly, so a flag left by a restarted agent
 * stops locking the project. The failure mode matters as much as the fix: an
 * agent that cannot answer must leave a set flag counting as running.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findMany: vi.fn(),
  updateMany: vi.fn(),
  agentFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: h.findMany, updateMany: h.updateMany } },
}))
vi.mock('@/lib/agentFetch', () => ({ agentFetch: (...a: unknown[]) => h.agentFetch(...a) }))

import { checkAgentSessions, describeAgentSessionState, sessionRunningCheck, sessionRunningState } from './agentSessions'

const T0 = new Date('2026-09-29T10:00:00.000Z')
const flag = (id: string, sessionId: string) => ({ id, sessionId, updatedAt: T0 })
const live = (ids: unknown) => ({ ok: true, json: async () => ({ project_id: 'p1', session_ids: ids }) })

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  h.findMany.mockResolvedValue([])
  h.updateMany.mockResolvedValue({ count: 1 })
  h.agentFetch.mockResolvedValue(live([]))
})

describe('checkAgentSessions', () => {
  test('no flag set: idle, and the agent is never asked', async () => {
    expect(await checkAgentSessions('p1')).toBe('idle')
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('a flag the agent confirms is running, and is left alone', async () => {
    h.findMany.mockResolvedValue([flag('c1', 's1')])
    h.agentFetch.mockResolvedValue(live(['s1']))
    expect(await checkAgentSessions('p1')).toBe('running')
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('the agent is asked about THIS project only', async () => {
    h.findMany.mockResolvedValue([flag('c1', 's1')])
    await checkAgentSessions('p 1/x')
    expect(h.agentFetch.mock.calls[0][0]).toBe('/agent-sessions/live?project_id=p%201%2Fx')
    expect(h.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { projectId: 'p 1/x', agentRunning: true },
    }))
  })

  test('a flag the agent does not hold is stale: cleared, and the project is idle', async () => {
    h.findMany.mockResolvedValue([flag('c1', 's1'), flag('c2', 's2')])
    h.agentFetch.mockResolvedValue(live(['some-other-session']))
    expect(await checkAgentSessions('p1')).toBe('idle')
    expect(h.updateMany).toHaveBeenCalledTimes(2)
    // Conditional on the row being unchanged since it was read.
    expect(h.updateMany).toHaveBeenCalledWith({
      where: { id: 'c1', agentRunning: true, updatedAt: T0 },
      data: { agentRunning: false },
    })
  })

  test('one confirmed session among stale ones: running, and nothing is cleared', async () => {
    h.findMany.mockResolvedValue([flag('c1', 's1'), flag('c2', 's2')])
    h.agentFetch.mockResolvedValue(live(['s2']))
    expect(await checkAgentSessions('p1')).toBe('running')
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a row that changed before the clear counts as running: a run may have just started', async () => {
    h.findMany.mockResolvedValue([flag('c1', 's1')])
    h.updateMany.mockResolvedValue({ count: 0 })
    expect(await checkAgentSessions('p1')).toBe('running')
  })

  test.each([
    ['unreachable', () => h.agentFetch.mockRejectedValue(new Error('ECONNREFUSED'))],
    ['a non-OK answer (an agent without the endpoint)', () => h.agentFetch.mockResolvedValue({ ok: false, status: 404, json: async () => ({}) })],
    ['a 503 before the manager is up', () => h.agentFetch.mockResolvedValue({ ok: false, status: 503, json: async () => ({}) })],
    ['an unexpected body shape', () => h.agentFetch.mockResolvedValue({ ok: true, json: async () => ({ sessions: 's1' }) })],
  ])('FAIL CLOSED: %s leaves the flag counting, and clears nothing', async (_label, arrange) => {
    h.findMany.mockResolvedValue([flag('c1', 's1')])
    arrange()
    expect(await checkAgentSessions('p1')).toBe('unverified')
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('a database error propagates, so each caller applies its own busy rule', async () => {
    h.findMany.mockRejectedValue(new Error('db down'))
    await expect(checkAgentSessions('p1')).rejects.toThrow('db down')
  })

  test('the live check has a short timeout of its own', async () => {
    h.findMany.mockResolvedValue([flag('c1', 's1')])
    await checkAgentSessions('p1')
    expect(h.agentFetch.mock.calls[0][2]).toEqual({ timeoutMs: 5_000 })
  })
})

describe('describeAgentSessionState', () => {
  test('names a running session, an unconfirmed one, and nothing for idle', () => {
    expect(describeAgentSessionState('running')).toBe('an agent session is running')
    expect(describeAgentSessionState('unverified')).toMatch(/marked running and the agent could not be reached/)
    expect(describeAgentSessionState('idle')).toBeNull()
  })
})

describe('sessionRunningCheck: why a session is unverified', () => {
  const conv = { id: 'c1', projectId: 'p1', sessionId: 's1', agentRunning: true, updatedAt: T0 }
  // agentFetch wraps a transport failure as AgentUnreachableError, keeping the original in cause_.
  const unreachable = (cause: unknown) => Object.assign(new Error('Cannot reach the agent'), { name: 'AgentUnreachableError', cause_: cause })

  test.each<[string, () => void, Record<string, unknown>]>([
    ['refused', () => h.agentFetch.mockRejectedValue(unreachable(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }))), { code: 'agent_unreachable', cause: 'ECONNREFUSED' }],
    ['timed out', () => h.agentFetch.mockRejectedValue(unreachable(new DOMException('timed out', 'TimeoutError'))), { code: 'agent_timeout' }],
    ['answered 500', () => h.agentFetch.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) }), { code: 'agent_error', upstreamStatus: 500 }],
    ['answered without a list', () => h.agentFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ sessions: 's1' }) }), { code: 'agent_bad_answer', upstreamStatus: 200 }],
  ])('%s: unverified, with the cause', async (_label, arrange, failure) => {
    arrange()
    expect(await sessionRunningCheck(conv)).toEqual({ running: 'unverified', failure })
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('the agent answers: no failure, and sessionRunningState (what the Gateway hands plugins) is unchanged', async () => {
    h.agentFetch.mockResolvedValue(live(['s1']))
    expect(await sessionRunningCheck(conv)).toEqual({ running: true })
    expect(await sessionRunningState(conv)).toBe(true)
    h.agentFetch.mockResolvedValue({ ok: false, status: 503, json: async () => ({}) })
    expect(await sessionRunningState(conv)).toBe('unverified')
  })

  test('a non-OK answer is logged with its status (it was not logged at all)', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    h.agentFetch.mockResolvedValue({ ok: false, status: 401, json: async () => ({}) })
    await sessionRunningCheck(conv)
    expect(warn.mock.calls.flat().join(' ')).toContain('the agent answered HTTP 401')
  })
})
