/**
 * The gear-menu click with a pick (platform 1.1.0, plan Phase 3.3 and D12): an item that says
 * `pick: "session.skill"` opens the core's skill picker BEFORE the model gate, a cancel there
 * aborts everything, and the POST carries only `{kind, ref}` of the pick. An item without
 * `pick` still sends exactly `{context}` (runPluginAction.test.ts pins that too). A job answer
 * names the skill; one already running on another skill says so.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { pickedSkillLabel, runPluginAction, type PluginActionHandlers } from './runPluginAction'
import type { SessionPick } from './SessionSkillPicker'
import type { ChatSessionActionContribution } from '@/lib/plugins/contributions'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

const plugin = { pluginId: 'skiller', displayName: 'Skiller' }
const context = { projectId: 'p1', sessionId: 's1' }
const userPick: SessionPick = { kind: 'session.skill', ref: 'user_skill:sk1', name: 'My SQLi flow v2', skillKind: 'user' }

const item = (over: Partial<ChatSessionActionContribution> = {}): ChatSessionActionContribution => ({
  key: 'analyze', label: 'Improve skill from this session', action: 'analyze', pick: 'session.skill', llm: true, async: true, ...over,
})

/** Records the order of picker, gate and POST so "picker before gate" is asserted, not assumed. */
function setup(opts: { pick?: SessionPick | null; model?: string | null; answer?: Response } = {}) {
  const order: string[] = []
  const fetchMock = vi.fn(async () => {
    order.push('post')
    return opts.answer ?? json(202, { jobId: 'job_1' })
  })
  vi.stubGlobal('fetch', fetchMock)
  const gate = {
    ensureFeatureModel: vi.fn(async () => {
      order.push('gate')
      return opts.model === undefined ? 'anthropic/claude' : opts.model
    }),
    fetchWithFeatureModel: vi.fn(),
    userId: 'u1',
    savedVersion: 0,
  } as unknown as FeatureModelGateApi & { ensureFeatureModel: ReturnType<typeof vi.fn> }
  const handlers = {
    onReviewProposal: vi.fn<PluginActionHandlers['onReviewProposal']>(),
    onCoreScreen: vi.fn<PluginActionHandlers['onCoreScreen']>(),
    onJob: vi.fn<PluginActionHandlers['onJob']>(),
    pickSessionSkill: vi.fn<NonNullable<PluginActionHandlers['pickSessionSkill']>>(async () => {
      order.push('picker')
      return opts.pick === undefined ? userPick : opts.pick
    }),
    onPicked: vi.fn<NonNullable<PluginActionHandlers['onPicked']>>(),
    toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
  } satisfies PluginActionHandlers
  return { order, fetchMock, gate, handlers }
}

const bodyOf = (fetchMock: ReturnType<typeof vi.fn>, i = 0) => JSON.parse(String(((fetchMock.mock.calls[i] as unknown[])[1] as RequestInit).body))

describe('the picker comes first', () => {
  test('a pick item opens the picker with the plugin and context, before the model gate and the POST', async () => {
    const s = setup()
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.pickSessionSkill).toHaveBeenCalledWith(plugin, context)
    expect(s.order).toEqual(['picker', 'gate', 'post'])
  })

  test('cancelling the picker aborts: no gate, no POST, no job, nothing recorded for Retry', async () => {
    const s = setup({ pick: null })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.gate.ensureFeatureModel).not.toHaveBeenCalled()
    expect(s.fetchMock).not.toHaveBeenCalled()
    expect(s.handlers.onJob).not.toHaveBeenCalled()
    expect(s.handlers.onPicked).not.toHaveBeenCalled()
  })

  test('a pick item with no picker handler starts nothing', async () => {
    const s = setup()
    const { pickSessionSkill: _p, ...noPicker } = s.handlers
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: noPicker })
    expect(s.fetchMock).not.toHaveBeenCalled()
    expect(s.gate.ensureFeatureModel).not.toHaveBeenCalled()
  })

  test('the picked skill is reported (for Retry) before the gate', async () => {
    const s = setup()
    s.handlers.onPicked.mockImplementation(() => { s.order.push('picked') })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.onPicked).toHaveBeenCalledWith(userPick)
    expect(s.order).toEqual(['picker', 'picked', 'gate', 'post'])
  })

  test('cancelling the gate after a pick posts nothing', async () => {
    const s = setup({ model: null })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.order).toEqual(['picker', 'gate'])
    expect(s.fetchMock).not.toHaveBeenCalled()
  })

  test('a replayed pick (Retry) skips the picker and posts the same pick', async () => {
    const s = setup()
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers, pick: userPick })
    expect(s.handlers.pickSessionSkill).not.toHaveBeenCalled()
    expect(s.order).toEqual(['gate', 'post'])
    expect(bodyOf(s.fetchMock).params).toEqual({ pick: { kind: 'session.skill', ref: 'user_skill:sk1' } })
  })
})

describe('the POST', () => {
  test('carries {context, params: {pick: {kind, ref}}} and nothing else of the pick', async () => {
    const s = setup()
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.fetchMock).toHaveBeenCalledWith('/api/plugins/skiller/actions/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ context, params: { pick: { kind: 'session.skill', ref: 'user_skill:sk1' } } }),
    })
  })

  test('without pick the body is exactly {context}, and the picker is never opened', async () => {
    const s = setup({ answer: json(200, { ok: true, result: {} }) })
    await runPluginAction({ plugin, item: item({ pick: undefined, llm: false, async: false }), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.pickSessionSkill).not.toHaveBeenCalled()
    expect(s.handlers.onPicked).not.toHaveBeenCalled()
    expect(((s.fetchMock.mock.calls[0] as unknown[])[1] as RequestInit).body).toBe(JSON.stringify({ context }))
  })

  test('a stray replay pick on an item without pick is not sent', async () => {
    const s = setup({ answer: json(200, { ok: true, result: {} }) })
    await runPluginAction({ plugin, item: item({ pick: undefined, llm: false, async: false }), context, gate: s.gate, handlers: s.handlers, pick: userPick })
    expect(((s.fetchMock.mock.calls[0] as unknown[])[1] as RequestInit).body).toBe(JSON.stringify({ context }))
  })

  test('a refusal of the pick (invalid_pick) is an error toast and opens nothing', async () => {
    const s = setup({ answer: json(400, { code: 'invalid_pick', error: 'This skill cannot be picked in this session.' }) })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.toast.error).toHaveBeenCalledWith('This skill cannot be picked in this session. (invalid_pick · HTTP 400)')
    expect(s.handlers.onJob).not.toHaveBeenCalled()
  })

  test('a sync result with a reviewProposal still opens the review after a pick', async () => {
    const s = setup({ answer: json(200, { ok: true, result: { reviewProposal: { extensionPoint: 'user_skill.text', changeSetId: 'cs_7' } } }) })
    await runPluginAction({ plugin, item: item({ async: false }), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.onReviewProposal).toHaveBeenCalledWith('cs_7')
  })
})

describe('the job answer', () => {
  test('a new job names the picked skill', async () => {
    const s = setup()
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.onJob).toHaveBeenCalledWith({
      jobId: 'job_1', pluginId: 'skiller', displayName: 'Skiller', label: 'Improve skill from this session', skillName: 'My SQLi flow v2 (your skill)',
    })
    expect(s.handlers.toast.info).not.toHaveBeenCalled()
  })

  test('the server-recorded pick wins over the local one for the name', async () => {
    const s = setup({ answer: json(202, { jobId: 'job_1', pick: { ref: 'user_skill:sk1', name: 'My SQLi flow v2 (renamed)' } }) })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.onJob).toHaveBeenCalledWith(expect.objectContaining({ skillName: 'My SQLi flow v2 (renamed) (your skill)' }))
  })

  test('an existing job on ANOTHER skill: the toast names it and the window follows that job', async () => {
    const s = setup({ answer: json(200, { jobId: 'job_0', existing: true, status: 'running', pick: { ref: 'skill.text:sql_injection', name: 'SQL Injection' } }) })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.toast.info).toHaveBeenCalledWith('A job is already working on SQL Injection in this session.')
    expect(s.handlers.onJob).toHaveBeenCalledWith(expect.objectContaining({ jobId: 'job_0', skillName: 'SQL Injection' }))
  })

  test('an existing job on the SAME skill opens it without the toast', async () => {
    const s = setup({ answer: json(200, { jobId: 'job_0', existing: true, pick: { ref: 'user_skill:sk1', name: 'My SQLi flow v2' } }) })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.toast.info).not.toHaveBeenCalled()
    expect(s.handlers.onJob).toHaveBeenCalledWith(expect.objectContaining({ jobId: 'job_0' }))
  })

  test('an existing job whose recorded skill was deleted (name null) is named as a deleted skill', async () => {
    const s = setup({ answer: json(200, { jobId: 'job_0', existing: true, pick: { ref: 'user_skill:gone', name: null } }) })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.toast.info).toHaveBeenCalledWith('A job is already working on a deleted skill in this session.')
    expect(s.handlers.onJob).toHaveBeenCalledWith(expect.objectContaining({ skillName: 'a deleted skill' }))
  })

  test('an existing job started without a pick: the toast says so and the window names no skill, not the new pick', async () => {
    const s = setup({ answer: json(200, { jobId: 'job_0', existing: true }) })
    await runPluginAction({ plugin, item: item(), context, gate: s.gate, handlers: s.handlers })
    expect(s.handlers.toast.info).toHaveBeenCalledWith('A job is already running in this session; it works on the skill it chose itself.')
    const job = s.handlers.onJob.mock.calls[0][0]
    expect(job.jobId).toBe('job_0')
    expect('skillName' in job).toBe(false)
  })

  test('without a pick the job carries no skillName key at all', async () => {
    const s = setup()
    await runPluginAction({ plugin, item: item({ pick: undefined }), context, gate: s.gate, handlers: s.handlers })
    const job = s.handlers.onJob.mock.calls[0][0]
    expect('skillName' in job).toBe(false)
  })
})

describe('pickedSkillLabel', () => {
  test('a user skill is labelled "(your skill)"', () => {
    expect(pickedSkillLabel({ name: 'My SQLi flow v2', skillKind: 'user' })).toBe('My SQLi flow v2 (your skill)')
  })
  test('a built-in skill is its name', () => {
    expect(pickedSkillLabel({ name: 'SQL Injection', skillKind: 'builtin' })).toBe('SQL Injection')
    expect(pickedSkillLabel({ name: 'SQL Injection' })).toBe('SQL Injection')
  })
  test('no name reads "a deleted skill"', () => {
    expect(pickedSkillLabel({ name: null, skillKind: 'user' })).toBe('a deleted skill')
    expect(pickedSkillLabel({ name: null })).toBe('a deleted skill')
  })
  test('without a kind, a user_skill: ref is the person\'s own', () => {
    expect(pickedSkillLabel({ name: 'Mine', ref: 'user_skill:sk1' })).toBe('Mine (your skill)')
    expect(pickedSkillLabel({ name: 'SQL Injection', ref: 'skill.text:sql_injection' })).toBe('SQL Injection')
  })
})
