/**
 * The gear-menu click flow (design §6 chat.session.actions), testable without the bar. An
 * `llm` action goes through the model gate first and a cancel there aborts; a sync result
 * with a reviewProposal opens the review, any other result shows a toast or a result screen;
 * an async action opens the job modal. A coreScreen item opens a core screen instead.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { runPluginAction, type PluginActionHandlers } from './runPluginAction'
import type { ChatSessionActionContribution } from '@/lib/plugins/contributions'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

function gate(model: string | null = 'anthropic/claude'): FeatureModelGateApi & { ensureFeatureModel: ReturnType<typeof vi.fn> } {
  return {
    ensureFeatureModel: vi.fn(async () => model),
    fetchWithFeatureModel: vi.fn(),
    userId: 'u1',
    savedVersion: 0,
  } as never
}

function handlers(over: Partial<PluginActionHandlers> = {}): PluginActionHandlers {
  return {
    onReviewProposal: vi.fn(),
    onCoreScreen: vi.fn(),
    onJob: vi.fn(),
    toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
    ...over,
  }
}

const action = (over: Partial<ChatSessionActionContribution> = {}): ChatSessionActionContribution => ({
  key: 'analyze',
  label: 'Analyze',
  action: 'analyze',
  llm: false,
  async: false,
  ...over,
})

const plugin = { pluginId: 'skiller', displayName: 'Skiller' }
const context = { projectId: 'p1', sessionId: 's1' }

describe('coreScreen items', () => {
  test('open the named core screen, never an action call', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn())
    await runPluginAction({ plugin, item: action({ action: undefined, coreScreen: 'skill.text.versions', llm: false, async: false }), context, gate: gate(), handlers: h })
    expect(h.onCoreScreen).toHaveBeenCalledWith('skill.text.versions', context)
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('the model gate', () => {
  test('an llm action asks for a model first, under the plugin feature id with the display name', async () => {
    const g = gate()
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { ok: true, result: { message: 'ok' } })))
    await runPluginAction({ plugin, item: action({ llm: true }), context, gate: g, handlers: handlers() })
    expect(g.ensureFeatureModel).toHaveBeenCalledWith('plugin:skiller', { label: 'Skiller' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  test('cancelling the gate aborts: no action call', async () => {
    const g = gate(null)
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn())
    await runPluginAction({ plugin, item: action({ llm: true }), context, gate: g, handlers: h })
    expect(fetch).not.toHaveBeenCalled()
    expect(h.onJob).not.toHaveBeenCalled()
  })

  test('a non-llm action does not touch the gate', async () => {
    const g = gate()
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { ok: true, result: {} })))
    await runPluginAction({ plugin, item: action(), context, gate: g, handlers: handlers() })
    expect(g.ensureFeatureModel).not.toHaveBeenCalled()
  })
})

describe('the POST and its answer', () => {
  test('posts the context (not params) to the action route', async () => {
    const fetchMock = vi.fn(async () => json(200, { ok: true, result: {} }))
    vi.stubGlobal('fetch', fetchMock)
    await runPluginAction({ plugin, item: action(), context, gate: gate(), handlers: handlers() })
    expect(fetchMock).toHaveBeenCalledWith('/api/plugins/skiller/actions/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ context }),
    })
  })

  test('a sync result with a reviewProposal opens the review on its change set', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { ok: true, result: { reviewProposal: { extensionPoint: 'skill.text', changeSetId: 'cs_1' } } })))
    await runPluginAction({ plugin, item: action(), context, gate: gate(), handlers: h })
    expect(h.onReviewProposal).toHaveBeenCalledWith('cs_1')
  })

  test('a plain result shows its message as a toast', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { ok: true, result: { message: 'Nothing to improve' } })))
    await runPluginAction({ plugin, item: action(), context, gate: gate(), handlers: h })
    expect(h.toast.info).toHaveBeenCalledWith('Nothing to improve')
    expect(h.onReviewProposal).not.toHaveBeenCalled()
  })

  test('an async action opens the job modal with the job id and the plugin', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => json(202, { jobId: 'job_9' })))
    await runPluginAction({ plugin, item: action({ async: true }), context, gate: gate(), handlers: h })
    expect(h.onJob).toHaveBeenCalledWith({ jobId: 'job_9', pluginId: 'skiller', displayName: 'Skiller', label: 'Analyze' })
  })

  test('an already-running job (200 existing) opens the modal too', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { jobId: 'job_9', status: 'running', existing: true })))
    await runPluginAction({ plugin, item: action({ async: true }), context, gate: gate(), handlers: h })
    expect(h.onJob).toHaveBeenCalledWith(expect.objectContaining({ jobId: 'job_9' }))
  })

  test('a refusal is shown as an error toast and opens nothing', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => json(409, { error: 'This plugin is disabled or not ready.', code: 'plugin_unavailable' })))
    await runPluginAction({ plugin, item: action(), context, gate: gate(), handlers: h })
    expect(h.toast.error).toHaveBeenCalledWith('This plugin is disabled or not ready. (plugin_unavailable · HTTP 409)')
    expect(h.onJob).not.toHaveBeenCalled()
    expect(h.onReviewProposal).not.toHaveBeenCalled()
  })

  test('a runner that is down: the reason, the code and the status reach the toast', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => json(503, {
      error: 'The plugin runner did not answer in time (upstream_timeout); the action may still have run.',
      code: 'runner_unavailable',
      reason: 'timeout',
      proxyCode: 'upstream_timeout',
    })))
    await runPluginAction({ plugin, item: action(), context, gate: gate(), handlers: h })
    expect(h.toast.error).toHaveBeenCalledWith('The plugin runner did not answer in time (upstream_timeout); the action may still have run. (runner_unavailable · HTTP 503)')
  })

  test('no answer at all is a named network failure, not a generic one', async () => {
    const h = handlers()
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    }))
    await runPluginAction({ plugin, item: action(), context, gate: gate(), handlers: h })
    expect(h.toast.error).toHaveBeenCalledWith('The plugin action got no answer from RedAmon (network_error).')
  })
})
