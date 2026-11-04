/**
 * How the browser calls a plugin action (POST /api/plugins/<id>/actions/<action>) and reads
 * the answer: a result, a job, or a named failure. A screen's call goes through the model
 * gate, so `model_required` opens "Choose a model" and retries once (design §6 bindings).
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { PluginActionError, createScreenRunAction, postPluginAction, readActionAnswer } from './actionClient'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('readActionAnswer', () => {
  test('a sync result', async () => {
    expect(await readActionAnswer(json(200, { ok: true, result: { items: [] } }))).toEqual({
      kind: 'result',
      result: { items: [] },
    })
  })

  test('a started job (202) and an already running one (200 with existing)', async () => {
    expect(await readActionAnswer(json(202, { jobId: 'job_1' }))).toEqual({ kind: 'job', jobId: 'job_1' })
    expect(await readActionAnswer(json(200, { jobId: 'job_2', status: 'running', existing: true }))).toEqual({
      kind: 'job',
      jobId: 'job_2',
      existing: true,
    })
  })

  test('an already running job names the skill it works on (platform 1.1.0)', async () => {
    const res = json(200, { jobId: 'job_3', status: 'running', existing: true, pick: { kind: 'session.skill', ref: 'user_skill:c1', name: 'My flow' } })
    expect(await readActionAnswer(res)).toEqual({ kind: 'job', jobId: 'job_3', existing: true, pick: { ref: 'user_skill:c1', name: 'My flow' } })
  })

  test('a failure the plugin reported, as an object or as text', async () => {
    await expect(readActionAnswer(json(200, { ok: false, error: { code: 'bad_input', message: 'No such item' } }))).rejects.toMatchObject({
      code: 'bad_input',
      message: 'No such item',
    })
    await expect(readActionAnswer(json(200, { ok: false, error: 'boom' }))).rejects.toMatchObject({
      code: 'action_failed',
      message: 'boom',
    })
  })

  test('a refusal from the platform keeps its code, message and status', async () => {
    const err = await readActionAnswer(json(409, { error: 'This plugin is disabled or not ready.', code: 'plugin_unavailable' })).catch((e) => e)
    expect(err).toBeInstanceOf(PluginActionError)
    // What the person sees carries the code and the status, so a screenshot names the cause.
    expect(err).toMatchObject({ code: 'plugin_unavailable', status: 409, message: 'This plugin is disabled or not ready. (plugin_unavailable · HTTP 409)' })
  })

  test("a runner failure shows the runner's own status beside the platform's", async () => {
    const res = json(502, { error: 'The plugin runner could not run this action (worker_crashed); its log has the details.', code: 'runner_error', upstreamStatus: 500, runnerCode: 'worker_crashed' })
    const err = await readActionAnswer(res).catch((e) => e)
    expect(err).toMatchObject({ code: 'runner_error', status: 502 })
    expect(err.message).toBe('The plugin runner could not run this action (worker_crashed); its log has the details. (runner_error · HTTP 502 · upstream HTTP 500)')
  })

  test('a non-JSON error page is still a named failure, with its status', async () => {
    const err = await readActionAnswer(new Response('<html>bad gateway</html>', { status: 502 })).catch((e) => e)
    expect(err).toMatchObject({ code: 'non_json_response', status: 502, message: 'The plugin action failed (non_json_response · HTTP 502)' })
  })

  test("Next's empty 500 says so", async () => {
    const err = await readActionAnswer(new Response('', { status: 500 })).catch((e) => e)
    expect(err).toMatchObject({ code: 'empty_response', status: 500, message: 'The plugin action failed (empty_response · HTTP 500)' })
  })

  test('a request that got no answer is a named failure with status 0, offline said when the browser knows', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const err = await postPluginAction('echo', 'run', {}).catch((e) => e)
    expect(err).toBeInstanceOf(PluginActionError)
    expect(err).toMatchObject({ code: 'network_error', status: 0, message: 'The plugin action got no answer from RedAmon (network_error).' })
    const online = vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false)
    const offline = await postPluginAction('echo', 'run', {}).catch((e) => e)
    expect(offline.message).toBe('The plugin action got no answer from RedAmon (network_error); this browser is offline.')
    online.mockRestore()
  })

  test('a 200 that is neither a result nor a job is refused', async () => {
    await expect(readActionAnswer(json(200, { ok: true, result: 'text' }))).rejects.toMatchObject({ code: 'bad_answer' })
  })
})

describe('postPluginAction', () => {
  test('POSTs JSON with the context and params to the action route', async () => {
    const fetchMock = vi.fn(async () => json(200, { ok: true, result: {} }))
    vi.stubGlobal('fetch', fetchMock)
    await postPluginAction('echo', 'list_items', { context: { projectId: 'p1' }, params: { q: 'x' } })
    expect(fetchMock).toHaveBeenCalledWith('/api/plugins/echo/actions/list_items', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ context: { projectId: 'p1' }, params: { q: 'x' } }),
    })
  })

  test('ids are path-encoded', async () => {
    const fetchMock = vi.fn(async () => json(200, { ok: true, result: {} }))
    vi.stubGlobal('fetch', fetchMock)
    await postPluginAction('echo', '../x', {})
    expect((fetchMock.mock.calls[0] as unknown[])[0]).toBe('/api/plugins/echo/actions/..%2Fx')
  })
})

describe('createScreenRunAction', () => {
  function gate(): FeatureModelGateApi & { fetchWithFeatureModel: ReturnType<typeof vi.fn> } {
    return {
      ensureFeatureModel: vi.fn(),
      fetchWithFeatureModel: vi.fn((_f: unknown, doFetch: () => Promise<Response>) => doFetch()),
      userId: 'u1',
      savedVersion: 0,
    } as never
  }

  test('runs through the model gate under the plugin feature id and resolves the result', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { ok: true, result: { a: 1 } })))
    const g = gate()
    const run = createScreenRunAction({ pluginId: 'echo', displayName: 'Echo', context: { projectId: 'p1' }, gate: g })
    expect(await run('list_items', { q: 1 })).toEqual({ a: 1 })
    expect(g.fetchWithFeatureModel).toHaveBeenCalledWith('plugin:echo', expect.any(Function), { label: 'Echo' })
  })

  test('an action that answers with a job cannot fill a screen', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(202, { jobId: 'job_1' })))
    const run = createScreenRunAction({ pluginId: 'echo', displayName: 'Echo', context: {}, gate: gate() })
    await expect(run('echo_skill', {})).rejects.toMatchObject({ code: 'async_action' })
  })
})
