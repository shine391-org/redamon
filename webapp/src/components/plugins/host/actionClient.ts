import { readApiError, toApiError } from '@/lib/apiError'
import { pluginFeatureId } from '@/lib/llmFeatures'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'

/**
 * The browser side of POST /api/plugins/<id>/actions/<action> (lib/plugins/actions.ts):
 * a sync action answers `{ok, result | error}`, an async one a job id (202, or 200 with
 * `existing` when the same job is already running), and the platform refuses with
 * `{error, code}` and a status. Everything that is not a result becomes a PluginActionError
 * whose message is safe to show.
 */
export class PluginActionError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status?: number,
  ) {
    super(message)
    this.name = 'PluginActionError'
  }
}

export interface ActionContext {
  projectId?: string | null
  sessionId?: string | null
}

/** The skill a job works on, as the server recorded it (platform 1.1.0). */
export interface JobPickView {
  ref: string
  name: string | null
}

export type ActionAnswer =
  | { kind: 'result'; result: Record<string, unknown> }
  | { kind: 'job'; jobId: string; existing?: boolean; pick?: JobPickView | null }

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

/**
 * A request that got no answer (offline, a reset connection) is a PluginActionError too,
 * `network_error` with status 0, so every place that shows these errors shows it.
 */
export async function postPluginAction(
  pluginId: string,
  action: string,
  body: { context?: ActionContext; params?: Record<string, unknown> },
): Promise<Response> {
  try {
    return await fetch(`/api/plugins/${encodeURIComponent(pluginId)}/actions/${encodeURIComponent(action)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  } catch (e) {
    const err = toApiError(e, 'The plugin action got no answer from RedAmon')
    const offline = typeof navigator !== 'undefined' && navigator.onLine === false
    throw new PluginActionError(err.code ?? 'network_error', offline ? `${err.message}; this browser is offline.` : `${err.message}.`, 0)
  }
}

export async function readActionAnswer(res: Response): Promise<ActionAnswer> {
  if (!res.ok) {
    // "reason (code · HTTP n · upstream HTTP m)": the runner's status rides along when it failed.
    const err = await readApiError(res, 'The plugin action failed')
    throw new PluginActionError(err.code ?? `http_${res.status}`, err.message, res.status)
  }
  const body: unknown = await res.json().catch(() => null)
  if (isObj(body) && typeof body.jobId === 'string') {
    const pick = isObj(body.pick) && typeof body.pick.ref === 'string'
      ? { ref: body.pick.ref, name: typeof body.pick.name === 'string' ? body.pick.name : null }
      : null
    return { kind: 'job', jobId: body.jobId, ...(body.existing === true ? { existing: true } : {}), ...(pick ? { pick } : {}) }
  }
  if (isObj(body) && body.ok === true && isObj(body.result)) return { kind: 'result', result: body.result }
  if (isObj(body) && body.ok === false) {
    const e = body.error
    if (isObj(e)) {
      throw new PluginActionError(
        typeof e.code === 'string' ? e.code : 'action_failed',
        typeof e.message === 'string' ? e.message : 'The plugin action failed.',
      )
    }
    throw new PluginActionError('action_failed', typeof e === 'string' && e ? e : 'The plugin action failed.')
  }
  throw new PluginActionError('bad_answer', 'The plugin answered in a form RedAmon cannot read.')
}

/**
 * The action runner a plugin screen uses: through the model gate (an LLM action with no
 * model chosen opens "Choose a model" and runs once more), and only sync actions, since a
 * screen needs the data now; a job answer is an error the screen shows.
 */
export function createScreenRunAction(opts: {
  pluginId: string
  displayName: string
  context: ActionContext
  gate: Pick<FeatureModelGateApi, 'fetchWithFeatureModel'>
}) {
  const { pluginId, displayName, context, gate } = opts
  return async (action: string, params: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const res = await gate.fetchWithFeatureModel(
      pluginFeatureId(pluginId),
      () => postPluginAction(pluginId, action, { context, params }),
      { label: displayName },
    )
    const answer = await readActionAnswer(res)
    if (answer.kind === 'job') {
      throw new PluginActionError('async_action', 'This action runs as a background job and cannot fill this screen.')
    }
    return answer.result
  }
}
