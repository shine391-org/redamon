/**
 * The webapp's client for the plugin runner's supervisor (README.PLUGINS.md §5.3, TD-08),
 * reached through the plugin-gateway proxy at PLUGIN_RUNNER_URL. The wire format is
 * pinned by services/plugin_runner/tests/runner_contract_cases.json, which also runs
 * against the fake runner behind this module's tests.
 *
 * Fails closed: without a runner key no request is sent. Every transport failure (no
 * answer, a timeout, a redirect, an answer that is not JSON, the proxy reporting that it
 * could not reach the runner or is full) is a RunnerUnavailableError, which routes turn
 * into 503 `runner_unavailable`; an answer with `{error, code}` is a RunnerError with the
 * runner's status and code. Nothing else of the platform depends on
 * the runner: approved skill versions are data and keep applying while it is down (D-21).
 */
import { PLUGIN_ID_RE } from './ids'
import { ACTION_ID_RE } from './schemas/common'

export const RUNNER_KEY_HEADER = 'X-Plugin-Runner-Key'
const DEFAULT_RUNNER_URL = 'http://plugin-gateway:7072'
const JOB_ID_RE = /^[A-Za-z0-9_-]{1,200}$/
// reload: waits for new workers to say ready (up to 30 s), then stops and scrubs the
// replaced ones.
// migrate: the runner's worst case for one batch (worker start 30 s, the batch 120 s, clean-up
// and UID scrub 37 s; runnerClient.migrate.test.ts reads them from its config) plus a margin.
export const RUNNER_TIMEOUTS = { health: 3_000, reload: 90_000, small: 10_000, migrate: 200_000 }
// The plugin-gateway proxy's own answers (gateway_proxy/proxy.py): the runner behind it was
// not reached, so they are not the runner's errors.
const PROXY_UNAVAILABLE: Record<string, UnavailableReason> = {
  upstream_unreachable: 'unreachable',
  upstream_timeout: 'timeout',
  upstream_response_too_large: 'bad_response',
  proxy_busy: 'unreachable',
}
// An action may use its whole timeout; the supervisor answers 504 itself just after.
const ACTION_MARGIN_MS = 10_000

export type UnavailableReason = 'not_configured' | 'unreachable' | 'timeout' | 'bad_response'

export class RunnerUnavailableError extends Error {
  readonly code = 'runner_unavailable'
  constructor(
    message: string,
    readonly reason: UnavailableReason,
    /** The plugin-gateway proxy's own code (`upstream_timeout`, `proxy_busy`) when it answered. */
    readonly proxyCode?: string,
  ) {
    super(message)
    this.name = 'RunnerUnavailableError'
  }
}

export class RunnerError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'RunnerError'
  }
}

/**
 * A runner failure in one short line for a plugin's `lastError` and the log:
 * `runner_unavailable (timeout)`, `runner_unavailable (unreachable, proxy_busy)`,
 * `runner_error: <code> (HTTP n)`. Only codes and the status: both errors' messages are
 * the platform's own, but a line that is stored and shown stays terse.
 */
export function runnerFailureSummary(e: RunnerUnavailableError | RunnerError): string {
  if (e instanceof RunnerUnavailableError) {
    return `runner_unavailable (${e.reason}${e.proxyCode ? `, ${e.proxyCode}` : ''})`
  }
  return `runner_error: ${e.code} (HTTP ${e.status})`
}

export interface RunnerConfig {
  baseUrl: string
  key: string
  /** Overrides for tests, in milliseconds. */
  timeouts?: Partial<typeof RUNNER_TIMEOUTS>
}

export function runnerConfig(): RunnerConfig {
  return {
    baseUrl: (process.env.PLUGIN_RUNNER_URL || DEFAULT_RUNNER_URL).trim().replace(/\/+$/, ''),
    key: (process.env.PLUGIN_RUNNER_KEY || '').trim(),
  }
}

export function actionTimeoutMs(timeoutSeconds: number): number {
  return timeoutSeconds * 1000 + ACTION_MARGIN_MS
}

export interface RunnerWorker {
  id: string
  version: string
  pid: number | null
  uid: number | null
  inFlight: number
  startedAt: string | null
  restarts: number
  state?: string
}

export interface RunnerHealth {
  platformVersion: string
  bootId: string
  state: 'ok' | 'out_of_date' | 'degraded'
  workers: RunnerWorker[]
}

export interface ActionRequest {
  token: string
  params: Record<string, unknown>
  ctx: Record<string, unknown>
  timeoutSeconds: number
  async?: boolean
  jobId?: string
}

export type ActionOutcome =
  | { kind: 'result'; ok: true; result: Record<string, unknown> }
  | { kind: 'result'; ok: false; error: { code: string; message: string } }
  /** `bootId`: the runner that took the job (TD-22); null from a runner that does not say. */
  | { kind: 'accepted'; jobId: string; bootId: string | null }

async function call(
  config: RunnerConfig,
  method: 'GET' | 'POST',
  path: string,
  timeoutMs: number,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!config.key || config.key === 'changeme') {
    throw new RunnerUnavailableError('The plugin runner key is not configured.', 'not_configured')
  }
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  // Set last, so nothing above can replace it.
  headers[RUNNER_KEY_HEADER] = config.key
  let res: Response
  try {
    res = await fetch(config.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'manual',
      cache: 'no-store',
    })
  } catch (e) {
    const name = (e as { name?: string })?.name
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new RunnerUnavailableError(`The plugin runner did not answer within ${timeoutMs} ms.`, 'timeout')
    }
    throw new RunnerUnavailableError('The plugin runner could not be reached.', 'unreachable')
  }
  if (res.status >= 300 && res.status < 400) {
    throw new RunnerUnavailableError(`The plugin runner answered with a redirect (HTTP ${res.status}).`, 'bad_response')
  }
  let parsed: unknown = null
  try {
    parsed = JSON.parse(await res.text())
  } catch {
    parsed = null
  }
  const obj = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null
  if (!res.ok) {
    if (obj && typeof obj.code === 'string' && typeof obj.error === 'string') {
      const proxyReason = Object.hasOwn(PROXY_UNAVAILABLE, obj.code) ? PROXY_UNAVAILABLE[obj.code] : undefined
      if (proxyReason) throw new RunnerUnavailableError(`The plugin runner is unavailable (${obj.code}).`, proxyReason, obj.code)
      throw new RunnerError(res.status, obj.code, obj.error)
    }
    throw new RunnerError(res.status, 'runner_error', `The plugin runner answered HTTP ${res.status}.`)
  }
  if (!obj) throw new RunnerUnavailableError('The plugin runner answered with something that is not JSON.', 'bad_response')
  return { status: res.status, body: obj }
}

function segment(value: string, re: RegExp, what: string): string {
  if (typeof value !== 'string' || !re.test(value)) throw new TypeError(`invalid ${what} ${JSON.stringify(value)}`)
  return value
}

export async function runnerHealth(config: RunnerConfig = runnerConfig()): Promise<RunnerHealth> {
  const out = await call(config, 'GET', '/runner/v1/health', config.timeouts?.health ?? RUNNER_TIMEOUTS.health)
  const b = out.body
  if (typeof b.platformVersion !== 'string' || typeof b.bootId !== 'string' || typeof b.state !== 'string' ||
      !Array.isArray(b.workers)) {
    throw new RunnerUnavailableError('The plugin runner answered /health with an unexpected shape.', 'bad_response')
  }
  return b as unknown as RunnerHealth
}

export async function runnerReload(
  config: RunnerConfig = runnerConfig(),
): Promise<{ ok: boolean; state?: string; workers?: number }> {
  const out = await call(config, 'POST', '/runner/v1/reload', config.timeouts?.reload ?? RUNNER_TIMEOUTS.reload)
  return out.body as { ok: boolean; state?: string; workers?: number }
}

export async function runAction(
  pluginId: string,
  actionId: string,
  req: ActionRequest,
  config: RunnerConfig = runnerConfig(),
): Promise<ActionOutcome> {
  const path =
    `/runner/v1/plugins/${segment(pluginId, PLUGIN_ID_RE, 'plugin id')}` +
    `/actions/${segment(actionId, ACTION_ID_RE, 'action id')}`
  if (req.jobId !== undefined) segment(req.jobId, JOB_ID_RE, 'job id')
  if (req.async === true && req.jobId === undefined) throw new TypeError('an async action needs the job id')
  const body = { ...req, async: req.async === true }
  const out = await call(config, 'POST', path, actionTimeoutMs(req.timeoutSeconds), body)
  if (out.status === 202) {
    const bootId = typeof out.body.bootId === 'string' && out.body.bootId ? out.body.bootId : null
    return { kind: 'accepted', jobId: String(out.body.jobId), bootId }
  }
  if (out.body.ok === true) {
    return { kind: 'result', ok: true, result: (out.body.result ?? {}) as Record<string, unknown> }
  }
  return { kind: 'result', ok: false, error: out.body.error as { code: string; message: string } }
}

/** True when the job was running and is being cancelled, false when it is not running. */
export async function cancelJob(pluginId: string, jobId: string, config: RunnerConfig = runnerConfig()): Promise<boolean> {
  const path =
    `/runner/v1/plugins/${segment(pluginId, PLUGIN_ID_RE, 'plugin id')}` +
    `/jobs/${segment(jobId, JOB_ID_RE, 'job id')}/cancel`
  try {
    await call(config, 'POST', path, config.timeouts?.small ?? RUNNER_TIMEOUTS.small, {})
    return true
  } catch (e) {
    if (e instanceof RunnerError && e.status === 404 && e.code === 'unknown_job') return false
    throw e
  }
}

export interface MigrationRow {
  /** The data row's id: how the answer is matched back to it. */
  id: string
  collection: string
  key: string
  ownerType: 'user' | 'project'
  value: unknown
}

export type MigrationAnswer = { id: string; value: unknown } | { id: string; delete: true }

export interface MigrationRequest {
  version: string
  step: number
  direction: 'up' | 'down'
  rows: MigrationRow[]
}

const VERSION_RE = /^\d+\.\d+\.\d+$/

/**
 * One batch of a data migration (TD-28): the rows through the plugin's `migrate_row` of
 * `step` in a temporary worker of `version`. The request carries no call token. A batch
 * that fails is a RunnerError with the runner's code (`migration_failed`,
 * `migration_missing`, `invalid_migration`, `invalid_result`, `result_too_large`,
 * `migration_timeout`, `unknown_version`).
 */
export async function runMigration(
  pluginId: string,
  req: MigrationRequest,
  config: RunnerConfig = runnerConfig(),
): Promise<MigrationAnswer[]> {
  const path = `/runner/v1/plugins/${segment(pluginId, PLUGIN_ID_RE, 'plugin id')}/migrate`
  if (typeof req.version !== 'string' || !VERSION_RE.test(req.version)) throw new TypeError(`invalid version ${JSON.stringify(req.version)}`)
  if (!Number.isInteger(req.step) || req.step < 2 || req.step > 9999) throw new TypeError(`invalid migration step ${req.step}`)
  if (req.direction !== 'up' && req.direction !== 'down') throw new TypeError(`invalid direction ${JSON.stringify(req.direction)}`)
  const body = { version: req.version, step: req.step, direction: req.direction, rows: req.rows }
  const out = await call(config, 'POST', path, config.timeouts?.migrate ?? RUNNER_TIMEOUTS.migrate, body)
  if (!Array.isArray(out.body.results)) {
    throw new RunnerUnavailableError('The plugin runner answered a migration without results.', 'bad_response')
  }
  return out.body.results as MigrationAnswer[]
}

export async function pluginLogs(pluginId: string, lines: number, config: RunnerConfig = runnerConfig()): Promise<string[]> {
  const n = Math.max(1, Math.min(1000, Math.floor(lines) || 1))
  const path = `/runner/v1/plugins/${segment(pluginId, PLUGIN_ID_RE, 'plugin id')}/logs?lines=${n}`
  const out = await call(config, 'GET', path, config.timeouts?.small ?? RUNNER_TIMEOUTS.small)
  return Array.isArray(out.body.lines) ? (out.body.lines as string[]) : []
}
