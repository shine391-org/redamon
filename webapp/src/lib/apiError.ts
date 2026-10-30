/**
 * Read a failed API call into one error whose message says what failed AND why,
 * e.g. "Failed to load users (P2024 · HTTP 500)" or "Could not start scan
 * (orchestrator_unreachable · HTTP 503)". A bug report then carries the cause.
 *
 * Every shape the app meets is handled: our routes' `{error, code}`, FastAPI's
 * `{detail}` (string, object or array), a proxy's HTML 502/504, Next's empty 500,
 * and a request that got no answer at all.
 *
 * Safe in the browser and on the server; the server writes these bodies with
 * `lib/routeErrors.ts`.
 */

const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/
const REASON_MAX = 500
const DETAIL_MAX = 300
const DETAILS_MAX = 10

export interface ApiErrorInit {
  /** The sentence without the code and status, e.g. "Failed to load users". */
  reason: string
  /** HTTP status; 0 when the request got no answer. */
  status: number
  code?: string
  upstreamStatus?: number
  details?: string[]
  /** The parsed body, for callers that read more fields (limit, busy, keys). */
  body?: Record<string, unknown>
}

/** "reason (code · HTTP n · upstream HTTP m)"; just the reason when there is nothing to add. */
export function formatApiError(init: Pick<ApiErrorInit, 'reason' | 'code' | 'status' | 'upstreamStatus'>): string {
  const parts: string[] = []
  if (init.code) parts.push(init.code)
  if (init.status > 0 && !init.reason.includes(`HTTP ${init.status}`) && !init.reason.includes(`(${init.status})`)) {
    parts.push(`HTTP ${init.status}`)
  }
  if (init.upstreamStatus) parts.push(`upstream HTTP ${init.upstreamStatus}`)
  return parts.length ? `${init.reason} (${parts.join(' · ')})` : init.reason
}

export class ApiError extends Error {
  readonly reason: string
  readonly status: number
  readonly code?: string
  readonly upstreamStatus?: number
  readonly details?: string[]
  readonly body?: Record<string, unknown>

  constructor(init: ApiErrorInit) {
    super(formatApiError(init))
    this.name = 'ApiError'
    this.reason = init.reason
    this.status = init.status
    this.code = init.code
    this.upstreamStatus = init.upstreamStatus
    this.details = init.details
    this.body = init.body
  }
}

function text(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined
  const clean = value.replace(/\s+/g, ' ').trim()
  return clean ? clean.slice(0, max) : undefined
}

function detailsOf(body: Record<string, unknown>): string[] | undefined {
  const list = [body.details, body.errors, body.issues].find(Array.isArray) as unknown[] | undefined
  if (!list) return undefined
  const out = list
    .map((d) => text(d, DETAIL_MAX)
      ?? (d && typeof d === 'object' ? text((d as { message?: unknown; msg?: unknown }).message ?? (d as { msg?: unknown }).msg, DETAIL_MAX) : undefined))
    .filter((d): d is string => !!d)
    .slice(0, DETAILS_MAX)
  return out.length ? out : undefined
}

/** The raw text and parsed JSON of a body. A Response-like object with only `json()` is read through it. */
async function readBody(res: Response): Promise<{ raw: string; parsed: unknown }> {
  if (typeof res.text !== 'function') {
    const parsed = typeof res.json === 'function' ? await res.json().catch(() => null) : null
    return { raw: parsed == null ? '' : 'json', parsed }
  }
  const raw = await res.text().catch(() => '')
  try {
    return { raw, parsed: raw ? JSON.parse(raw) : null }
  } catch {
    return { raw, parsed: null }
  }
}

/**
 * An error from a non-OK response. The reason is the body's `error`, else a string
 * `detail` (or an object detail's `detail`), else `message`, else `fallback`.
 * A body that is not JSON gets the code `non_json_response` (`empty_response` when
 * there is none), so a proxy's error page reads differently from our own refusal.
 */
export async function readApiError(res: Response, fallback: string): Promise<ApiError> {
  const { raw, parsed } = await readBody(res)
  const body = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  if (!body) {
    return new ApiError({ reason: fallback, status: res.status, code: raw.trim() ? 'non_json_response' : 'empty_response' })
  }
  const detail = body.detail
  const nested = detail && typeof detail === 'object' && !Array.isArray(detail) ? detail as Record<string, unknown> : null
  const reason = text(body.error, REASON_MAX) ?? text(detail, REASON_MAX) ?? text(nested?.detail, REASON_MAX)
    ?? text(body.message, REASON_MAX) ?? fallback
  const code = [body.code, nested?.code].find((c): c is string => typeof c === 'string' && SAFE_CODE.test(c))
  const upstreamStatus = typeof body.upstreamStatus === 'number' ? body.upstreamStatus : undefined
  const details = detailsOf(body)
  return new ApiError({
    reason,
    status: res.status,
    ...(code ? { code } : {}),
    ...(upstreamStatus ? { upstreamStatus } : {}),
    ...(details ? { details } : {}),
    body,
  })
}

/**
 * An ApiError for anything a catch block receives. A fetch that got no answer
 * (fetch throws a TypeError) is `network_error`; a cancelled one `aborted` or
 * `timeout`; any other error keeps its class name as the code.
 */
export function toApiError(err: unknown, fallback: string): ApiError {
  if (err instanceof ApiError) return err
  const name = err && typeof err === 'object' ? (err as { name?: unknown }).name : undefined
  const code = name === 'AbortError' ? 'aborted'
    : name === 'TimeoutError' ? 'timeout'
      : name === 'TypeError' || name === undefined ? 'network_error'
        : typeof name === 'string' && SAFE_CODE.test(name) && name !== 'Error' ? name : 'client_error'
  return new ApiError({ reason: fallback, status: 0, code })
}

/** `fetch` that throws an ApiError for no answer or a non-OK status, and returns the Response otherwise. */
export async function fetchOk(input: RequestInfo | URL, init: RequestInit | undefined, fallback: string): Promise<Response> {
  let res: Response
  try {
    res = await fetch(input, init)
  } catch (err) {
    throw toApiError(err, fallback)
  }
  if (!res.ok) throw await readApiError(res, fallback)
  return res
}

/** `fetchOk` plus the JSON body; a 204 or an unparsable 2xx body throws (`invalid_json`) rather than returning garbage. */
export async function fetchJson<T>(input: RequestInfo | URL, init: RequestInit | undefined, fallback: string): Promise<T> {
  const res = await fetchOk(input, init, fallback)
  try {
    return await res.json() as T
  } catch {
    throw new ApiError({ reason: fallback, status: res.status, code: 'invalid_json' })
  }
}

/** The text to show for anything a catch block receives. */
export function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message
  if (err instanceof Error && err.message) return err.message
  return fallback
}

export type ApiResult<T> = { ok: true; value: T } | { ok: false; error: ApiError }

/** Run a call and answer with a value instead of throwing, for code that shows each failure where it happened. */
export async function settle<T>(call: () => Promise<T>, fallback: string): Promise<ApiResult<T>> {
  try {
    return { ok: true, value: await call() }
  } catch (err) {
    return { ok: false, error: toApiError(err, fallback) }
  }
}
