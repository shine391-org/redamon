/**
 * Shared shape of a failed scan-start attempt, readable synchronously right after
 * a start* call resolves (via each status hook's getLastStartError()).
 *
 * `status` is the HTTP status of the rejected start. It is the ONLY reliable
 * temporary-vs-permanent signal: a memory-governor refusal without a structured
 * `limit` object still arrives as a 409, and an "already active for project X"
 * refusal is a plain string with no limit at all. All seven start hooks used to
 * drop it (see Scan Queue plan Phase 0.2); they now keep it.
 */
import { readApiError, toApiError } from './apiError'

export interface ScanStartLimit {
  limitType?: 'hard' | 'ram'
  settingName?: string | null
  detail?: string
  current?: number
  ceiling?: number
}

export interface ScanStartError {
  message: string
  limit?: ScanStartLimit
  /** 0 when the start request got no answer at all. */
  status?: number
  /** Why, when the route or the orchestrator says: orchestrator_unreachable, spawn_failed, P2024. */
  code?: string
  upstreamStatus?: number
}

/** The ScanStartError of a non-OK start answer, whatever its body (a proxy's HTML page too). */
export async function readScanStartError(res: Response, fallback: string): Promise<ScanStartError> {
  const e = await readApiError(res, fallback)
  const limit = e.body?.limit
  return {
    message: e.reason,
    status: e.status,
    ...(e.code ? { code: e.code } : {}),
    ...(e.upstreamStatus ? { upstreamStatus: e.upstreamStatus } : {}),
    ...(limit && typeof limit === 'object' ? { limit: limit as ScanStartLimit } : {}),
  }
}

/** The ScanStartError of a start request that got no answer (`network_error`, `timeout`). */
export function scanStartNetworkError(err: unknown, fallback: string): ScanStartError {
  const e = toApiError(err, fallback)
  return { message: e.reason, status: e.status, ...(e.code ? { code: e.code } : {}) }
}
