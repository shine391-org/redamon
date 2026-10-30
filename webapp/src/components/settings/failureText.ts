/**
 * Text for two failures the settings surfaces show beside their own wording:
 * a load or write that failed (keep the sentence the UI already had, add the
 * cause), and a save that was stored but whose follow-up call failed (the
 * `warnings` a settings or MCP route answers with its 200).
 */
import { formatApiError, toApiError } from '@/lib/apiError'

/** The UI's own sentence plus the cause the error carries: "Couldn't load your providers (P1001 · HTTP 500)". */
export function failureText(reason: string, err: unknown): string {
  const e = toApiError(err, reason)
  return formatApiError({ reason, code: e.code, status: e.status, upstreamStatus: e.upstreamStatus })
}

interface SaveWarning {
  message: string
  code?: string
  upstreamStatus?: number
  cause?: string
}

function isSaveWarning(value: unknown): value is SaveWarning {
  return !!value && typeof value === 'object' && typeof (value as SaveWarning).message === 'string'
}

/**
 * The `warnings` of a save's answer, one line each:
 * "The capture proxy was not started (orchestrator_unreachable · ECONNREFUSED)".
 */
export function saveWarningLines(body: unknown): string[] {
  const list = body && typeof body === 'object' ? (body as { warnings?: unknown }).warnings : undefined
  if (!Array.isArray(list)) return []
  return list.filter(isSaveWarning).map(w => {
    const parts = [
      typeof w.code === 'string' ? w.code : null,
      typeof w.cause === 'string' ? w.cause : null,
      typeof w.upstreamStatus === 'number' ? `upstream HTTP ${w.upstreamStatus}` : null,
    ].filter((p): p is string => !!p)
    return parts.length ? `${w.message} (${parts.join(' · ')})` : w.message
  })
}

/**
 * A toast line for an action that failed: "Delete failed: Resource not found (HTTP 404)"
 * when the server answered, "Delete failed (network_error)" when nothing did.
 */
export function actionFailedText(action: string, err: unknown): string {
  const e = toApiError(err, `${action} failed`)
  return e.status ? `${action} failed: ${e.message}` : e.message
}
