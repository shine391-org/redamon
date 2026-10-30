/**
 * The text of an agent ERROR frame (live, or a persisted `error` row on
 * restore): its sentence plus what the agent sent about the cause, e.g.
 * "The agent run failed (agent_run_failed · RateLimitError · provider HTTP 429)".
 *
 * The agent sends an exception's class and a status, never its text, so each
 * part is safe to show; anything that does not look like one is dropped.
 */

const CODE = /^[a-z][a-z0-9_]{0,63}$/
const CLASS_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/

export interface AgentErrorPayload {
  message?: unknown
  code?: unknown
  error_class?: unknown
  provider_status?: unknown
  http_status?: unknown
}

const httpStatus = (v: unknown): number | null =>
  typeof v === 'number' && Number.isInteger(v) && v >= 100 && v <= 599 ? v : null

export function agentErrorText(payload: AgentErrorPayload | null | undefined, fallback = 'Agent error'): string {
  const p = payload ?? {}
  const message = typeof p.message === 'string' && p.message.trim() ? p.message.trim() : fallback
  const parts: string[] = []
  if (typeof p.code === 'string' && CODE.test(p.code)) parts.push(p.code)
  if (typeof p.error_class === 'string' && CLASS_NAME.test(p.error_class)) parts.push(p.error_class)
  const provider = httpStatus(p.provider_status)
  if (provider) parts.push(`provider HTTP ${provider}`)
  const http = httpStatus(p.http_status)
  if (http) parts.push(`HTTP ${http}`)
  return parts.length ? `${message} (${parts.join(' · ')})` : message
}

/** The one-time "chat is not being saved" notice: shown, but it does not end the run. */
export function isPersistFailedNotice(payload: AgentErrorPayload | null | undefined): boolean {
  return payload?.code === 'persist_failed'
}
