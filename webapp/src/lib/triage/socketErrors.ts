/**
 * What the CypherFix sockets (triage and CodeFix) show when something fails.
 *
 * The agent sends a fixed sentence plus safe facts: its code, the webapp's or
 * the provider's HTTP status, an exception's class, the phase or git step it
 * died in. Each fact is re-checked here against a strict shape before it is
 * shown, so an older or misbehaving agent cannot put free text on screen
 * through a field meant for a code.
 */
import { providerFailureDetail } from '@/lib/llmFeatures'

const CODE = /^[a-z][a-z0-9_]{0,63}$/
const CLASS = /^[A-Za-z_][A-Za-z0-9_.]{0,79}$/
const GITHUB_MESSAGE = /^[A-Za-z][A-Za-z ,.'-]{0,79}$/
const REASON_MAX = 120

function str(value: unknown, shape: RegExp): string | undefined {
  return typeof value === 'string' && shape.test(value) ? value : undefined
}

function httpStatus(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599 ? value : undefined
}

/** "message (code · upstream HTTP 409 · RateLimitError · provider HTTP 429 · in reviewing)". */
export function socketErrorText(payload: Record<string, unknown>, fallback = 'Unknown error'): string {
  const message = typeof payload.message === 'string' && payload.message ? payload.message : fallback
  const parts: string[] = []
  const code = str(payload.code, CODE)
  if (code) parts.push(code)
  const upstream = httpStatus(payload.upstream_status)
  if (upstream) parts.push(`upstream HTTP ${upstream}`)
  const provider = providerFailureDetail(payload)
  if (provider) {
    parts.push(provider)
  } else {
    const cls = str(payload.error_class, CLASS)
    if (cls) parts.push(cls)
  }
  const step = str(payload.step, CODE)
  if (step) parts.push(`step ${step}`)
  if (typeof payload.git_exit_code === 'number' && Number.isInteger(payload.git_exit_code)) {
    parts.push(`git exit ${payload.git_exit_code}`)
  }
  const cause = str(payload.cause, CODE)
  if (cause) parts.push(cause)
  const github = httpStatus(payload.github_status)
  if (github) parts.push(`GitHub HTTP ${github}`)
  const githubMessage = str(payload.github_message, GITHUB_MESSAGE)
  if (githubMessage) parts.push(`GitHub: ${githubMessage}`)
  const phase = str(payload.phase, CODE)
  if (phase) parts.push(`in ${phase}`)
  return parts.length ? `${message} (${parts.join(' · ')})` : message
}

/** True for a close the page did not ask for and the agent did not end cleanly. */
export function isAbnormalClose(event: Pick<CloseEvent, 'code'>): boolean {
  // 1000: a clean close; 1005: no status, which is what our own close() sends.
  return event.code !== 1000 && event.code !== 1005
}

/**
 * "<what> (code 1008: missing or invalid ticket)". The reason is the agent's
 * own fixed text; 1006 never has one, because the browser writes it when the
 * connection dropped or was refused before the agent could say why.
 */
export function closeEventText(what: string, event: Pick<CloseEvent, 'code' | 'reason'>): string {
  const reason = typeof event.reason === 'string'
    ? event.reason.replace(/[^\x20-\x7E]/g, '').trim().slice(0, REASON_MAX)
    : ''
  if (reason) return `${what} (code ${event.code}: ${reason})`
  if (event.code === 1006) {
    return `${what} (code 1006: no reason given; the agent is down, restarting or refused the connection)`
  }
  return `${what} (code ${event.code})`
}

/**
 * The complete event's note on reviews that should have run and did not, or
 * null. Without it a run whose every review hit a bad key or a 429 completed
 * looking like a clean one.
 */
export function reviewNoticeText(payload: Record<string, unknown>): string | null {
  const detail = providerFailureDetail(payload) || str(payload.error_class, CLASS) || ''
  const why = detail ? ` (${detail})` : ''
  if (payload.review_unavailable) {
    return `The AI review did not run: the Triage review model could not be set up${why}. ` +
      'Every finding keeps its rules-only ranking.'
  }
  const failed = payload.review_failed
  if (typeof failed === 'number' && failed > 0) {
    return `The AI review failed for ${failed} finding${failed === 1 ? '' : 's'}${why}. ` +
      'They keep their rules-only ranking; run triage again to review them.'
  }
  return null
}
