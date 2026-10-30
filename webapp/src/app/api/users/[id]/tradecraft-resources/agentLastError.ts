/**
 * The `lastError` a failed agent verify or refresh stores on the resource, which
 * the Tradecraft list shows. It carries a code and the agent's status only: the
 * agent answers a failure with `str(exc)`, and an LLM setup error there can
 * quote a provider's answer, so neither its text nor a raw exception is stored.
 */
import { AgentUnreachableError } from '@/lib/agentFetch'
import { safeErrorCode, upstreamFailure } from '@/lib/routeErrors'

type AgentAction = 'verify' | 'refresh'

/** The agent answered with an error: "refresh failed (agent_error, agent HTTP 503)". */
export function agentAnswerLastError(action: AgentAction, code: string, agentStatus: number): string {
  return `${action} failed (${code}, agent HTTP ${agentStatus})`
}

/** The call threw: "verify failed (agent_unreachable, ECONNREFUSED)", "verify failed (agent_timeout)". */
export function thrownLastError(action: AgentAction, err: unknown): string {
  if (err instanceof AgentUnreachableError) {
    const { code, cause } = upstreamFailure('agent', err.cause_, '').body
    return `${action} failed (${cause ? `${code}, ${cause}` : code})`
  }
  return `${action} failed (${safeErrorCode(err)})`
}
