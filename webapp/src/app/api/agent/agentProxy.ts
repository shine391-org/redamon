/**
 * The two ways an agent proxy route fails, answered so the browser can tell them
 * apart: the agent never answered (503 `agent_unreachable` / 504 `agent_timeout`,
 * with the errno as `cause`), or it answered with an error (`agent_error` or its
 * own code, plus `upstreamStatus`).
 *
 * A 4xx sentence is shown as the agent wrote it: the workspace and session
 * endpoints write those themselves ("path escapes workspace: x"). A 5xx gets the
 * route's fixed message, since the agent's 5xx body is an exception's text.
 *
 * Server-side only.
 */
import type { NextResponse } from 'next/server'
import { agentFetch, AgentUnreachableError, type AgentFetchOptions } from '@/lib/agentFetch'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

export type AgentCall = { ok: true; res: Response } | { ok: false; response: NextResponse }

/** `agentFetch`, with a transport failure already turned into the route's answer. */
export async function callAgent(
  path: string,
  init: RequestInit,
  message: string,
  opts?: AgentFetchOptions,
): Promise<AgentCall> {
  try {
    return { ok: true, res: await agentFetch(path, init, opts) }
  } catch (err) {
    if (err instanceof AgentUnreachableError) {
      // The original fetch error carries the errno and the TimeoutError name.
      return { ok: false, response: upstreamFailureResponse('agent', err.cause_, message) }
    }
    return { ok: false, response: internalError(err, message) }
  }
}

/** The answer for an agent that replied with a non-2xx status. */
export function agentErrorResponse(res: Response, message: string): Promise<NextResponse> {
  return upstreamErrorResponse('agent', res, message, { forwardText: res.status < 500 })
}
