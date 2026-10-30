/**
 * Mint the short-lived ticket an agent WebSocket (chat, CypherFix triage and
 * CodeFix, Kali terminal) presents to the agent. A failed mint answers its cause
 * (401 expired session, 404 no project access, 409 version activation in
 * progress), which the caller shows instead of a bare "authentication failed".
 */
import { ApiError, readApiError, toApiError } from './apiError'

export type WsTicketResult =
  /** `ticket` is null when the deployment runs without ticket signing: the agent then accepts the socket. */
  | { ok: true; ticket: string | null }
  | { ok: false; error: ApiError }

const FALLBACK = 'Could not get a ticket for the agent connection'

export async function mintWsTicket(projectId: string, sessionId: string): Promise<WsTicketResult> {
  try {
    const res = await fetch('/api/agent/ws-ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ projectId, sessionId }),
    })
    if (!res.ok) return { ok: false, error: await readApiError(res, FALLBACK) }
    const body = await res.json().catch(() => null) as { ticket?: unknown } | null
    return { ok: true, ticket: typeof body?.ticket === 'string' && body.ticket ? body.ticket : null }
  } catch (err) {
    return { ok: false, error: toApiError(err, FALLBACK) }
  }
}
