/**
 * A save that was stored but whose follow-up call to another service failed:
 * the orchestrator did not (re)start the capture proxy, the kali-sandbox did not
 * take the tunnel config, the agent did not reload its MCP servers.
 *
 * The write still answers 200, because the data is saved and repeating it would
 * not help; a `warnings` entry says what is not live yet and why. The cause is a
 * code and a status, never the service's own text: the orchestrator and the agent
 * answer these calls with `str(exc)`, which can quote a provider error or a key.
 *
 * The browser reads these entries with `components/settings/failureText.ts`.
 */
import { AgentUnreachableError } from '@/lib/agentFetch'
import { readUpstreamBody, upstreamFailure, type UpstreamBody } from '@/lib/routeErrors'

export interface SaveWarning {
  /** `orchestrator`, `kali_sandbox` or `agent`. */
  service: string
  /** What is not live yet, e.g. "The capture proxy was not started". */
  message: string
  /** `<service>_unreachable`, `<service>_timeout`, the service's own code, or `<service>_error`. */
  code: string
  upstreamStatus?: number
  /** The errno when the service never answered. */
  cause?: string
}

/** Run a follow-up call; null when it succeeded, else the warning describing why it did not. */
export async function followUpWarning(
  service: string,
  message: string,
  call: () => Promise<Response>,
): Promise<SaveWarning | null> {
  let res: Response
  try {
    res = await call()
  } catch (err) {
    console.warn(`${message}:`, err)
    // agentFetch wraps the transport error; its errno and timeout live on the original.
    const transport = err instanceof AgentUnreachableError ? err.cause_ : err
    const { code, cause } = upstreamFailure(service, transport, message).body
    return { service, message, code, ...(cause ? { cause } : {}) }
  }
  if (res.ok) return null
  const body = await readUpstreamBody(res).catch((): UpstreamBody => ({ json: null }))
  console.warn(`${message}: ${service} answered HTTP ${res.status}`)
  return { service, message, code: body.code ?? `${service}_error`, upstreamStatus: res.status }
}
