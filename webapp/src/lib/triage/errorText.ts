/**
 * The text a Priority Board surface shows for a failed triage route.
 *
 * `readApiError` already carries the route's code and both HTTP statuses; a
 * triage route also says what the AGENT reported (its own code, the exception
 * class, or the errno when it never answered), which is what tells a stopped
 * agent from a missing INTERNAL_API_KEY or a Neo4j failure.
 *
 * Browser-safe.
 */
import { ApiError, formatApiError, readApiError } from '@/lib/apiError'

const FACT = /^[A-Za-z_][A-Za-z0-9_.]{0,79}$/

export function triageErrorText(err: ApiError): string {
  const body = err.body ?? {}
  const facts = [body.agentCode, body.errorClass, body.cause]
    .filter((v): v is string => typeof v === 'string' && FACT.test(v) && v !== err.code)
  if (facts.length === 0) return err.message
  return formatApiError({
    reason: err.reason,
    code: [err.code, ...facts].filter(Boolean).join(' · '),
    status: err.status,
    upstreamStatus: err.upstreamStatus,
  })
}

export async function readTriageError(res: Response, fallback: string): Promise<string> {
  return triageErrorText(await readApiError(res, fallback))
}

const CODE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/

/** `triageErrorText` for a body the caller has already parsed. */
export function triageBodyErrorText(body: Record<string, unknown>, status: number, fallback: string): string {
  const reason = typeof body.error === 'string' && body.error.trim() ? body.error.trim().slice(0, 500) : fallback
  const code = typeof body.code === 'string' && CODE.test(body.code) ? body.code : undefined
  const upstreamStatus = typeof body.upstreamStatus === 'number' ? body.upstreamStatus : undefined
  return triageErrorText(new ApiError({
    reason, status, body,
    ...(code ? { code } : {}),
    ...(upstreamStatus ? { upstreamStatus } : {}),
  }))
}
