/**
 * A secret's validation status as people read it: the Red Zone secrets
 * table, the JS Recon table and the client report.
 *
 * js_recon stores `validated`, `rejected` (the provider's verdict), `unknown`
 * (no verdict: a timeout, a 429 or 5xx, a breaker skip, a 403),
 * `format_invalid`, `unvalidated` (no validator) or `skipped`. Nodes written
 * before those hold `invalid`, which mixed rejections with calls that never
 * got an answer, and `error`; they keep their own word. TruffleHog writes
 * `validated`, `rejected`, `verify_error` and `unverified`; before `rejected`
 * it wrote `unvalidated` for a credential checked and dead.
 */
export type ValidationTone = 'live' | 'warn' | 'dead' | 'none'

interface Entry { label: string; rank: number; tone: ValidationTone }

const STATES: Record<string, Entry> = {
  validated:        { label: 'LIVE',            rank: 0, tone: 'live' },
  format_validated: { label: 'format ok',       rank: 1, tone: 'warn' },
  // No verdict: never styled or sorted like a dead credential.
  unknown:          { label: 'could not check', rank: 2, tone: 'warn' },
  verify_error:     { label: 'verify error',    rank: 2, tone: 'warn' },
  incomplete:       { label: 'incomplete',      rank: 3, tone: 'none' },
  unvalidated:      { label: 'no validator',    rank: 3, tone: 'none' },
  rejected:         { label: 'rejected',        rank: 3, tone: 'dead' },
  unverified:       { label: 'not checked',     rank: 4, tone: 'none' },
  skipped:          { label: 'not checked',     rank: 5, tone: 'none' },
  invalid:          { label: 'invalid',         rank: 6, tone: 'dead' },
  error:            { label: 'error',           rank: 6, tone: 'none' },
  format_invalid:   { label: 'malformed',       rank: 7, tone: 'dead' },
}

/** TruffleHog's legacy `unvalidated` meant checked and dead. */
function entry(status: string | null | undefined, origin?: string): Entry | undefined {
  if (!status) return undefined
  if (status === 'unvalidated' && origin === 'MultiscannerFinding') return STATES.rejected
  return STATES[status]
}

export function validationLabel(status: string | null | undefined, origin?: string): string {
  if (!status) return '-'
  return entry(status, origin)?.label ?? status.replace(/_/g, ' ')
}

export function validationRank(status: string | null | undefined, origin?: string): number {
  return entry(status || 'unvalidated', origin)?.rank ?? STATES.unvalidated.rank
}

export function validationTone(status: string | null | undefined, origin?: string): ValidationTone {
  return entry(status, origin)?.tone ?? 'none'
}
