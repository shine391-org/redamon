/** Defense-in-depth projection: upstream artifacts never supply display strings. */
export interface ReconDiagnostics {
  status: 'ready' | 'unknown'
  reason?: string
  run_id: string | null
  group_id: null
  is_history: boolean
  inventory: Record<string, unknown> | null
  selection: Record<string, unknown> | null
  checkpoint: Record<string, unknown> | null
}
const tools = ['vuln_scan', 'graphql_scan', 'subdomain_takeover', 'vhost_sni', 'cache_scan', 'origin_discovery', 'route_exposure']
const reasons = new Set(['artifact_unavailable', 'durable_evidence', 'historical_run', 'legacy_durable_evidence',
  'run_context_unavailable', 'evidence_unavailable', 'checkpoint_unavailable', 'project_revision_mismatch',
  'output_revision_mismatch', 'unsupported_targeting_mode', 'unsupported_batch_continuation', 'ambiguous_execution',
  'scan_active', 'no_safe_deferred_chunks', 'explicit_human_invocation_required', 'preflight_incompatible_or_unavailable'])
export const validReconId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value)
const obj = (value: unknown): Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
const num = (value: unknown): number | null => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 1e9 ? value : null
const counts = (value: unknown, keys: string[]) => Object.fromEntries(keys.filter(k => k in obj(value)).map(k => [k, num(obj(value)[k])]))
const reason = (value: unknown) => typeof value === 'string' && reasons.has(value) ? value : 'evidence_unavailable'

export function sanitizeReconDiagnostics(value: unknown): ReconDiagnostics {
  const raw = obj(value)
  const inventory = obj(raw.inventory)
  const selection = obj(raw.selection)
  const checkpoint = obj(raw.checkpoint)
  const continuation = obj(checkpoint.continuation)
  const budgets = obj(checkpoint.budgets)
  const modules = obj(selection.modules)
  const run = validReconId(raw.run_id) ? raw.run_id : null
  const entries = Array.isArray(checkpoint.entries) ? checkpoint.entries.slice(0, 100).map(e => {
    const entry = obj(e)
    return { tool: tools.includes(String(entry.tool)) ? entry.tool : 'unknown',
      status: ['pending', 'running', 'completed', 'partial', 'deferred', 'failed'].includes(String(entry.status)) ? entry.status : 'unknown',
      coverage_durable: entry.coverage_durable === true,
      reason: entry.reason === 'budget_exhausted' ? 'budget_exhausted' : 'durable_chunk_state' }
  }) : []
  return {
    status: raw.status === 'ready' ? 'ready' : 'unknown', reason: reason(raw.reason),
    run_id: run, group_id: null, is_history: raw.is_history === true,
    inventory: raw.inventory && typeof raw.inventory === 'object' ? {
      schema_version: num(inventory.schema_version), origins: num(inventory.origins),
      producers: Array.isArray(inventory.producers) ? inventory.producers.slice(0, 32).map(p => counts(p, ['observations', 'observations_total', 'rejected_count'])) : [],
      reasons: ['durable_inventory_counts_only'],
    } : null,
    selection: raw.selection && typeof raw.selection === 'object' ? {
      modules: Object.fromEntries(tools.filter(t => t in modules).map(t => {
        const plan = obj(modules[t])
        return [t, { status: ['planned', 'complete', 'partial', 'failed'].includes(String(plan.status)) ? plan.status : 'unknown',
          exhaustive: plan.exhaustive === true, targets: counts(plan.targets, ['count']),
          outcomes: counts(plan.outcomes, ['completed', 'partial', 'failed', 'deferred', 'unknown']), reasons: ['selection_recorded'] }]
      })),
    } : null,
    checkpoint: raw.checkpoint && typeof raw.checkpoint === 'object' ? {
      scope: 'group6_phase_a', counts: counts(checkpoint.counts, ['pending', 'running', 'completed', 'partial', 'deferred', 'failed', 'not_tested']),
      planned: num(checkpoint.planned), entries, entries_truncated: checkpoint.entries_truncated === true,
      budgets: { ...counts(budgets, ['per_group', 'per_tool', 'window', 'lifetime_used']), unit: 'tool_group_chunks', renewal: 'explicit_continuation' },
      continuation: { supported: continuation.supported === true,
        eligible: continuation.eligible === true && raw.is_history !== true && run !== null,
        reason: reason(continuation.reason), run_id: run },
    } : null,
  }
}
