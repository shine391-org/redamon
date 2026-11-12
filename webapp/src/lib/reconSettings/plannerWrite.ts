/**
 * Strict planner/enrichment write contract for form and bundle entry points.
 * Judge RAW input, before column projection, null dropping or LLM coercion.
 * Absence is not an override; actual false is retained unchanged. Other form
 * fields keep their existing validation/normalization and write permissions.
 */
import { field } from './registry'
import { validateValue } from './validators'

const QUALITY_KEYS = new Set([
  'nucleiRoutingMode', 'jsReconFetchAdmission', 'arjunLateSources',
  'chunkCheckpointEnabled', 'checkpointBudgetPerGroup', 'checkpointBudgetPerTool',
])
const QUALITY_RUNTIME_KEYS = /^(NUCLEI_ROUTING_MODE|JS_RECON_FETCH_ADMISSION|ARJUN_LATE_SOURCES|CHUNK_CHECKPOINT_ENABLED|CHECKPOINT_BUDGET_PER_GROUP|CHECKPOINT_BUDGET_PER_TOOL)$/i

const ENRICHMENT_KEYS = new Set(['cveLookupEnabled', 'mitreEnabled', 'securityCheckEnabled'])

export function plannerWriteProblem(input: Record<string, unknown>): string | null {
  for (const [key, value] of Object.entries(input)) {
    // Runtime names are not API column names; refuse instead of silently losing
    // a misspelled/unsupported planner control in pickProjectColumns.
    const planner = /^planner/i.test(key) || /^PLANNER_/i.test(key)
    if (QUALITY_RUNTIME_KEYS.test(key)) return `${key} is not a canonical project settings name.`
    if (!planner && !QUALITY_KEYS.has(key) && !ENRICHMENT_KEYS.has(key)) continue
    const spec = field(key)
    if (!spec || (planner && !key.startsWith('planner'))) {
      return `${key} is not a supported planner setting; use canonical settings names.`
    }
    const problem = validateValue(key, spec, value)
    if (problem) return `${key} ${problem}.`
  }
  return null
}
