/**
 * Strict planner/enrichment write contract for form and bundle entry points.
 * Judge RAW input, before column projection, null dropping or LLM coercion.
 * Absence is not an override; actual false is retained unchanged. Other form
 * fields keep their existing validation/normalization and write permissions.
 */
import { field } from './registry'
import { validateValue } from './validators'

const ENRICHMENT_KEYS = new Set(['cveLookupEnabled', 'mitreEnabled', 'securityCheckEnabled'])

export function plannerWriteProblem(input: Record<string, unknown>): string | null {
  for (const [key, value] of Object.entries(input)) {
    // Runtime names are not API column names; refuse instead of silently losing
    // a misspelled/unsupported planner control in pickProjectColumns.
    const planner = /^planner/i.test(key) || /^PLANNER_/i.test(key)
    if (!planner && !ENRICHMENT_KEYS.has(key)) continue
    const spec = field(key)
    if (!spec || (planner && !key.startsWith('planner'))) {
      return `${key} is not a supported planner setting; use canonical settings names.`
    }
    const problem = validateValue(key, spec, value)
    if (problem) return `${key} ${problem}.`
  }
  return null
}
