/**
 * Per-host coverage stamps on BaseURL nodes (plan 09.1): what a module did on a
 * web host in its last run. The recon writers stamp them
 * (graph_db/coverage_stamps.py holds the module list this copies;
 * tests/test_coverage_stamps_parity.py keeps the two in step).
 *
 * A BaseURL a module never considered carries no stamp. That absence means "not
 * scanned" only in a project where the module stamped some other host. A project
 * with no stamp for the module at all was scanned before stamps existed, or never
 * ran the module, and reads "coverage not recorded".
 */
import { formatNeo4jDateTime } from '@/app/graph/utils/formatters'

export const COVERAGE_MODULES = [
  { key: 'js_recon', label: 'JS analysis', input: 'file', noInput: 'the host served no JavaScript' },
  { key: 'nuclei', label: 'Nuclei', input: 'URL', noInput: 'nothing to scan on this host' },
] as const

export type CoverageModule = (typeof COVERAGE_MODULES)[number]['key']
export const COVERAGE_STATUSES = ['complete', 'partial', 'no_input', 'failed'] as const
type CoverageStatus = (typeof COVERAGE_STATUSES)[number]

const FIELDS = ['at', 'status', 'inputs', 'outputs', 'reason'] as const
export const COVERAGE_STAMP_PROPERTIES: string[] =
  COVERAGE_MODULES.flatMap(m => FIELDS.map(f => `${m.key}_${f}`))

export type CoverageState = CoverageStatus | 'not_scanned' | 'not_recorded'

export interface CoverageLine {
  module: CoverageModule
  label: string
  state: CoverageState
  text: string
  /** When the module's run started, formatted like every graph timestamp. */
  at?: string
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

const COUNT_BUCKETS = [...COVERAGE_STATUSES, 'not_scanned'] as const
export type CoverageCounts =
  | { recorded: false }
  | ({ recorded: true } & Record<(typeof COUNT_BUCKETS)[number], number>)

/**
 * The agent summary op's per-module host counts (coverage_summary in
 * graph_db/coverage_stamps.py), reduced to the known modules and buckets.
 * `null` when the block is absent: an older agent, or a count it could not read.
 */
export function coverageCountsBlock(raw: unknown): Record<CoverageModule, CoverageCounts> | null {
  if (!raw || typeof raw !== 'object') return null
  const out = {} as Record<CoverageModule, CoverageCounts>
  for (const m of COVERAGE_MODULES) {
    const entry = (raw as Record<string, unknown>)[m.key] as Record<string, unknown> | undefined
    if (!entry || entry.recorded !== true) {
      out[m.key] = { recorded: false }
      continue
    }
    const counts = Object.fromEntries(COUNT_BUCKETS.map(b => {
      const n = Number(entry[b])
      return [b, Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0]
    })) as Record<(typeof COUNT_BUCKETS)[number], number>
    out[m.key] = { recorded: true, ...counts }
  }
  return out
}

/** The modules any BaseURL of the project carries a stamp for. */
export function recordedCoverageModules(
  nodes: readonly { type: string; properties?: Record<string, unknown> }[] | null | undefined,
): Set<CoverageModule> {
  const recorded = new Set<CoverageModule>()
  for (const node of nodes ?? []) {
    if (node.type !== 'BaseURL') continue
    for (const m of COVERAGE_MODULES) {
      if (node.properties?.[`${m.key}_status`] != null) recorded.add(m.key)
    }
  }
  return recorded
}

/** One line per module for a BaseURL's properties. */
export function coverageLines(
  props: Record<string, unknown>,
  recorded: ReadonlySet<string>,
): CoverageLine[] {
  return COVERAGE_MODULES.map(m => {
    const status = props[`${m.key}_status`]
    const base = { module: m.key, label: m.label }
    if (typeof status !== 'string' || !(COVERAGE_STATUSES as readonly string[]).includes(status)) {
      return recorded.has(m.key)
        ? { ...base, state: 'not_scanned' as const, text: 'not scanned by this module' }
        : { ...base, state: 'not_recorded' as const, text: 'coverage not recorded' }
    }
    const inputs = Number(props[`${m.key}_inputs`] ?? 0)
    const outputs = Number(props[`${m.key}_outputs`] ?? 0)
    const reason = typeof props[`${m.key}_reason`] === 'string' ? props[`${m.key}_reason`] as string : ''
    const at = formatNeo4jDateTime(props[`${m.key}_at`]) ?? undefined
    const counts = `${plural(inputs, m.input)}, ${plural(outputs, 'finding')}`
    const text =
      status === 'no_input' ? `no input: ${m.noInput}`
        : status === 'failed' ? `failed${reason ? ` (${reason})` : ''}`
          : status === 'partial' ? `partial${reason ? ` (${reason})` : ''}, ${counts}`
            : `complete, ${counts}`
    return { ...base, state: status as CoverageStatus, text, at }
  })
}
