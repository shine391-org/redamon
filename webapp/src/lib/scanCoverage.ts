/**
 * Recon coverage carried by the graph.
 *
 * The recon pipeline records, on each covered `Domain`, which finding sources it
 * could not fully re-check this run (a circuit breaker opened, a host went
 * unreachable, Nuclei was truncated): `recon_coverage_at`, `recon_coverage_gaps`
 * (a JSON array of `{ source, ... }`), `recon_skipped_hosts`, `recon_nuclei_truncated`.
 *
 * The orchestrator cannot count this from logs (it only parses while a viewer
 * streams, replays from container start, and reaps the container ~30s after
 * exit), so the graph record is the carrier. This module reads it at run close
 * to stamp `ScanJob.degradedSources`, and for the delta/report views.
 */
import { getGraphSession } from '@/app/api/graph/neo4j'
import { type CurrentPolicyRow, admittedByCurrentPolicy } from '@/lib/ipHostnamePolicy'
import { IP_HOSTNAME_SELECT, type ScopeFields, resolveScopeGroups } from '@/lib/scopeGroups'

/** A single parsed coverage gap. Only `source` is relied on here. */
export interface CoverageGap {
  source: string
  [key: string]: unknown
}

/** The bounded selection block a Domain's coverage record carries. */
export interface SelectionCoverage {
  recorded: boolean
  selection_unknown: boolean
  plan_ids: string[]
  exhaustive: boolean
}

/**
 * Parse a `recon_coverage_gaps` value into an array of gaps, or `null` when it
 * is not a JSON array of objects with a string `source` of <=64 chars. An
 * imported/exported bundle is untrusted, so anything malformed is rejected
 * rather than trusted or coerced.
 */
export function parseCoverageGaps(raw: unknown): CoverageGap[] | null {
  let value = raw
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value)
    } catch {
      return null
    }
  }
  if (!Array.isArray(value)) return null
  const out: CoverageGap[] = []
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
    const source = (entry as { source?: unknown }).source
    if (typeof source !== 'string' || source.length === 0 || source.length > 64) return null
    out.push(entry as CoverageGap)
  }
  return out
}

/**
 * The project's current scan roots, lower-cased, for the coverage filters
 * below; null when there is nothing to filter by (IP mode, no target).
 */
export const SCOPE_SELECT = {
  ipMode: true, domainBatchMode: true, domainBatchHosts: true, targetDomain: true, subdomainList: true,
  // An IP project's hostname policy is part of its scope: which scanned names
  // still count as covered hosts is the current policy's call (design §6.3).
  ...IP_HOSTNAME_SELECT,
} as const

/**
 * An IP-mode project's coverage scope. It has no scan roots (every gap is
 * tagged with the synthetic root, and all count); a skipped host counts while it
 * is a target address, its label, or a hostname the CURRENT policy admits:
 * after a narrowing a scanned name is no longer the project's (design §6.3).
 * A Set, empty, so it travels where a set of scan roots does.
 */
export class IpModeCoverageScope extends Set<string> {
  constructor(private readonly policy: CurrentPolicyRow) {
    super()
  }

  admitsHost(host: string): boolean {
    // Addresses and labels: the run's own targets, kept by its clamps.
    if (host.includes(':') || /^[0-9.]+$/.test(host) || !host.includes('.') || host.startsWith('ip-targets.')) {
      return true
    }
    return admittedByCurrentPolicy([host], this.policy).length > 0
  }
}

export function currentScanRoots(project: ScopeFields): Set<string> | null {
  if (project.ipMode) return new IpModeCoverageScope(project)
  const roots = resolveScopeGroups(project).groups.map(g => g.scanRoot.toLowerCase())
  return roots.length ? new Set(roots) : null
}

/**
 * Is this coverage entry about a current scan root (§4.11.7)? The org Domain
 * keeps a removed root's entries until the next full recon clears the graph.
 * A gap carries its `root`; a gap with none (written before roots were tagged)
 * is kept. `null` roots keep everything, and so does an IP-mode scope.
 */
export function gapInScope(gap: CoverageGap, roots: ReadonlySet<string> | null): boolean {
  if (!roots || roots instanceof IpModeCoverageScope || typeof gap.root !== 'string' || !gap.root) return true
  return roots.has(gap.root.toLowerCase())
}

/** Is a skipped `host:port` under a current scan root? Its root is the longest
 *  scan root it equals or sits under; none means a removed root's host. */
export function skippedHostInScope(hostPort: string, roots: ReadonlySet<string> | null): boolean {
  if (!roots) return true
  if (roots instanceof IpModeCoverageScope) {
    return roots.admitsHost(hostPort.replace(/^\[([^\]]*)\](:\d+)?$/, '$1').replace(/^([^:]*):\d+$/, '$1').toLowerCase())
  }
  const host = hostPort.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase()
  for (const r of roots) if (host === r || host.endsWith(`.${r}`)) return true
  return false
}

/**
 * Parse a `recon_selection_json` / `vuln_scan_selection_json` value into a
 * bounded block, or `null` when it is not an object with a `plan_ids` array of
 * strings. An imported/exported bundle is untrusted, so anything malformed is
 * rejected rather than trusted or coerced.
 */
export function parseSelectionBlock(raw: unknown): SelectionCoverage | null {
  let value = raw
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value)
    } catch {
      return null
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const obj = value as Record<string, unknown>
  const rawIds = obj.plan_ids === undefined ? [] : obj.plan_ids
  if (!Array.isArray(rawIds)) return null
  const planIds: string[] = []
  for (const id of rawIds) {
    if (typeof id !== 'string' || !id) return null
    if (!planIds.includes(id)) planIds.push(id)
  }
  return {
    recorded: obj.recorded === true,
    selection_unknown: obj.selection_unknown === true,
    plan_ids: planIds,
    exhaustive: obj.exhaustive === true,
  }
}

/** Merge two blocks: recorded/unknown OR-ed, plan ids unioned, exhaustive only
 *  when both sides cut nothing. */
export function mergeSelectionBlocks(
  a: SelectionCoverage | null,
  b: SelectionCoverage | null,
): SelectionCoverage | null {
  if (a === null) return b
  if (b === null) return a
  const planIds = [...a.plan_ids]
  for (const id of b.plan_ids) if (!planIds.includes(id)) planIds.push(id)
  return {
    recorded: a.recorded || b.recorded,
    selection_unknown: a.selection_unknown || b.selection_unknown,
    plan_ids: planIds,
    exhaustive: a.exhaustive && b.exhaustive,
  }
}

/**
 * The project's current run selection block, or `null` when coverage is
 * unknown.
 *
 * Reads `recon_selection_json` (the per-run record, merged across the run's
 * groups) and `vuln_scan_selection_json` (the per-group plan write) from every
 * covered `Domain` and merges them. Returns `null` when no Domain carries a
 * coverage record, when neither property is present, or when any block fails to
 * parse. Never throws.
 */
export async function readSelectionCoverage(
  projectId: string,
): Promise<SelectionCoverage | null> {
  let session
  try {
    session = getGraphSession()
  } catch {
    return null
  }
  try {
    const res = await session.run(
      `MATCH (d:Domain {project_id: $pid})
       WHERE d.recon_coverage_at IS NOT NULL
       RETURN d.recon_selection_json AS selection, d.vuln_scan_selection_json AS plan`,
      { pid: projectId },
    )
    if (!res.records.length) return null
    let merged: SelectionCoverage | null = null
    let sawRecord = false
    for (const record of res.records) {
      for (const key of ['selection', 'plan']) {
        const raw = record.get(key)
        if (raw === undefined || raw === null) continue
        sawRecord = true
        const parsed = parseSelectionBlock(raw)
        if (parsed === null) return null // fail closed on any unparseable block
        merged = mergeSelectionBlocks(merged, parsed)
      }
    }
    return sawRecord ? merged : null
  } catch {
    return null
  } finally {
    try {
      await session.close()
    } catch {
      /* already closed */
    }
  }
}

/**
 * The number of distinct degraded finding sources across every covered `Domain`
 * of a project's latest run, or `null` when coverage is unknown.
 *
 * Returns `null` when no `Domain` carries `recon_coverage_at` (the run predates
 * the feature, or wrote nothing), or when any gaps value fails to parse. Returns
 * `0` when coverage was recorded and clean. Never throws.
 */
export async function readDegradedSourceCount(
  projectId: string, roots: ReadonlySet<string> | null = null,
): Promise<number | null> {
  let session
  try {
    session = getGraphSession()
  } catch {
    return null
  }
  try {
    const res = await session.run(
      `MATCH (d:Domain {project_id: $pid})
       WHERE d.recon_coverage_at IS NOT NULL
       RETURN d.recon_coverage_gaps AS gaps`,
      { pid: projectId },
    )
    if (!res.records.length) return null
    const sources = new Set<string>()
    for (const record of res.records) {
      const gaps = parseCoverageGaps(record.get('gaps'))
      if (gaps === null) return null // fail closed on any unparseable record
      for (const gap of gaps) if (gapInScope(gap, roots)) sources.add(gap.source)
    }
    return sources.size
  } catch {
    return null
  } finally {
    try {
      await session.close()
    } catch {
      /* already closed */
    }
  }
}
