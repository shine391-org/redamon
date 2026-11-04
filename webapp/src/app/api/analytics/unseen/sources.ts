/**
 * Where each tab's badge count comes from.
 *
 * The first version of this counted NODES BY LABEL and it was wrong in the one
 * way a badge must never be wrong: it showed a number over a tab that then
 * rendered an empty table. Nearly every sheet is a FILTERED view, not a label
 * dump - Web Cache Poisoning lists only `Vulnerability {source:'cache_poisoning'}`,
 * Shared Infrastructure only certificates covering 2+ hosts, Kill-Chain only
 * complete Subdomain->IP->Port->Tech->CVE paths. A recon run that writes four
 * ordinary Vulnerability nodes lit up four unrelated tabs, all of which opened
 * empty.
 *
 * So a badge now counts the rows the tab WOULD show: the tab's own route is
 * invoked in-process and its rows are counted against the watermark. It costs
 * one query per tab instead of one for all of them, which is the price of the
 * badge meaning something. The two whole-graph tabs stay on label counts, where
 * "every node" is not an approximation.
 */
import { NextRequest } from 'next/server'
import { ALL_GRAPH_LABELS } from '@/app/graph/unseen/registry'

/** A route module, as imported. The second arg is only used by the dynamic routes. */
type RouteModule = { GET: (request: NextRequest, ctx?: unknown) => Promise<Response> }

/**
 * Tabs whose table is every node of a set of labels, with no further filter.
 * For these the label count IS the row count.
 */
const LABEL_SOURCES: Record<string, readonly string[]> = {
  nodeDetails: ALL_GRAPH_LABELS,
  all: ALL_GRAPH_LABELS,
  jsRecon: ['JsReconFinding'],
}

/**
 * Tabs backed by a Red Zone route, keyed by tab id -> that route's importer.
 *
 * Literal paths, not a computed template: the bundler has to see every target
 * statically or the import resolves at runtime to nothing.
 */
const ROUTE_SOURCES: Record<string, () => Promise<RouteModule>> = {
  aiSurface: () => import('../redzone/aiSurface/route'),
  aiRisk: () => import('../redzone/aiRisk/route'),
  killChain: () => import('../redzone/killChain/route'),
  blastRadius: () => import('../redzone/blastRadius/route'),
  takeover: () => import('../redzone/takeover/route'),
  secrets: () => import('../redzone/secrets/route'),
  netInitAccess: () => import('../redzone/netInitAccess/route'),
  graphql: () => import('../redzone/graphql/route'),
  webInitAccess: () => import('../redzone/webInitAccess/route'),
  paramMatrix: () => import('../redzone/paramMatrix/route'),
  sharedInfra: () => import('../redzone/sharedInfra/route'),
  dnsEmail: () => import('../redzone/dnsEmail/route'),
  threatIntel: () => import('../redzone/threatIntel/route'),
  // The slug predates the "Supply-Chain" -> "JS Dep Signals" rename.
  jsDepSignals: () => import('../redzone/supplyChain/route'),
  supplyChainSca: () => import('../redzone/supplyChainSca/route'),
  dnsDrift: () => import('../redzone/dnsDrift/route'),
  webCachePoison: () => import('../redzone/webCachePoison/route'),
  routeExposure: () => import('../redzone/routeExposure/route'),
}

export const LABEL_TABS = Object.keys(LABEL_SOURCES)
export const ROUTE_TABS = Object.keys(ROUTE_SOURCES)

export function labelsForTab(tab: string): readonly string[] {
  return LABEL_SOURCES[tab] ?? []
}

/**
 * A row's write time, in epoch ms.
 *
 * Handles both shapes a Red Zone route returns: a Cypher temporal, which
 * serialises to a nested object of `{low, high}` integers, and a plain ISO
 * string. A zoneless string is read as UTC to agree with the temporal branch -
 * the same instant must not land either side of the watermark depending on how
 * it happened to be stored.
 */
export function rowUpdatedAtMs(raw: unknown): number | null {
  if (raw && typeof raw === 'object') {
    const t = raw as Record<string, { low?: number } | number | undefined>
    const num = (v: unknown): number =>
      v && typeof v === 'object' && 'low' in (v as object) ? (v as { low: number }).low : Number(v ?? 0)
    if ('year' in t && 'month' in t && 'day' in t) {
      const ms = Date.UTC(
        num(t.year), num(t.month) - 1, num(t.day),
        num(t.hour), num(t.minute), num(t.second),
        Math.floor(num(t.nanosecond) / 1e6),
      )
      return Number.isFinite(ms) ? ms : null
    }
    return null
  }
  if (typeof raw !== 'string') return null
  const s = raw.trim()
  if (!s) return null
  const iso = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s) && !/[Zz]|[+-]\d{2}:?\d{2}$/.test(s)
    ? `${s.replace(' ', 'T')}Z`
    : s
  const ms = Date.parse(iso)
  return Number.isFinite(ms) ? ms : null
}

/** Every row a Red Zone response carries, flat and sheet-agnostic. */
function rowsOf(payload: unknown): unknown[] {
  if (!payload || typeof payload !== 'object') return []
  const body = payload as { rows?: unknown; sheets?: Record<string, unknown> }
  if (Array.isArray(body.rows)) return body.rows
  if (body.sheets && typeof body.sheets === 'object') {
    // A multi-sheet tab (AI Risk, Supply-Chain SCA) shows every sheet behind one
    // selector, so its badge covers all of them and clears all of them at once.
    return Object.values(body.sheets).flatMap(sheet => (Array.isArray(sheet) ? sheet : []))
  }
  return []
}

/**
 * Rows this tab would show that are newer than `sinceMs`.
 *
 * A route that fails counts as zero rather than taking the whole response down:
 * one broken sheet must not blank every badge on the page. The error is logged
 * because a permanently-zero badge is otherwise indistinguishable from a quiet
 * tab.
 */
export async function countUnseenRows(
  tab: string,
  projectId: string,
  sinceMs: number,
): Promise<number> {
  const importer = ROUTE_SOURCES[tab]
  if (!importer) return 0
  try {
    const mod = await importer()
    const url = `http://internal/api/analytics/redzone/${tab}?projectId=${encodeURIComponent(projectId)}`
    const res = await mod.GET(new NextRequest(url))
    if (!res.ok) return 0
    const rows = rowsOf(await res.json())
    let unseen = 0
    for (const row of rows) {
      const ms = rowUpdatedAtMs((row as Record<string, unknown>)?.updatedAt)
      if (ms !== null && ms > sinceMs) unseen++
    }
    return unseen
  } catch (error) {
    console.error(`[unseen] ${tab} source failed:`, error)
    return 0
  }
}
