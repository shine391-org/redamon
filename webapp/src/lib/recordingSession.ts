import type { Prisma } from '@prisma/client'
import { normalizeScopeHosts } from '@/lib/authProfile'
import { recordingScope, resolveScopeGroups, type ScopeFields } from '@/lib/scopeGroups'
import { isRoeExcluded } from '@/lib/roeScope'

// Server-side max recording window. The operator re-starts to extend.
export const RECORDING_TTL_MS = 30 * 60 * 1000

// How long after Stop a late spool record may still be folded in. The ingest
// worker polls the spool on a ~1s loop, so the final response of a login (the
// one carrying Set-Cookie) routinely lands AFTER the operator clicks Stop.
export const OBSERVE_GRACE_MS = 2 * 60 * 1000

export interface RecordingSessionRow {
  id: string
  state: string
  scopeHosts: string[]
  expiresAt: Date
  observedCount: number
  lastError: string | null
}

/** Browser-safe view of a recording session (no secrets are stored on it). */
export function publicRecordingSession(s: RecordingSessionRow) {
  return {
    id: s.id,
    state: s.state,
    scopeHosts: s.scopeHosts,
    expiresAt: s.expiresAt.toISOString(),
    observedCount: s.observedCount,
    lastError: s.lastError,
  }
}

export interface RecordingMaterial {
  cookie?: string
  authorization?: string
  extra?: Record<string, string>
  host?: string
  hosts?: string[]
}

export interface DerivedProfile {
  authType: string
  authValue: string
  authHeaderName: string
  extraHeaders: Record<string, string>
}

/**
 * Turn accumulated recording material into a ProjectAuthProfile shape.
 * Cookie → cookie mode; a lone Bearer → bearer; anything else → extra headers.
 * A cookie + bearer keeps both (bearer rides along as an extra Authorization).
 */
export function deriveProfileFromMaterial(m: RecordingMaterial): DerivedProfile {
  const extra: Record<string, string> = { ...(m.extra || {}) }
  const cookie = m.cookie?.trim()
  const authz = m.authorization?.trim()

  if (cookie) {
    if (authz) extra['Authorization'] = authz
    return { authType: 'cookie', authValue: cookie, authHeaderName: '', extraHeaders: extra }
  }
  if (authz && /^bearer\s+/i.test(authz)) {
    return { authType: 'bearer', authValue: authz.replace(/^bearer\s+/i, ''), authHeaderName: '', extraHeaders: extra }
  }
  if (authz) extra['Authorization'] = authz
  return { authType: 'none', authValue: '', authHeaderName: '', extraHeaders: extra }
}

export function materialIsEmpty(m: RecordingMaterial | null | undefined): boolean {
  if (!m) return true
  const d = deriveProfileFromMaterial(m)
  return !d.authValue && Object.keys(d.extraHeaders).length === 0
}

/** Masked, secret-free summary of what a recording captured, for operator confirm. */
export function summarizeMaterial(m: RecordingMaterial | null | undefined) {
  if (!m) return { hasCookie: false, hasBearer: false, extraHeaderNames: [] as string[], hosts: [] as string[] }
  const d = deriveProfileFromMaterial(m)
  return {
    hasCookie: d.authType === 'cookie',
    hasBearer: d.authType === 'bearer',
    authType: d.authType,
    extraHeaderNames: Object.keys(d.extraHeaders),
    hosts: m.hosts || (m.host ? [m.host] : []),
  }
}

function parseCookiePairs(cookie: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of String(cookie || '').split(';')) {
    const p = part.trim()
    const i = p.indexOf('=')
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim()
  }
  return out
}

/** Merge a freshly observed record into the running material. */
export function mergeMaterial(prev: RecordingMaterial | null | undefined, next: RecordingMaterial): RecordingMaterial {
  const out: RecordingMaterial = { ...(prev || {}) }
  if (next.cookie) {
    // Merge by cookie NAME, never whole-string replacement. Spool records arrive
    // in no guaranteed order and span several hosts, so a later request carrying
    // only `theme=dark` would otherwise wipe the session cookie captured moments
    // earlier and the recording would silently store the wrong identity.
    const pairs = { ...parseCookiePairs(out.cookie), ...parseCookiePairs(next.cookie) }
    out.cookie = Object.entries(pairs).map(([n, v]) => `${n}=${v}`).join('; ')
  }
  if (next.authorization) out.authorization = next.authorization
  if (next.extra) out.extra = { ...(out.extra || {}), ...next.extra }
  const hosts = new Set([...(out.hosts || []), ...(next.hosts || [])])
  if (next.host) hosts.add(next.host)
  out.hosts = [...hosts].filter(Boolean)
  return out
}

interface ProjectScopeFields extends ScopeFields {
  targetIps?: string[]
  roeExcludedHosts?: string[]
}

/**
 * Default recording scope: the project's auth scope (§4.6: `*.<root>` for an
 * enumerated group, the listed hosts for a listed one, the root only when it
 * is a target), or its target IPs in IP mode, minus RoE-excluded hosts.
 * Fail-safe: never broader than what the project targets; the proxy only tags
 * in-scope requests, so operator browsing elsewhere never lands in the corpus.
 */
export function defaultRecordingScope(project: ProjectScopeFields): string[] {
  // Residual, deliberate: the proxy cannot evaluate RoE, so a recording under
  // `*.<root>` may capture an RoE-excluded subdomain. The scan-time fan-out
  // still refuses RoE-excluded hosts (merge_auth_headers checks each one).
  const raw = project.ipMode
    ? [...(project.targetIps || [])]
    : recordingScope(resolveScopeGroups(project).groups)
  let { hosts } = normalizeScopeHosts(raw)
  // A non-empty exclusion list IS the limit: there is no separate switch that
  // could leave it configured and inert.
  if (project.roeExcludedHosts?.length) {
    hosts = hosts.filter(h => !isRoeExcluded(h, project.roeExcludedHosts!))
  }
  return hosts
}

/**
 * Re-derive the active recording's scope from the project as it is now. The
 * proxy tags by the scope stored at Start, so a rescope or an RoE change made
 * mid-recording would otherwise keep capturing hosts the project dropped.
 * Never throws: a failure leaves the old scope until the recording expires.
 */
export async function refreshActiveRecordingScope(
  db: Pick<Prisma.TransactionClient, 'recordingSession'>,
  projectId: string,
  project: ProjectScopeFields,
): Promise<boolean> {
  try {
    const session = await db.recordingSession.findFirst({
      where: { projectId, state: 'active', expiresAt: { gt: new Date() } },
      select: { id: true },
    })
    if (!session) return false
    await db.recordingSession.update({
      where: { id: session.id },
      data: { scopeHosts: defaultRecordingScope(project) },
    })
    return true
  } catch (e) {
    console.error('[recording] could not refresh the recording scope:', e)
    return false
  }
}
