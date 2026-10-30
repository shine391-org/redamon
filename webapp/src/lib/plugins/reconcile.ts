import { randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { Prisma, type PluginData, type PluginInstall } from '@prisma/client'
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { isValidRange, isValidVersion, satisfies } from '@/lib/semver'
import { auditPlugin } from './audit'
import { CatalogError, isRevoked, loadCatalog, type LoadedCatalog } from './catalog'
import { now } from './clock'
import { FetchRemoteError, fetchRemote } from './fetchRemote'
import { checkAndStage } from './installChecks'
import { JOBS_COLLECTION, failJob, type Job } from './jobs'
import { commitIn, hasKeptData, manifestOnDisk, purgeRows, withoutPrevious } from './lifecycle'
import { INSTALLED_STATUSES } from './lifecycleCommon'
import { markStale, type StaleReason } from './overrides'
import { pairsWithUserSkillProvenance, revokeUserSkillProvenance } from './userSkillRevocation'
import { PLUGIN_PLATFORM_VERSION } from './platformVersion'
import {
  PluginConflictError,
  endOperation,
  takeOverOperation,
  transition,
  type Operation,
  type OperationKind,
  type PluginStatus,
} from './registry'
import { RunnerError, RunnerUnavailableError, runnerFailureSummary, runnerHealth, runnerReload } from './runnerClient'
import type { CatalogRelease } from './schemas/catalog'
import { SkillPartsRegistryError, registrySkill, type RegistrySkill } from './skillPartsRegistry'
import {
  STAGING_DIR,
  commitVersion,
  discardStaging,
  listPluginFolders,
  listStaging,
  listVersions,
  pluginsDir,
  removePluginFolder,
  removeVersion,
  versionExists,
} from './staging'

/**
 * Reconciliation (README.PLUGINS.md §9.7): the registry is the source of truth and this
 * brings the volume, the runner and the rows back in line with it. Driven by the recon
 * orchestrator every PLUGIN_RECONCILE_INTERVAL (TD-20), so crash recovery waits at most one
 * interval.
 *
 * - One reconcile at a time: a platform-wide lease in PluginPlatformState taken with a
 *   compare-and-set (a client timeout does not cancel a Next.js handler, so the tick, the
 *   runner's start and any key holder could otherwise overlap; RV-16). A held lease
 *   answers `skipped: 'busy'`.
 * - Bounded work: at most one heal download per call and a time budget; what is left goes
 *   to the next tick.
 * - Only operations whose lease expired are touched, each claimed first.
 * - A folder is referenced when it is the active, previous or pending version of a row,
 *   or the staging of a live lease; an unreferenced folder younger than 15 minutes stays
 *   (a racing install may not have written its row yet; X4).
 * - Revocation writes `revokedReason`, never `enabled` (RV-17), and only from a catalog
 *   that verified. Stale overrides are found against the agent's part registry and never
 *   guessed when the agent cannot be asked (TD-16).
 */
export const RECONCILE_LEASE_KEY = 'reconcile.lease'
// Longer than any one operation of a run (a purge's transaction may take 120 s), and renewed
// before each: a run never outlives its lease, so two never overlap.
export const RECONCILE_LEASE_MS = 300_000
export const RECONCILE_BUDGET_MS = 20_000
export const FOLDER_GRACE_MS = 15 * 60_000
const EXPIRED_BATCH = 1000
const EXPIRED_BATCHES_MAX = 50
const OVERDUE_JOBS_MAX = 500
const LEASE_CLEARED = { operationId: null, operationKind: null, operationArgs: Prisma.DbNull, leaseExpiresAt: null }

export interface ReconcileDeps {
  loadCatalog?: () => Promise<LoadedCatalog>
  fetchArchive?: (url: string) => Promise<Buffer>
  registrySkill?: (skillId: string) => Promise<RegistrySkill | null>
  platformVersion?: string
  budgetMs?: number
}

export interface ReconcileReport {
  recovered: { pluginId: string; from: string; outcome: 'rolled_back' | 'finished' }[]
  healed: string[]
  deferred: string[]
  statusChanges: { pluginId: string; from: string; to: string }[]
  revoked: string[]
  unrevoked: string[]
  /** What revoked plugin versions left at user_skill.text: proposals withdrawn, skills quarantined. */
  userSkillRevocations: { withdrawn: string[]; quarantined: string[] }
  catalog: string
  registry: string
  staleSets: string[]
  foldersRemoved: string[]
  stagingRemoved: string[]
  expiredRows: number
  overdueJobs: number
  runnerReloaded: boolean
  budgetExhausted: boolean
  errors: string[]
}

type Deps = Required<Omit<ReconcileDeps, 'budgetMs'>> & { budgetMs: number }

const defaults = (): Deps => ({
  loadCatalog: () => loadCatalog({ source: 'official' }),
  fetchArchive: async (url) => (await fetchRemote(url, { kind: 'archive' })).bytes,
  registrySkill,
  platformVersion: PLUGIN_PLATFORM_VERSION,
  budgetMs: RECONCILE_BUDGET_MS,
})

const isInstalled = (s: string) => (INSTALLED_STATUSES as readonly string[]).includes(s)
const liveLease = (r: PluginInstall) => !!r.operationId && !!r.leaseExpiresAt && r.leaseExpiresAt > now()
const SYSTEM = { actorId: null, source: 'system' as const }

// ---------------------------------------------------------------------------
// The platform-wide lease
// ---------------------------------------------------------------------------

async function takeLease(holder: string): Promise<boolean> {
  const value = { holder, until: new Date(now().getTime() + RECONCILE_LEASE_MS).toISOString() }
  try {
    await prisma.pluginPlatformState.create({ data: { key: RECONCILE_LEASE_KEY, value } })
    return true
  } catch (e) {
    if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002')) throw e
  }
  const row = await prisma.pluginPlatformState.findUnique({ where: { key: RECONCILE_LEASE_KEY } })
  const held = row?.value as { holder?: unknown; until?: unknown } | null
  if (!row || typeof held?.holder !== 'string' || typeof held.until !== 'string') {
    // Nothing usable to compare with: whoever deletes it first may try again next tick.
    await prisma.pluginPlatformState.deleteMany({ where: { key: RECONCILE_LEASE_KEY } })
    return false
  }
  if (Date.parse(held.until) > now().getTime()) return false
  const { count } = await prisma.pluginPlatformState.updateMany({
    where: { key: RECONCILE_LEASE_KEY, value: { path: ['holder'], equals: held.holder } },
    data: { value },
  })
  return count === 1
}

async function renewLease(holder: string) {
  const value = { holder, until: new Date(now().getTime() + RECONCILE_LEASE_MS).toISOString() }
  await prisma.pluginPlatformState.updateMany({
    where: { key: RECONCILE_LEASE_KEY, value: { path: ['holder'], equals: holder } },
    data: { value },
  })
}

async function releaseLease(holder: string) {
  await prisma.pluginPlatformState.deleteMany({
    where: { key: RECONCILE_LEASE_KEY, value: { path: ['holder'], equals: holder } },
  })
}

/** Ends a claim that leaves the status as it is (the registry's machine has no X → X). */
async function releaseClaim(op: Operation, patch: Prisma.PluginInstallUpdateManyMutationInput = {}) {
  await prisma.pluginInstall.updateMany({
    where: { pluginId: op.pluginId, operationId: op.operationId },
    data: { ...patch, ...LEASE_CLEARED },
  })
}

// ---------------------------------------------------------------------------
// Interrupted operations
// ---------------------------------------------------------------------------

function releaseOf(args: Prisma.JsonValue | null, version: string): CatalogRelease | null {
  const r = (args as { release?: Record<string, unknown> } | null)?.release
  if (!r || typeof r !== 'object' || r.version !== version || typeof r.url !== 'string' || typeof r.sha256 !== 'string') return null
  return r as unknown as CatalogRelease
}

/** An interrupted update or rollback whose target is on the volume and moves no data. */
async function finishSwitch(row: PluginInstall, op: Operation, kind: string, d: Deps): Promise<boolean> {
  const target = row.pendingVersion
  if (!target || !row.activeVersion || !(await versionExists(row.pluginId, target))) return false
  const manifest = await manifestOnDisk(row.pluginId, target)
  if (!manifest || !satisfies(d.platformVersion, manifest.platform)) return false
  if (manifest.dataVersion !== row.dataVersion && (await hasKeptData(row.pluginId))) return false
  let catalogEntry: Prisma.InputJsonValue | typeof Prisma.DbNull
  if (kind === 'update') {
    const release = releaseOf(row.operationArgs, target)
    if (!release) return false
    catalogEntry = { ...release, previous: withoutPrevious(row.catalogEntry) } as Prisma.InputJsonValue
  } else {
    const previous = (row.catalogEntry as { previous?: unknown } | null)?.previous
    catalogEntry = (previous && typeof previous === 'object'
      ? { ...(previous as object), previous: withoutPrevious(row.catalogEntry) }
      : row.catalogEntry ?? Prisma.DbNull) as Prisma.InputJsonValue
  }
  await prisma.$transaction(
    commitIn(op, 'updating', {
      activeVersion: target,
      previousVersion: row.activeVersion,
      pendingVersion: null,
      dataVersion: manifest.dataVersion,
      previousDataVersion: row.dataVersion,
      grantedPermissions: manifest.permissions,
      manifest: manifest as unknown as Prisma.InputJsonValue,
      catalogEntry,
      lastError: null,
      revokedReason: null,
    }),
  )
  for (const v of await listVersions(row.pluginId)) {
    if (v !== target && v !== row.activeVersion) await removeVersion(row.pluginId, v).catch(() => {})
  }
  await auditPlugin(kind === 'update' ? 'plugin.update' : 'plugin.rollback', {
    ...SYSTEM,
    pluginId: row.pluginId,
    before: { activeVersion: row.activeVersion, status: 'updating' },
    after: { activeVersion: target, previousVersion: row.activeVersion, recovered: true },
  })
  return true
}

async function recoverOperation(row: PluginInstall, d: Deps): Promise<'rolled_back' | 'finished'> {
  const pluginId = row.pluginId
  const interrupted = row.operationId
  const kind = (row.operationKind ?? '') as OperationKind
  const args = (row.operationArgs ?? undefined) as Prisma.InputJsonValue | undefined
  if (row.status === 'installing') {
    const op = await takeOverOperation(pluginId, 'installing', 'install', args)
    if (interrupted) {
      await discardStaging(interrupted).catch(() => {})
      // An install over kept data migrates a copy of it first.
      await prisma.pluginData.deleteMany({ where: { pluginId, namespace: `migrating:${interrupted}` } })
    }
    await endOperation(op, 'available', { pendingVersion: null, lastError: 'interrupted: the install did not finish; install it again' })
    await auditPlugin('plugin.install_failed', { ...SYSTEM, pluginId, after: { code: 'interrupted', recovered: true } })
    return 'rolled_back'
  }
  if (row.status === 'updating') {
    const op = await takeOverOperation(pluginId, 'updating', kind === 'rollback' ? 'rollback' : 'update', args)
    if (interrupted) {
      await discardStaging(interrupted).catch(() => {})
      await prisma.pluginData.deleteMany({ where: { pluginId, namespace: `migrating:${interrupted}` } })
    }
    if (await finishSwitch(row, op, kind === 'rollback' ? 'rollback' : 'update', d)) return 'finished'
    const pending = row.pendingVersion
    if (pending && pending !== row.activeVersion && pending !== row.previousVersion && isValidVersion(pending)) {
      await removeVersion(pluginId, pending).catch(() => {})
    }
    await endOperation(op, 'ready', {
      pendingVersion: null,
      lastError: `interrupted: the ${kind === 'rollback' ? 'rollback' : 'update'} did not finish and was undone`,
    })
    await auditPlugin(kind === 'rollback' ? 'plugin.rollback' : 'plugin.update', {
      ...SYSTEM,
      pluginId,
      after: { outcome: 'failed', code: 'interrupted', version: pending, recovered: true },
    })
    return 'rolled_back'
  }
  // uninstalling
  const op = await takeOverOperation(pluginId, 'uninstalling', 'uninstall', args)
  await removePluginFolder(pluginId)
  const purge = (row.operationArgs as { mode?: unknown } | null)?.mode === 'purge'
  if (purge) {
    const counts = await prisma.$transaction((tx) => purgeRows(tx, op), { maxWait: 10_000, timeout: 120_000 })
    await auditPlugin('plugin.purge', { ...SYSTEM, pluginId, after: { mode: 'purge', ...counts, recovered: true } })
  } else {
    await endOperation(op, 'available', {
      enabled: false,
      activeVersion: null,
      previousVersion: null,
      pendingVersion: null,
      previousDataVersion: null,
      lastError: null,
    })
    await auditPlugin('plugin.uninstall', { ...SYSTEM, pluginId, after: { mode: 'keep', status: 'available', recovered: true } })
  }
  return 'finished'
}

// ---------------------------------------------------------------------------
// Installed plugins
// ---------------------------------------------------------------------------

function pinnedRelease(row: PluginInstall): CatalogRelease | null {
  const e = row.catalogEntry as Record<string, unknown> | null
  if (!e || typeof e !== 'object' || e.version !== row.activeVersion || typeof e.url !== 'string' ||
      typeof e.sha256 !== 'string' || typeof e.platform !== 'string' || typeof e.dataVersion !== 'number' ||
      !Array.isArray(e.permissions)) return null
  return e as unknown as CatalogRelease
}

/** Re-downloads the pinned archive of a lost version folder, checked like an install. */
async function heal(row: PluginInstall, d: Deps): Promise<{ ok: true } | { ok: false; lastError: string }> {
  const release = pinnedRelease(row)
  if (!release) return { ok: false, lastError: 'heal_failed: no_catalog_entry: the version folder is gone and no pinned archive is known; reinstall the plugin' }
  const op = await takeOverOperation(row.pluginId, row.status as PluginStatus, 'install', { heal: true })
  let lastError: string | null = null
  try {
    let bytes: Buffer
    try {
      bytes = await d.fetchArchive(release.url)
    } catch (e) {
      lastError = `heal_failed: download_failed: ${e instanceof FetchRemoteError ? `${e.code}: ${e.message}` : safeErrorCode(e)}`.slice(0, 2000)
      return { ok: false, lastError }
    }
    const checked = await checkAndStage(op.operationId, { pluginId: row.pluginId, archiveBytes: bytes, release, platformVersion: d.platformVersion })
    if (!checked.ok) {
      lastError = `heal_failed: ${checked.code}: ${checked.message}`.slice(0, 2000)
      return { ok: false, lastError }
    }
    if (await versionExists(row.pluginId, release.version)) await removeVersion(row.pluginId, release.version)
    await commitVersion(op.operationId, row.pluginId, release.version)
    return { ok: true }
  } finally {
    await discardStaging(op.operationId).catch(() => {})
    await releaseClaim(op, lastError ? { lastError } : {})
  }
}

function toJob(row: PluginData): Job {
  return { ...(row.value as unknown as Omit<Job, 'jobId' | 'pluginId' | 'userId'>), jobId: row.key, pluginId: row.pluginId, userId: row.ownerId }
}

async function failOverdueJobs(): Promise<number> {
  const rows = await prisma.pluginData.findMany({
    where: {
      collection: JOBS_COLLECTION,
      namespace: 'live',
      OR: [{ value: { path: ['status'], equals: 'running' } }, { value: { path: ['status'], equals: 'queued' } }],
    },
    take: OVERDUE_JOBS_MAX,
  })
  let n = 0
  for (const row of rows) {
    const deadline = Date.parse(String((row.value as { deadline?: unknown } | null)?.deadline ?? ''))
    if (!(deadline < now().getTime())) continue
    await failJob(toJob(row), { code: 'timeout', message: 'The job did not finish before its deadline.' })
    n++
  }
  return n
}

async function deleteExpiredRows(timeLeft: () => boolean): Promise<number> {
  let total = 0
  for (let i = 0; i < EXPIRED_BATCHES_MAX && timeLeft(); i++) {
    // A migration's copy keeps its rows until the swap; expired ones go from live at the next tick.
    const ids = await prisma.pluginData.findMany({
      where: { namespace: 'live', expiresAt: { lte: now() } },
      select: { id: true },
      take: EXPIRED_BATCH,
    })
    if (!ids.length) break
    const { count } = await prisma.pluginData.deleteMany({ where: { id: { in: ids.map((r) => r.id) } } })
    total += count
    if (ids.length < EXPIRED_BATCH) break
  }
  return total
}

async function checkStaleOverrides(d: Deps, report: ReconcileReport) {
  const rows = await prisma.pluginOverride.findMany({ where: { extensionPoint: 'skill.text', status: 'active' } })
  if (!rows.length) {
    report.registry = 'none'
    return
  }
  const skills = new Map<string, RegistrySkill | null>()
  try {
    for (const g of new Set(rows.map((r) => r.targetGroup))) skills.set(g, await d.registrySkill(g))
  } catch (e) {
    const code = e instanceof SkillPartsRegistryError ? e.code : 'error'
    report.registry = `skipped: ${code}`
    console.warn(`[plugins] reconcile: stale-override check skipped, the agent's part registry is unavailable (${code})`)
    return
  }
  report.registry = 'checked'
  const sets = new Map<string, typeof rows>()
  for (const r of rows) sets.set(r.changeSetId, [...(sets.get(r.changeSetId) ?? []), r])
  for (const [changeSetId, parts] of sets) {
    let reason: StaleReason | null = null
    for (const p of parts) {
      const part = skills.get(p.targetGroup)?.parts.find((x) => x.partId === p.targetKey.slice(p.targetKey.indexOf('/') + 1))
      if (!part) {
        reason = 'part_removed'
        break
      }
      if (part.sha256 !== p.baseSha256) reason = 'factory_changed'
    }
    if (!reason || !(await markStale(changeSetId, reason)).length) continue
    report.staleSets.push(changeSetId)
    await auditPlugin('plugin.override.stale', {
      ...SYSTEM,
      pluginId: parts[0].pluginId,
      targetType: 'plugin_change_set',
      targetId: changeSetId,
      before: { status: 'active' },
      after: { status: 'stale', staleReason: reason },
    })
  }
}

async function cleanFolders(report: ReconcileReport) {
  const rows = await prisma.pluginInstall.findMany()
  const referenced = new Map<string, Set<string>>()
  const liveOps = new Set<string>()
  for (const r of rows) {
    referenced.set(r.pluginId, new Set([r.activeVersion, r.previousVersion, r.pendingVersion].filter(Boolean) as string[]))
    if (liveLease(r)) liveOps.add(r.operationId as string)
  }
  // File times are wall-clock: the grace is measured against the real clock.
  const cutoff = Date.now() - FOLDER_GRACE_MS
  for (const p of await listPluginFolders()) {
    const keep = referenced.get(p.pluginId)
    for (const v of p.versions) {
      if (keep?.has(v.version) || v.mtimeMs > cutoff) continue
      await removeVersion(p.pluginId, v.version)
      report.foldersRemoved.push(`${p.pluginId}/versions/${v.version}`)
    }
    if (!referenced.has(p.pluginId) && (await listVersions(p.pluginId)).length === 0) {
      await removePluginFolder(p.pluginId)
    }
  }
  for (const s of await listStaging()) {
    if (liveOps.has(s.operationId) || s.mtimeMs > cutoff || s.operationId.includes('/') || s.operationId.startsWith('.')) continue
    await fs.rm(path.join(pluginsDir(), STAGING_DIR, s.operationId), { recursive: true, force: true })
    report.stagingRemoved.push(s.operationId)
  }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export async function reconcile(deps: ReconcileDeps = {}): Promise<ReconcileReport | { skipped: 'busy' }> {
  const d: Deps = { ...defaults(), ...deps } as Deps
  const holder = randomUUID()
  if (!(await takeLease(holder))) return { skipped: 'busy' }
  const started = Date.now()
  const timeLeft = () => Date.now() - started < d.budgetMs
  const report: ReconcileReport = {
    recovered: [], healed: [], deferred: [], statusChanges: [], revoked: [], unrevoked: [],
    userSkillRevocations: { withdrawn: [], quarantined: [] }, catalog: 'not_loaded',
    registry: 'not_checked', staleSets: [], foldersRemoved: [], stagingRemoved: [], expiredRows: 0, overdueJobs: 0,
    runnerReloaded: false, budgetExhausted: false, errors: [],
  }
  let runListChanged = false
  const retry = new Set<string>()
  const note = (what: string, e: unknown) => {
    if (e instanceof PluginConflictError) return // another operation took it meanwhile: its outcome wins
    report.errors.push(`${what}: ${(e as Error)?.message ?? String(e)}`)
    console.error(`[plugins] reconcile: ${what} failed: ${(e as Error)?.stack ?? String(e)}`)
  }
  const changeStatus = async (row: PluginInstall, to: PluginStatus, patch: Prisma.PluginInstallUpdateManyMutationInput = {}) => {
    await transition(row.pluginId, { from: [row.status as PluginStatus], to, patch })
    report.statusChanges.push({ pluginId: row.pluginId, from: row.status, to })
    runListChanged = true
  }

  try {
    // 1. Operations whose lease expired.
    for (const row of await prisma.pluginInstall.findMany({ orderBy: { pluginId: 'asc' } })) {
      if (!['installing', 'updating', 'uninstalling'].includes(row.status) || liveLease(row)) continue
      await renewLease(holder)
      try {
        const outcome = await recoverOperation(row, d)
        report.recovered.push({ pluginId: row.pluginId, from: row.status, outcome })
        runListChanged = true
      } catch (e) {
        note(`recovering ${row.pluginId}`, e)
      }
    }

    // 2. The catalog, for revocations; installed plugins keep running without one.
    let loaded: LoadedCatalog | null = null
    try {
      loaded = await d.loadCatalog()
      report.catalog = 'loaded'
    } catch (e) {
      report.catalog = `unavailable: ${e instanceof CatalogError ? e.code : 'error'}`
    }

    // 3. Installed plugins: revocation, the version folder, the platform range, Retry.
    let healsLeft = 1
    for (const row of await prisma.pluginInstall.findMany({ orderBy: { pluginId: 'asc' } })) {
      if (!isInstalled(row.status) || liveLease(row) || !row.activeVersion) continue
      await renewLease(holder)
      try {
        let revokedReason = row.revokedReason
        if (loaded) {
          const reason = isRevoked(loaded.catalog, row.pluginId, row.activeVersion)
          if (reason !== row.revokedReason && !(reason === null && row.revokedReason === null)) {
            // For the version read: an operation that switched it meanwhile wins.
            const { count } = await prisma.pluginInstall.updateMany({
              where: { pluginId: row.pluginId, activeVersion: row.activeVersion, operationId: null },
              data: { revokedReason: reason },
            })
            if (!count) continue
            revokedReason = reason
            runListChanged = true
            ;(reason === null ? report.unrevoked : report.revoked).push(row.pluginId)
            await auditPlugin('plugin.revoked', {
              ...SYSTEM,
              pluginId: row.pluginId,
              before: { revokedReason: row.revokedReason },
              after: { version: row.activeVersion, revokedReason: reason, ...(reason === null ? { cleared: true } : {}) },
            })
          }
        }

        if (!(await versionExists(row.pluginId, row.activeVersion))) {
          if (pinnedRelease(row) && (healsLeft <= 0 || !timeLeft())) {
            report.deferred.push(row.pluginId)
            continue
          }
          if (pinnedRelease(row)) healsLeft--
          const outcome = await heal(row, d)
          runListChanged = true
          if (outcome.ok) {
            report.healed.push(row.pluginId)
            if (row.status === 'failed' && row.enabled && revokedReason === null) await changeStatus(row, 'ready')
            continue
          }
          if (row.status === 'ready') await changeStatus(row, 'failed', { lastError: outcome.lastError })
          else await prisma.pluginInstall.updateMany({ where: { pluginId: row.pluginId, operationId: null }, data: { lastError: outcome.lastError } })
          continue
        }

        const range = (row.manifest as { platform?: unknown } | null)?.platform
        const inRange = typeof range === 'string' && isValidRange(range) && satisfies(d.platformVersion, range)
        if (!inRange && row.status !== 'incompatible') {
          await changeStatus(row, 'incompatible')
        } else if (inRange && row.status === 'incompatible') {
          await changeStatus(row, 'ready')
          // The run list leaves out a disabled or revoked plugin: no worker to wait for.
          if (row.enabled && revokedReason === null) retry.add(row.pluginId)
        } else if (inRange && row.status === 'failed' && row.enabled && revokedReason === null) {
          await changeStatus(row, 'ready')
          retry.add(row.pluginId)
        }
      } catch (e) {
        note(`checking ${row.pluginId}`, e)
      }
    }

    // 3b. Every version the catalog revokes, installed or not: its waiting user-skill
    // proposals are withdrawn and the skills saved from its proposals quarantined. A plugin
    // that was uninstalled keeps no row here, which is why this does not walk the installs.
    if (loaded) {
      let pairs: { id: string; version: string }[] = []
      try {
        pairs = await pairsWithUserSkillProvenance(loaded.catalog.revoked)
      } catch (e) {
        note('reading what revoked versions proposed', e)
      }
      for (const { id, version } of pairs) {
        try {
          const done = await revokeUserSkillProvenance(id, version)
          report.userSkillRevocations.withdrawn.push(...done.withdrawn)
          report.userSkillRevocations.quarantined.push(...done.quarantined)
        } catch (e) {
          note(`revoking what ${id} ${version} proposed`, e)
        }
      }
    }

    // 4. Housekeeping, while time is left.
    const steps: [string, () => Promise<void>][] = [
      ['stale overrides', () => checkStaleOverrides(d, report)],
      ['expired data rows', async () => void (report.expiredRows = await deleteExpiredRows(timeLeft))],
      ['overdue jobs', async () => void (report.overdueJobs = await failOverdueJobs())],
      ['folders', () => cleanFolders(report)],
    ]
    for (const [what, step] of steps) {
      if (!timeLeft()) {
        report.budgetExhausted = true
        break
      }
      await renewLease(holder)
      try {
        await step()
      } catch (e) {
        note(what, e)
      }
    }

    // 5. The runner converges on the run list; a retried plugin is settled by its worker.
    if (runListChanged) {
      await renewLease(holder)
      report.runnerReloaded = true
      let workers: { id: string; state?: string }[] | null = null
      let why = 'runner_unavailable'
      try {
        await runnerReload()
        const health = await runnerHealth()
        if (health.state === 'out_of_date') why = 'runner_out_of_date'
        else workers = health.workers
      } catch (e) {
        if (e instanceof RunnerError || e instanceof RunnerUnavailableError) why = runnerFailureSummary(e)
        else note('reloading the runner', e)
      }
      for (const pluginId of retry) {
        const row = await prisma.pluginInstall.findUnique({ where: { pluginId } })
        if (!row || row.status !== 'ready' || liveLease(row)) continue
        const w = workers?.find((x) => x.id === pluginId && (x as { version?: string }).version === row.activeVersion)
        try {
          if (w && (!w.state || w.state === 'ready')) {
            await prisma.pluginInstall.updateMany({ where: { pluginId, operationId: null }, data: { lastError: null } })
          } else {
            const lastError = workers ? `worker_failed: the worker is ${w?.state ?? 'not running'}` : why
            await changeStatus(row, 'failed', { lastError })
          }
        } catch (e) {
          note(`settling ${pluginId}`, e)
        }
      }
    }
    if (report.errors.length || report.recovered.length || report.healed.length || report.statusChanges.length) {
      console.log(
        `[plugins] reconcile: recovered=${report.recovered.length} healed=${report.healed.length} ` +
          `status=${report.statusChanges.length} revoked=${report.revoked.length} stale=${report.staleSets.length} ` +
          `errors=${report.errors.length} in ${Date.now() - started} ms`,
      )
    }
    return report
  } finally {
    await releaseLease(holder).catch(() => {})
  }
}
