import { Prisma, type PluginInstall, type PluginOverride } from '@prisma/client'
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { compareVersions, isValidVersion, parseVersion, satisfies } from '@/lib/semver'
import { auditPlugin } from './audit'
import { CatalogError, findCatalogPlugin, isRevoked, loadCatalog, type LoadedCatalog } from './catalog'
import { now } from './clock'
import { likePrefix } from './dataStore'
import { lastExportAt } from './exportData'
import { FetchRemoteError, fetchRemote } from './fetchRemote'
import { isValidPluginId } from './ids'
import { checkAndStage } from './installChecks'
import {
  EXPORT_FRESH_MS,
  INSTALLED_STATUSES,
  LifecycleError,
  exportMarkerKey,
  installView,
  type InstallView,
} from './lifecycleCommon'
import { MigrationFailure, migrationSteps, runMigrations, type MigrationStats } from './migrations'
import { USER_SKILL_POINT, markStaleIn, type StaleReason } from './overrides'
import { isPluginPermission } from './permissions'
import { PLUGIN_PLATFORM_VERSION } from './platformVersion'
import {
  PluginConflictError,
  beginOperation,
  createForInstall,
  endOperation,
  findInstall,
  heartbeat,
  transition,
  type Operation,
  type PluginStatus,
} from './registry'
import { RunnerError, RunnerUnavailableError, runnerFailureSummary, runnerHealth, runnerReload } from './runnerClient'
import { parseManifest, type PluginManifest } from './schemas/manifest'
import type { CatalogRelease } from './schemas/catalog'
import { registrySkill, type RegistrySkill } from './skillPartsRegistry'
import {
  commitVersion,
  discardStaging,
  listVersions,
  removePluginFolder,
  removeVersion,
  versionExists,
  versionPath,
} from './staging'

export { EXPORT_FRESH_MS, LifecycleError, installView, type InstallView } from './lifecycleCommon'

/**
 * The plugin lifecycle (README.PLUGINS.md §9): install, enable, disable, uninstall. Each
 * runs inside the admin's request (TD-21) and is audited with before and after.
 *
 * - Install, update and uninstall hold an operation lease (registry.ts), so two admins,
 *   two webapp copies or reconciliation never work on one plugin at once, and a crashed
 *   operation is found by its expired lease (§9.7).
 * - Enable and disable are one compare-and-set on `enabled`, refused while an operation
 *   holds a live lease.
 * - The database write is the commit: until it lands the runner, the UI and the agent
 *   ignore the folder; reconciliation removes a folder no row references.
 * - The runner is told after every change. The runner runs only `ready` rows, so an
 *   install commits `ready`, then reads the worker's state and moves to `failed` with the
 *   reason when it did not start (`runner_unavailable` when the runner cannot be reached;
 *   reconciliation retries).
 */
export interface LifecycleDeps {
  loadCatalog?: () => Promise<LoadedCatalog>
  fetchArchive?: (url: string) => Promise<Buffer>
  registrySkill?: (skillId: string) => Promise<RegistrySkill | null>
  platformVersion?: string
}

const defaults: Required<LifecycleDeps> = {
  loadCatalog: () => loadCatalog({ source: 'official' }),
  fetchArchive: async (url) => (await fetchRemote(url, { kind: 'archive' })).bytes,
  registrySkill,
  platformVersion: PLUGIN_PLATFORM_VERSION,
}

const withDefaults = (deps: LifecycleDeps = {}): Required<LifecycleDeps> => ({ ...defaults, ...deps })

const leaseFree = (): Prisma.PluginInstallWhereInput[] => [{ operationId: null }, { leaseExpiresAt: { lt: now() } }]
const isInstalled = (s: string) => (INSTALLED_STATUSES as readonly string[]).includes(s)
const liveLease = (r: PluginInstall) => !!r.operationId && !!r.leaseExpiresAt && r.leaseExpiresAt > now()

function checkPluginId(pluginId: string) {
  if (!isValidPluginId(pluginId)) throw new LifecycleError(400, 'invalid_plugin_id', 'Invalid plugin id.')
}

const sameSet = (a: string[], b: string[]) => a.length === b.length && new Set(a).size === a.length && a.every((x) => b.includes(x))

const snapshot = (r: PluginInstall | null) =>
  r
    ? {
        status: r.status,
        enabled: r.enabled,
        activeVersion: r.activeVersion,
        previousVersion: r.previousVersion,
        dataVersion: r.dataVersion,
        grantedPermissions: r.grantedPermissions,
        lastError: r.lastError,
      }
    : null

/** The versions an operation is planned with: its start is a compare-and-set on them. */
const plannedWith = (r: PluginInstall) => ({ activeVersion: r.activeVersion, previousVersion: r.previousVersion, dataVersion: r.dataVersion })
const samePlan = (a: PluginInstall, b: PluginInstall) => JSON.stringify(plannedWith(a)) === JSON.stringify(plannedWith(b))

/**
 * A failure after the commit: the operation took effect, so the answer says so instead of
 * reporting a failure that a retry would then refuse as already done.
 */
function failedAfterCommit(e: unknown, what: string): LifecycleError {
  const code = safeErrorCode(e)
  console.error(`[plugins] ${what} took effect, but a step after its commit failed (${code}): ${(e as Error)?.stack ?? String(e)}`)
  return new LifecycleError(
    500,
    code,
    `The ${what} took effect, but a step after it failed (${code}); the page shows its state now. The webapp log has the details.`,
    undefined,
    { committed: true },
  )
}

function changed(pluginId: string, row: PluginInstall): LifecycleError {
  return new LifecycleError(
    409,
    'plugin_changed',
    `Plugin ${pluginId} changed while this request was being prepared (now ${row.activeVersion ?? 'not installed'}); reload and try again.`,
  )
}

/** Why a start lost its compare-and-set: an operation that finished meanwhile, or one still running. */
async function lostStart(pluginId: string, before: PluginInstall): Promise<LifecycleError> {
  const row = await findInstall(pluginId)
  if (row && !liveLease(row) && row.status !== 'uninstalling' && !samePlan(row, before)) return changed(pluginId, row)
  return busyOrNotInstalled(row, pluginId)
}

function busyOrNotInstalled(row: PluginInstall | null, pluginId: string): LifecycleError {
  if (row && !isInstalled(row.status) && row.status !== 'available' && liveLease(row)) {
    return new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: another operation is in progress.`)
  }
  if (!row || !isInstalled(row.status)) {
    return new LifecycleError(409, 'not_installed', `Plugin ${pluginId} is not installed.`)
  }
  return new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: another operation is in progress.`)
}

/** The plugin's own data rows (not the platform's `__` rows) that a reinstall would find. */
/**
 * What an uninstall with "keep data" left: data rows, approved skill versions, or proposals
 * for people's own skills still waiting. A user-skill proposal that was saved, rejected or
 * withdrawn is only the provenance of a decision: alone it must not keep an uninstalled
 * plugin listed forever.
 */
export async function hasKeptAnything(pluginId: string): Promise<boolean> {
  if (await hasKeptData(pluginId)) return true
  return !!(await prisma.pluginOverride.findFirst({
    where: { pluginId, OR: [{ extensionPoint: { not: USER_SKILL_POINT } }, { status: 'proposed' }] },
    select: { id: true },
  }))
}

export async function hasKeptData(pluginId: string): Promise<boolean> {
  const row = await prisma.pluginData.findFirst({
    where: { pluginId, namespace: 'live', NOT: { collection: { startsWith: likePrefix('__') } } },
    select: { id: true },
  })
  return !!row
}

async function activeSetsOf(pluginId: string): Promise<Map<string, PluginOverride[]>> {
  const rows = await prisma.pluginOverride.findMany({ where: { pluginId, status: 'active' } })
  const sets = new Map<string, PluginOverride[]>()
  for (const r of rows) sets.set(r.changeSetId, [...(sets.get(r.changeSetId) ?? []), r])
  return sets
}

type WorkerOutcome = { ok: true } | { ok: false; lastError: string }

/** Asks the runner to converge on the run list, then whether this version's worker is up. */
export async function startWorker(pluginId: string, version: string): Promise<WorkerOutcome> {
  try {
    await runnerReload()
    const health = await runnerHealth()
    if (health.state === 'out_of_date') return { ok: false, lastError: 'runner_out_of_date' }
    const w = health.workers.find((x) => x.id === pluginId && x.version === version)
    if (!w) return { ok: false, lastError: 'worker_failed: the runner did not start a worker for this version' }
    if (w.state && w.state !== 'ready') return { ok: false, lastError: `worker_failed: the worker is ${w.state}` }
    return { ok: true }
  } catch (e) {
    if (e instanceof RunnerUnavailableError || e instanceof RunnerError) return { ok: false, lastError: runnerFailureSummary(e) }
    throw e
  }
}

/** Reloads the runner when only stopping workers: a runner that is down converges at its next sync. */
async function tellRunner(pluginId: string, what: string) {
  try {
    await runnerReload()
  } catch (e) {
    const why = e instanceof RunnerUnavailableError ? e.reason : e instanceof RunnerError ? e.code : String(e)
    console.warn(`[plugins] ${what} ${pluginId}: the runner was not told (${why}); it converges at its next run-list sync`)
  }
}

/** After a commit as `ready`: the worker's state decides `ready` or `failed`. */
async function settleWorker(pluginId: string, version: string): Promise<PluginInstall> {
  const outcome = await startWorker(pluginId, version)
  const row = (await findInstall(pluginId))!
  try {
    if (outcome.ok) {
      if (row.status === 'failed') await transition(pluginId, { from: ['failed'], to: 'ready', patch: { lastError: null } })
      else if (row.lastError) await prisma.pluginInstall.updateMany({ where: { pluginId, OR: leaseFree() }, data: { lastError: null } })
    } else if (row.status === 'ready') {
      await transition(pluginId, { from: ['ready'], to: 'failed', patch: { lastError: outcome.lastError } })
    } else {
      await prisma.pluginInstall.updateMany({ where: { pluginId, OR: leaseFree() }, data: { lastError: outcome.lastError } })
    }
  } catch (e) {
    // Another operation took the plugin meanwhile; its outcome wins.
    if (!(e instanceof PluginConflictError)) throw e
  }
  if (!outcome.ok) console.warn(`[plugins] ${pluginId} ${version}: ${outcome.lastError}`)
  return (await findInstall(pluginId))!
}

export const entryOf = (r: CatalogRelease) => ({
  version: r.version,
  url: r.url,
  sha256: r.sha256,
  platform: r.platform,
  dataVersion: r.dataVersion,
  permissions: r.permissions,
})

/** The pinned entry without its own `previous`: one level of history is enough to heal. */
export function withoutPrevious(entry: Prisma.JsonValue | null): Record<string, unknown> | null {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  const rest = { ...(entry as Record<string, unknown>) }
  delete rest.previous
  return rest
}

const LEASE_CLEARED = { operationId: null, operationKind: null, operationArgs: Prisma.DbNull, leaseExpiresAt: null }

/**
 * The write that ends an operation as `ready`, for use inside a transaction: the data
 * swap of a migration and the switch of version commit together, or neither does.
 */
export function commitIn(op: Operation, from: PluginStatus, patch: Prisma.PluginInstallUpdateManyMutationInput) {
  return async (tx: Prisma.TransactionClient) => {
    const { count } = await tx.pluginInstall.updateMany({
      where: { pluginId: op.pluginId, status: from, operationId: op.operationId },
      data: { ...patch, ...LEASE_CLEARED, status: 'ready' },
    })
    if (count !== 1) throw new PluginConflictError(op.pluginId, 'the operation lost its lease')
  }
}

/** A version's manifest as it is on the volume, checked again (rollback has no other copy). */
export async function manifestOnDisk(pluginId: string, version: string): Promise<PluginManifest | null> {
  try {
    const raw = JSON.parse(await fs.readFile(path.join(versionPath(pluginId, version), 'plugin.json'), 'utf8'))
    const parsed = parseManifest(raw)
    return parsed.ok && parsed.value.id === pluginId && parsed.value.version === version ? parsed.value : null
  } catch {
    return null
  }
}

/** Back to the status the plugin had before a refused update or rollback (`updating` only goes to `ready`). */
async function restoreStatus(op: Operation, previous: string, lastError: string) {
  try {
    await endOperation(op, 'ready', { pendingVersion: null, lastError: lastError.slice(0, 2000) })
    if (previous === 'failed' || previous === 'incompatible') {
      await transition(op.pluginId, { from: ['ready'], to: previous as PluginStatus })
    }
  } catch (e) {
    if (!(e instanceof PluginConflictError)) throw e
    console.warn(`[plugins] ${op.kind} ${op.pluginId}: the lease was lost; reconciliation finishes it`)
  }
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

export interface InstallInput {
  version: string
  acceptedPermissions: string[]
  restoreOverrides?: boolean
}

function checkInstallInput(input: InstallInput) {
  if (!input || typeof input !== 'object') throw new LifecycleError(400, 'invalid_request', 'A JSON object is required.')
  if (typeof input.version !== 'string' || !isValidVersion(input.version)) {
    throw new LifecycleError(400, 'invalid_request', 'version must be a version x.y.z.')
  }
  if (!Array.isArray(input.acceptedPermissions) || !input.acceptedPermissions.every((p) => typeof p === 'string')) {
    throw new LifecycleError(400, 'invalid_request', 'acceptedPermissions must be a list of permission names.')
  }
  if (input.restoreOverrides !== undefined && typeof input.restoreOverrides !== 'boolean') {
    throw new LifecycleError(400, 'invalid_request', 'restoreOverrides must be true or false.')
  }
}

async function catalogOrFail(d: Required<LifecycleDeps>): Promise<LoadedCatalog> {
  try {
    return await d.loadCatalog()
  } catch (e) {
    if (e instanceof CatalogError) {
      throw new LifecycleError(503, 'catalog_unavailable', `The plugin catalog cannot be used: ${e.message}`, [e.code])
    }
    throw e
  }
}

interface OverridePlan {
  clear: { changeSetId: string; revision: number | null }[]
  stale: { changeSetId: string; reason: StaleReason }[]
  restored: number
}

/**
 * What a reinstall does to the active versions a kept plugin left behind, decided before
 * anything is written: the writes go into the install's commit (applyOverrides), so none
 * applies early and a refused install changes none.
 */
async function planOverrides(pluginId: string, restore: boolean | undefined, d: Required<LifecycleDeps>): Promise<OverridePlan> {
  const sets = await activeSetsOf(pluginId)
  const plan: OverridePlan = { clear: [], stale: [], restored: 0 }
  if (!sets.size) return plan
  if (restore === false) {
    for (const [changeSetId, rows] of sets) plan.clear.push({ changeSetId, revision: rows[0].revision })
    return plan
  }
  for (const [changeSetId, rows] of sets) {
    let reason: StaleReason | null = null
    try {
      for (const r of rows) {
        const skill = await d.registrySkill(r.targetGroup)
        const partId = r.targetKey.slice(r.targetKey.indexOf('/') + 1)
        const part = skill?.parts.find((p) => p.partId === partId)
        if (!part) {
          reason = 'part_removed'
          break
        }
        if (part.sha256 !== r.baseSha256) reason = 'factory_changed'
      }
    } catch (e) {
      console.warn(`[plugins] reinstall ${pluginId}: the agent's skill registry could not be read (${(e as Error).message}); ` +
        'restored versions are checked at the next reconciliation')
      return { clear: [], stale: [], restored: sets.size }
    }
    if (reason) plan.stale.push({ changeSetId, reason })
    else plan.restored++
  }
  return plan
}

/** The plan's writes, inside the install's commit; what really changed, for the audits. */
async function applyOverrides(tx: Prisma.TransactionClient, plan: OverridePlan, actorId: string) {
  const cleared: OverridePlan['clear'] = []
  for (const c of plan.clear) {
    const { count } = await tx.pluginOverride.updateMany({
      where: { changeSetId: c.changeSetId, status: 'active' },
      data: { status: 'cleared', decidedBy: actorId, decidedAt: now() },
    })
    if (count) cleared.push(c)
  }
  const stale: OverridePlan['stale'] = []
  for (const st of plan.stale) if (await markStaleIn(tx, st.changeSetId, st.reason)) stale.push(st)
  return { cleared, stale }
}

async function auditOverrides(pluginId: string, applied: Awaited<ReturnType<typeof applyOverrides>>, actorId: string) {
  for (const c of applied.cleared) {
    await auditPlugin('plugin.override.reset', {
      actorId,
      pluginId,
      targetType: 'plugin_change_set',
      targetId: c.changeSetId,
      before: { status: 'active', revision: c.revision },
      after: { status: 'cleared', reason: 'not restored at reinstall' },
      source: 'admin',
    })
  }
  for (const st of applied.stale) {
    await auditPlugin('plugin.override.stale', {
      actorId,
      pluginId,
      targetType: 'plugin_change_set',
      targetId: st.changeSetId,
      before: { status: 'active' },
      after: { status: 'stale', staleReason: st.reason },
      source: 'admin',
    })
  }
}

export async function install(
  pluginId: string,
  input: InstallInput,
  actorId: string,
  deps?: LifecycleDeps,
): Promise<{ plugin: InstallView }> {
  const d = withDefaults(deps)
  checkPluginId(pluginId)
  checkInstallInput(input)

  const loaded = await catalogOrFail(d)
  const entry = findCatalogPlugin(loaded.catalog, pluginId)
  if (!entry) throw new LifecycleError(404, 'not_in_catalog', `The catalog lists no plugin ${pluginId}.`)
  const release = entry.releases.find((r) => r.version === input.version)
  if (!release) throw new LifecycleError(404, 'release_not_found', `The catalog lists no release ${input.version} of ${pluginId}.`)
  const revoked = isRevoked(loaded.catalog, pluginId, release.version)
  if (revoked !== null) throw new LifecycleError(409, 'release_revoked', `Release ${release.version} was revoked: ${revoked}`)
  if (!release.permissions.every(isPluginPermission)) {
    throw new LifecycleError(409, 'unknown_contribution', `Release ${release.version} asks for a permission this RedAmon does not know.`)
  }
  if (!satisfies(d.platformVersion, release.platform)) {
    throw new LifecycleError(
      409,
      'platform_incompatible',
      `Release ${release.version} needs platform ${release.platform}; this RedAmon runs ${d.platformVersion}.`,
    )
  }
  if (!sameSet(input.acceptedPermissions, release.permissions)) {
    throw new LifecycleError(400, 'permissions_mismatch', 'The accepted permissions must be exactly the ones this release asks for.')
  }

  const existing = await findInstall(pluginId)
  let activeSets = 0
  let keptData = false
  if (existing) {
    if (existing.status !== 'available') {
      if (liveLease(existing)) throw new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: another operation is in progress.`)
      throw new LifecycleError(409, 'already_installed', `Plugin ${pluginId} is already installed; update or uninstall it.`)
    }
    keptData = await hasKeptData(pluginId)
    if (keptData && existing.dataVersion > release.dataVersion) {
      throw new LifecycleError(
        409,
        'data_newer_than_release',
        `The data kept from an earlier install is at data version ${existing.dataVersion}, newer than this ` +
          `release's ${release.dataVersion}. Old code never runs on newer data: install a newer release, or export and purge the data.`,
      )
    }
    activeSets = (await activeSetsOf(pluginId)).size
    if (activeSets && input.restoreOverrides === undefined) {
      throw new LifecycleError(
        400,
        'restore_choice_required',
        `This plugin left ${activeSets} approved skill version(s): say whether to restore them.`,
        [String(activeSets)],
      )
    }
  }

  const args = { version: release.version, restoreOverrides: input.restoreOverrides ?? null, by: actorId }
  let op: Operation
  try {
    op = existing
      ? await beginOperation(pluginId, ['available'], 'installing', 'install', args, prisma, plannedWith(existing))
      : await createForInstall(pluginId, args)
    // Clean-up keeps a version folder a row references: this one is not referenced otherwise
    // until the commit, which a long migration of kept data puts past the folder grace.
    await prisma.pluginInstall.updateMany({ where: { pluginId, operationId: op.operationId }, data: { pendingVersion: release.version } })
  } catch (e) {
    if (e instanceof PluginConflictError) {
      if (existing) {
        const lost = await lostStart(pluginId, existing)
        if (lost.code === 'plugin_changed') throw lost
      }
      throw new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: another operation is in progress.`)
    }
    throw e
  }

  let committedFolder = false
  const refuse = async (code: string, message: string, status: number, details?: string[]) => {
    await discardStaging(op.operationId).catch(() => {})
    if (committedFolder) await removeVersion(pluginId, release.version).catch(() => {})
    await endOperation(op, 'available', { pendingVersion: null, lastError: `${code}: ${message}`.slice(0, 2000) }).catch(() => {})
    await auditPlugin('plugin.install_failed', {
      actorId,
      pluginId,
      before: snapshot(existing),
      after: { version: release.version, code, message },
      source: 'admin',
    })
    console.warn(`[plugins] install ${pluginId} ${release.version} refused: ${code}`)
    return new LifecycleError(status, code, message, details)
  }

  let bytes: Buffer
  try {
    bytes = await d.fetchArchive(release.url)
  } catch (e) {
    const why = e instanceof FetchRemoteError ? `${e.code}: ${e.message}` : safeErrorCode(e)
    throw await refuse('download_failed', `The archive could not be downloaded (${why}).`, 502)
  }
  let checked: Awaited<ReturnType<typeof checkAndStage>>
  try {
    checked = await checkAndStage(op.operationId, { pluginId, archiveBytes: bytes, release, platformVersion: d.platformVersion })
  } catch (e) {
    throw await refuse('staging_failed', `The archive could not be written to the plugins volume (${safeErrorCode(e)}).`, 500)
  }
  if (!checked.ok) throw await refuse(checked.code, checked.message, 422, checked.details)

  let committed = false
  try {
    await heartbeat(op)
    // A folder of this version no row references (an earlier crash) gives way to this one.
    if (await versionExists(pluginId, release.version)) await removeVersion(pluginId, release.version)
    await commitVersion(op.operationId, pluginId, release.version)
    committedFolder = true
    const plan = await planOverrides(pluginId, input.restoreOverrides, d)
    const commitRow = commitIn(op, 'installing', {
      enabled: true,
      activeVersion: release.version,
      previousVersion: null,
      pendingVersion: null,
      dataVersion: release.dataVersion,
      previousDataVersion: existing && keptData && existing.dataVersion !== release.dataVersion ? existing.dataVersion : null,
      grantedPermissions: release.permissions,
      manifest: checked.manifest as unknown as Prisma.InputJsonValue,
      catalogEntry: entryOf(release),
      installedBy: actorId,
      installedAt: now(),
      lastError: null,
      revokedReason: null,
    })
    let applied: Awaited<ReturnType<typeof applyOverrides>> = { cleared: [], stale: [] }
    const commit = async (tx: Prisma.TransactionClient) => {
      await commitRow(tx)
      applied = await applyOverrides(tx, plan, actorId)
    }
    let migration: MigrationStats | null = null
    if (existing && keptData && existing.dataVersion < release.dataVersion) {
      // Data kept from an earlier install, older than this release: migrated as an update would.
      try {
        migration = await runMigrations(
          { operation: op, version: release.version, from: existing.dataVersion, to: release.dataVersion },
          commit,
        )
      } catch (e) {
        const f = e as MigrationFailure
        if (f.code === 'plugin_busy') throw new PluginConflictError(pluginId, f.message)
        throw await refuse(f.code, f.message, f.status)
      }
    } else {
      await prisma.$transaction(commit)
    }
    committed = true
    await auditOverrides(pluginId, applied, actorId)
    const overrides = { restored: plan.restored, stale: applied.stale.length, cleared: applied.cleared.length }
    await auditPlugin('plugin.permissions_granted', {
      actorId,
      pluginId,
      after: { version: release.version, permissions: release.permissions },
      source: 'admin',
    })
    const row = await settleWorker(pluginId, release.version)
    await auditPlugin('plugin.install', {
      actorId,
      pluginId,
      before: snapshot(existing),
      after: { ...snapshot(row), overrides, ...(migration ? { migration } : {}) },
      source: 'admin',
    })
    return { plugin: installView(row) }
  } catch (e) {
    await discardStaging(op.operationId).catch(() => {})
    if (e instanceof LifecycleError) throw e
    if (e instanceof PluginConflictError) {
      throw new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: the install lost its lease to another operation.`)
    }
    // Before the commit nothing is installed yet: undone now, not ten minutes later.
    if (!committed) throw await refuse('install_failed', `The install failed before it was committed (${safeErrorCode(e)}).`, 500)
    throw failedAfterCommit(e, `install of ${pluginId} ${release.version}`)
  }
}

// ---------------------------------------------------------------------------
// Enable, disable
// ---------------------------------------------------------------------------

async function setEnabled(pluginId: string, enabled: boolean): Promise<void> {
  const { count } = await prisma.pluginInstall.updateMany({
    where: { pluginId, status: { in: [...INSTALLED_STATUSES] }, OR: leaseFree() },
    data: { enabled },
  })
  if (count !== 1) throw busyOrNotInstalled(await findInstall(pluginId), pluginId)
}

export async function enable(pluginId: string, actorId: string, deps?: LifecycleDeps): Promise<{ plugin: InstallView }> {
  const d = withDefaults(deps)
  checkPluginId(pluginId)
  const before = await findInstall(pluginId)
  if (!before || !isInstalled(before.status) || liveLease(before)) throw busyOrNotInstalled(before, pluginId)
  if (before.revokedReason != null) {
    throw new LifecycleError(409, 'plugin_revoked', `This version was revoked by the catalog: ${before.revokedReason}`)
  }
  const range = (before.manifest as { platform?: unknown } | null)?.platform
  if (typeof range !== 'string' || !satisfies(d.platformVersion, range)) {
    if (before.status !== 'incompatible') {
      await transition(pluginId, { from: [before.status as PluginStatus], to: 'incompatible' }).catch(() => {})
    }
    throw new LifecycleError(
      409,
      'platform_incompatible',
      `This version needs platform ${String(range)}; this RedAmon runs ${d.platformVersion}. Update the plugin.`,
    )
  }
  await setEnabled(pluginId, true)
  // The runner runs only `ready` rows, so a failed plugin (Retry) is made `ready` first and
  // goes back to `failed` if its worker still does not start.
  if (before.status !== 'ready') {
    await transition(pluginId, { from: [before.status as PluginStatus], to: 'ready' })
  }
  const row = await settleWorker(pluginId, before.activeVersion as string)
  await auditPlugin('plugin.enable', { actorId, pluginId, before: snapshot(before), after: snapshot(row), source: 'admin' })
  return { plugin: installView(row) }
}

export async function disable(pluginId: string, actorId: string): Promise<{ plugin: InstallView }> {
  checkPluginId(pluginId)
  const before = await findInstall(pluginId)
  if (!before || !isInstalled(before.status) || liveLease(before)) throw busyOrNotInstalled(before, pluginId)
  await setEnabled(pluginId, false)
  await tellRunner(pluginId, 'disable')
  const row = (await findInstall(pluginId))!
  await auditPlugin('plugin.disable', { actorId, pluginId, before: snapshot(before), after: snapshot(row), source: 'admin' })
  return { plugin: installView(row) }
}

// ---------------------------------------------------------------------------
// Update, rollback
// ---------------------------------------------------------------------------

export interface UpdateInput {
  version: string
  acceptedPermissions: string[]
}

/**
 * Side by side (§9.5): the new release is checked and renamed in beside the active one,
 * which keeps its run-list entry and contributions while the plugin is `updating`; then
 * one write (with the data swap, when the data moves) makes it active. Only the active and
 * the previous version stay on disk. A disabled plugin can be updated and stays disabled.
 */
export async function update(
  pluginId: string,
  input: UpdateInput,
  actorId: string,
  deps?: LifecycleDeps,
): Promise<{ plugin: InstallView }> {
  const d = withDefaults(deps)
  checkPluginId(pluginId)
  checkInstallInput(input)
  const before = await findInstall(pluginId)
  if (!before || !isInstalled(before.status) || liveLease(before) || !before.activeVersion) {
    throw busyOrNotInstalled(before, pluginId)
  }
  const active = before.activeVersion as string

  const loaded = await catalogOrFail(d)
  const entry = findCatalogPlugin(loaded.catalog, pluginId)
  if (!entry) throw new LifecycleError(404, 'not_in_catalog', `The catalog lists no plugin ${pluginId}.`)
  const release = entry.releases.find((r) => r.version === input.version)
  if (!release) throw new LifecycleError(404, 'release_not_found', `The catalog lists no release ${input.version} of ${pluginId}.`)
  if (compareVersions(parseVersion(release.version), parseVersion(active)) <= 0) {
    throw new LifecycleError(409, 'not_newer', `Release ${release.version} is not newer than ${active}; roll back instead.`)
  }
  const revoked = isRevoked(loaded.catalog, pluginId, release.version)
  if (revoked !== null) throw new LifecycleError(409, 'release_revoked', `Release ${release.version} was revoked: ${revoked}`)
  if (!release.permissions.every(isPluginPermission)) {
    throw new LifecycleError(409, 'unknown_contribution', `Release ${release.version} asks for a permission this RedAmon does not know.`)
  }
  if (!satisfies(d.platformVersion, release.platform)) {
    throw new LifecycleError(
      409,
      'platform_incompatible',
      `Release ${release.version} needs platform ${release.platform}; this RedAmon runs ${d.platformVersion}.`,
    )
  }
  if (!sameSet(input.acceptedPermissions, release.permissions)) {
    throw new LifecycleError(400, 'permissions_mismatch', 'The accepted permissions must be exactly the ones this release asks for.')
  }
  const kept = await hasKeptData(pluginId)
  if (kept && release.dataVersion < before.dataVersion) {
    throw new LifecycleError(409, 'data_newer_than_release', `Release ${release.version} reads data version ${release.dataVersion}; the data is at ${before.dataVersion}.`)
  }

  let op: Operation
  try {
    op = await beginOperation(
      pluginId,
      [...INSTALLED_STATUSES],
      'updating',
      'update',
      {
        version: release.version,
        from: active,
        fromDataVersion: before.dataVersion,
        by: actorId,
        // What reconciliation needs to finish the update if this request dies after the rename.
        release: entryOf(release),
      },
      prisma,
      plannedWith(before),
    )
    await prisma.pluginInstall.updateMany({ where: { pluginId, operationId: op.operationId }, data: { pendingVersion: release.version } })
  } catch (e) {
    if (e instanceof PluginConflictError) throw await lostStart(pluginId, before)
    throw e
  }

  let committedFolder = false
  const fail = async (code: string, message: string, status: number, details?: string[]) => {
    await discardStaging(op.operationId).catch(() => {})
    if (committedFolder) await removeVersion(pluginId, release.version).catch(() => {})
    await restoreStatus(op, before.status, `${code}: ${message}`)
    await auditPlugin('plugin.update', {
      actorId,
      pluginId,
      before: snapshot(before),
      after: { outcome: 'failed', version: release.version, code, message },
      source: 'admin',
    })
    console.warn(`[plugins] update ${pluginId} ${active} → ${release.version} refused: ${code}`)
    return new LifecycleError(status, code, message, details)
  }

  let bytes: Buffer
  try {
    bytes = await d.fetchArchive(release.url)
  } catch (e) {
    const why = e instanceof FetchRemoteError ? `${e.code}: ${e.message}` : safeErrorCode(e)
    throw await fail('download_failed', `The archive could not be downloaded (${why}).`, 502)
  }
  let checked: Awaited<ReturnType<typeof checkAndStage>>
  try {
    checked = await checkAndStage(op.operationId, { pluginId, archiveBytes: bytes, release, platformVersion: d.platformVersion })
  } catch (e) {
    throw await fail('staging_failed', `The archive could not be written to the plugins volume (${safeErrorCode(e)}).`, 500)
  }
  if (!checked.ok) throw await fail(checked.code, checked.message, 422, checked.details)

  let committed = false
  try {
    await heartbeat(op)
    if (await versionExists(pluginId, release.version)) await removeVersion(pluginId, release.version)
    await commitVersion(op.operationId, pluginId, release.version)
    committedFolder = true
    const commit = commitIn(op, 'updating', {
      activeVersion: release.version,
      previousVersion: active,
      pendingVersion: null,
      dataVersion: release.dataVersion,
      previousDataVersion: before.dataVersion,
      grantedPermissions: release.permissions,
      manifest: checked.manifest as unknown as Prisma.InputJsonValue,
      catalogEntry: { ...entryOf(release), previous: withoutPrevious(before.catalogEntry) } as Prisma.InputJsonValue,
      lastError: null,
      // A revocation is of the version that was active; the catalog vouched for this one.
      revokedReason: null,
    })
    let migration: MigrationStats | null = null
    if (kept && release.dataVersion !== before.dataVersion) {
      try {
        migration = await runMigrations({ operation: op, version: release.version, from: before.dataVersion, to: release.dataVersion }, commit)
      } catch (e) {
        const f = e as MigrationFailure
        if (f.code === 'plugin_busy') throw new PluginConflictError(pluginId, f.message)
        throw await fail(f.code, f.message, f.status)
      }
    } else {
      await prisma.$transaction(commit)
    }
    committed = true
    for (const v of await listVersions(pluginId)) {
      if (v !== release.version && v !== active) await removeVersion(pluginId, v).catch(() => {})
    }
    const granted = Array.isArray(before.grantedPermissions) ? (before.grantedPermissions as string[]) : []
    const added = release.permissions.filter((p) => !granted.includes(p))
    if (added.length) {
      await auditPlugin('plugin.permissions_granted', {
        actorId,
        pluginId,
        after: { version: release.version, permissions: release.permissions, added },
        source: 'admin',
      })
    }
    let row: PluginInstall
    if (before.enabled) row = await settleWorker(pluginId, release.version)
    else {
      await tellRunner(pluginId, 'update')
      row = (await findInstall(pluginId))!
    }
    await auditPlugin('plugin.update', {
      actorId,
      pluginId,
      before: snapshot(before),
      after: { ...snapshot(row), previousVersion: row.previousVersion, ...(migration ? { migration } : {}) },
      source: 'admin',
    })
    return { plugin: installView(row) }
  } catch (e) {
    await discardStaging(op.operationId).catch(() => {})
    if (e instanceof LifecycleError) throw e
    if (e instanceof PluginConflictError) {
      throw new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: the update lost its lease to another operation.`)
    }
    if (!committed) throw await fail('update_failed', `The update failed before it was committed (${safeErrorCode(e)}).`, 500)
    throw failedAfterCommit(e, `update of ${pluginId} to ${release.version}`)
  }
}

export type RollbackCheck =
  | { possible: true; migrates: boolean }
  | {
      possible: false
      reason: 'not_installed' | 'no_previous_version' | 'no_down_migration' | 'platform_incompatible'
      missing?: string[]
      /** For platform_incompatible: the range the previous version needs. */
      platform?: string
    }

/** Whether a rollback is possible now, and why not: the Plugins page shows it before an update. */
export async function rollbackCheck(pluginId: string, platformVersion = PLUGIN_PLATFORM_VERSION): Promise<RollbackCheck> {
  const row = await findInstall(pluginId)
  if (!row || !isInstalled(row.status) || !row.activeVersion) return { possible: false, reason: 'not_installed' }
  const prev = row.previousVersion
  const prevManifest = prev && (await versionExists(pluginId, prev)) ? await manifestOnDisk(pluginId, prev) : null
  if (!prev || !prevManifest) return { possible: false, reason: 'no_previous_version' }
  if (!satisfies(platformVersion, prevManifest.platform)) {
    return { possible: false, reason: 'platform_incompatible', platform: prevManifest.platform }
  }
  if (prevManifest.dataVersion === row.dataVersion || !(await hasKeptData(pluginId))) return { possible: true, migrates: false }
  if (prevManifest.dataVersion > row.dataVersion) return { possible: false, reason: 'no_down_migration', missing: [] }
  const missing: string[] = []
  for (const { step } of migrationSteps(row.dataVersion, prevManifest.dataVersion)) {
    const name = `migrations/${String(step).padStart(4, '0')}_down.py`
    const ok = await fs.stat(path.join(versionPath(pluginId, row.activeVersion), name)).then((st) => st.isFile(), () => false)
    if (!ok) missing.push(name)
  }
  return missing.length ? { possible: false, reason: 'no_down_migration', missing } : { possible: true, migrates: true }
}

/**
 * The previous version active again (§9.5). Data migrated forward is first taken back by
 * the newer version's down migrations (copy and swap); without them the rollback is
 * refused, because old code never runs on newer data.
 */
/** `toVersion`: the version the admin confirmed; refused if the previous version changed since. */
export async function rollback(
  pluginId: string,
  actorId: string,
  deps?: LifecycleDeps,
  toVersion?: unknown,
): Promise<{ plugin: InstallView }> {
  const d = withDefaults(deps)
  checkPluginId(pluginId)
  if (toVersion !== undefined && typeof toVersion !== 'string') {
    throw new LifecycleError(400, 'invalid_request', 'toVersion must be the version to roll back to.')
  }
  const before = await findInstall(pluginId)
  if (!before || !isInstalled(before.status) || liveLease(before) || !before.activeVersion) {
    throw busyOrNotInstalled(before, pluginId)
  }
  if (toVersion !== undefined && toVersion !== before.previousVersion) throw changed(pluginId, before)
  const check = await rollbackCheck(pluginId, d.platformVersion)
  if (!check.possible) {
    if (check.reason === 'platform_incompatible') {
      throw new LifecycleError(409, 'platform_incompatible', `Version ${before.previousVersion} needs platform ${check.platform}; this RedAmon runs ${d.platformVersion}.`)
    }
    if (check.reason === 'no_down_migration') {
      throw new LifecycleError(
        409,
        'no_down_migration',
        `Version ${before.activeVersion} moved the data and ships no way back${check.missing?.length ? ` (${check.missing.join(', ')})` : ''}; ` +
          'old code never runs on newer data.',
      )
    }
    throw new LifecycleError(409, check.reason, `Plugin ${pluginId} has no previous version on disk to roll back to.`)
  }
  const prev = before.previousVersion as string
  const prevManifest = (await manifestOnDisk(pluginId, prev))!
  try {
    const loaded = await d.loadCatalog()
    const revoked = isRevoked(loaded.catalog, pluginId, prev)
    if (revoked !== null) throw new LifecycleError(409, 'release_revoked', `Version ${prev} was revoked: ${revoked}`)
  } catch (e) {
    if (e instanceof LifecycleError) throw e
    // Offline: the rollback goes ahead; reconciliation applies a revocation once the catalog is back.
    console.warn(`[plugins] rollback ${pluginId}: the catalog could not be checked for a revocation of ${prev}`)
  }

  let op: Operation
  try {
    op = await beginOperation(
      pluginId,
      [...INSTALLED_STATUSES],
      'updating',
      'rollback',
      { to: prev, from: before.activeVersion, by: actorId },
      prisma,
      plannedWith(before),
    )
    await prisma.pluginInstall.updateMany({ where: { pluginId, operationId: op.operationId }, data: { pendingVersion: prev } })
  } catch (e) {
    if (e instanceof PluginConflictError) throw await lostStart(pluginId, before)
    throw e
  }
  const previousEntry = (withoutPrevious(before.catalogEntry)?.version === before.activeVersion
    ? (before.catalogEntry as Record<string, unknown>)?.previous
    : null) as Record<string, unknown> | null
  const commit = commitIn(op, 'updating', {
    activeVersion: prev,
    previousVersion: before.activeVersion,
    pendingVersion: null,
    dataVersion: prevManifest.dataVersion,
    previousDataVersion: before.dataVersion,
    grantedPermissions: prevManifest.permissions,
    manifest: prevManifest as unknown as Prisma.InputJsonValue,
    catalogEntry: (previousEntry
      ? { ...previousEntry, previous: withoutPrevious(before.catalogEntry) }
      : before.catalogEntry ?? Prisma.DbNull) as Prisma.InputJsonValue,
    lastError: null,
    // The revocation was of the version left; one of this version comes back at the next tick.
    revokedReason: null,
  })
  let migration: MigrationStats | null = null
  try {
    if (check.migrates) {
      try {
        migration = await runMigrations(
          { operation: op, version: before.activeVersion, from: before.dataVersion, to: prevManifest.dataVersion },
          commit,
        )
      } catch (e) {
        const f = e as MigrationFailure
        if (f.code === 'plugin_busy') throw new PluginConflictError(pluginId, f.message)
        await restoreStatus(op, before.status, `${f.code}: ${f.message}`)
        await auditPlugin('plugin.rollback', {
          actorId,
          pluginId,
          before: snapshot(before),
          after: { outcome: 'failed', to: prev, code: f.code, message: f.message },
          source: 'admin',
        })
        throw new LifecycleError(f.status, f.code, f.message)
      }
    } else {
      await prisma.$transaction(commit)
    }
  } catch (e) {
    if (e instanceof LifecycleError) throw e
    if (e instanceof PluginConflictError) {
      throw new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: the rollback lost its lease to another operation.`)
    }
    // Nothing was committed: back now, not when reconciliation finds the lease.
    const message = `The rollback failed before it was committed (${safeErrorCode(e)}).`
    await restoreStatus(op, before.status, `rollback_failed: ${message}`)
    await auditPlugin('plugin.rollback', {
      actorId,
      pluginId,
      before: snapshot(before),
      after: { outcome: 'failed', to: prev, code: 'rollback_failed', message },
      source: 'admin',
    })
    throw new LifecycleError(500, 'rollback_failed', message)
  }
  let row: PluginInstall
  try {
    if (before.enabled) row = await settleWorker(pluginId, prev)
    else {
      await tellRunner(pluginId, 'rollback')
      row = (await findInstall(pluginId))!
    }
  } catch (e) {
    throw failedAfterCommit(e, `rollback of ${pluginId} to ${prev}`)
  }
  await auditPlugin('plugin.rollback', {
    actorId,
    pluginId,
    before: snapshot(before),
    after: { ...snapshot(row), previousVersion: row.previousVersion, ...(migration ? { migration } : {}) },
    source: 'admin',
  })
  return { plugin: installView(row) }
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

export interface UninstallInput {
  mode: 'keep' | 'purge'
  confirm: string
}

/**
 * Removes `plugin:<id>` from every user's Models by feature (TD-10): one statement, not the
 * PUT route, which refuses internal callers. Returns the number of users changed.
 */
export async function stripFeatureModelKey(db: Pick<Prisma.TransactionClient, '$executeRaw'>, pluginId: string): Promise<number> {
  if (!isValidPluginId(pluginId)) throw new Error(`Invalid plugin id ${JSON.stringify(pluginId)}`)
  const key = `plugin:${pluginId}`
  return db.$executeRaw`UPDATE "user_settings" SET "feature_models" = "feature_models" - ${key} WHERE jsonb_exists("feature_models", ${key})`
}

async function deleteRows(tx: Prisma.TransactionClient, pluginId: string) {
  const data = await tx.pluginData.deleteMany({ where: { pluginId } })
  const overrides = await tx.pluginOverride.deleteMany({ where: { pluginId } })
  await stripFeatureModelKey(tx, pluginId)
  await tx.pluginPlatformState.deleteMany({ where: { key: exportMarkerKey(pluginId) } })
  return { dataRows: data.count, overrideRows: overrides.count }
}

export async function purgeRows(tx: Prisma.TransactionClient, op: Operation) {
  const counts = await deleteRows(tx, op.pluginId)
  const { count } = await tx.pluginInstall.deleteMany({
    where: { pluginId: op.pluginId, status: 'uninstalling', operationId: op.operationId },
  })
  if (count !== 1) throw new PluginConflictError(op.pluginId, 'the uninstall lost its lease')
  return counts
}

async function requireFreshExport(pluginId: string) {
  const at = await lastExportAt(pluginId)
  if (!at || now().getTime() - at.getTime() > EXPORT_FRESH_MS) {
    throw new LifecycleError(409, 'export_required', 'Download the export of this plugin\'s data first (within the last hour).')
  }
}

/**
 * "Delete kept data" of a plugin uninstalled with "keep data": no code and no worker are
 * left, so one transaction does it, gated on the row still being available with no live
 * lease (an install that starts meanwhile makes it roll back with nothing deleted).
 */
async function purgeKept(pluginId: string, before: PluginInstall, actorId: string): Promise<{ plugin: null }> {
  let counts: { dataRows: number; overrideRows: number }
  try {
    counts = await prisma.$transaction(
      async (tx) => {
        const c = await deleteRows(tx, pluginId)
        const { count } = await tx.pluginInstall.deleteMany({
          where: { pluginId, status: 'available', OR: [{ operationId: null }, { leaseExpiresAt: { lt: now() } }] },
        })
        if (count !== 1) throw new PluginConflictError(pluginId, 'it changed while its kept data was being deleted')
        return c
      },
      { maxWait: 10_000, timeout: 120_000 },
    )
  } catch (e) {
    if (e instanceof PluginConflictError) throw busyOrNotInstalled(await findInstall(pluginId), pluginId)
    throw e
  }
  await auditPlugin('plugin.purge', {
    actorId,
    pluginId,
    before: snapshot(before),
    after: { mode: 'purge', kept: true, ...counts },
    source: 'admin',
  })
  return { plugin: null }
}

export async function uninstall(
  pluginId: string,
  input: UninstallInput,
  actorId: string,
): Promise<{ plugin: InstallView | null }> {
  checkPluginId(pluginId)
  if (!input || (input.mode !== 'keep' && input.mode !== 'purge')) {
    throw new LifecycleError(400, 'invalid_request', 'mode must be "keep" or "purge".')
  }
  if (input.confirm !== pluginId) {
    throw new LifecycleError(400, 'confirm_mismatch', `Type the plugin id (${pluginId}) to confirm.`)
  }
  const before = await findInstall(pluginId)
  if (input.mode === 'purge' && before?.status === 'available' && !liveLease(before)) {
    await requireFreshExport(pluginId)
    return purgeKept(pluginId, before, actorId)
  }
  if (!before || !isInstalled(before.status) || liveLease(before)) throw busyOrNotInstalled(before, pluginId)
  if (input.mode === 'purge') await requireFreshExport(pluginId)

  let op: Operation
  try {
    op = await beginOperation(pluginId, [...INSTALLED_STATUSES], 'uninstalling', 'uninstall', { mode: input.mode, by: actorId })
  } catch (e) {
    if (e instanceof PluginConflictError) throw busyOrNotInstalled(await findInstall(pluginId), pluginId)
    throw e
  }
  try {
    // The run list no longer lists an uninstalling plugin: its worker stops before its code goes.
    await tellRunner(pluginId, 'uninstall')
    await removePluginFolder(pluginId)
    if (input.mode === 'keep') {
      await endOperation(op, 'available', {
        enabled: false,
        activeVersion: null,
        previousVersion: null,
        pendingVersion: null,
        previousDataVersion: null,
        lastError: null,
      })
      const row = (await findInstall(pluginId))!
      await auditPlugin('plugin.uninstall', {
        actorId,
        pluginId,
        before: snapshot(before),
        after: { ...snapshot(row), mode: 'keep' },
        source: 'admin',
      })
      return { plugin: installView(row) }
    }
    const counts = await prisma.$transaction((tx) => purgeRows(tx, op), { maxWait: 10_000, timeout: 120_000 })
    await auditPlugin('plugin.purge', {
      actorId,
      pluginId,
      before: snapshot(before),
      after: { mode: 'purge', ...counts },
      source: 'admin',
    })
    return { plugin: null }
  } catch (e) {
    if (e instanceof PluginConflictError) {
      throw new LifecycleError(409, 'plugin_busy', `Plugin ${pluginId}: the uninstall lost its lease to another operation.`)
    }
    throw e
  }
}

// ---------------------------------------------------------------------------
// Offline install
// ---------------------------------------------------------------------------

export interface OfflineInput {
  archive: Buffer
  catalog: Buffer
  signature: Buffer
  acceptedPermissions: string[]
  restoreOverrides?: boolean
}

/**
 * An archive uploaded with a catalog and signature that cover it (§9.7), through exactly
 * the checks of a download: the uploaded catalog is verified (keyring, signature, serial) and
 * must pin this archive's sha256; then the normal install, or the update of an installed
 * plugin, runs with that catalog and these bytes.
 */
export async function offlineInstall(input: OfflineInput, actorId: string, deps?: LifecycleDeps): Promise<{ plugin: InstallView }> {
  let loaded: LoadedCatalog
  try {
    loaded = await loadCatalog({ source: 'upload', bytes: input.catalog, sigBytes: input.signature })
  } catch (e) {
    if (e instanceof CatalogError) {
      throw new LifecycleError(422, 'catalog_invalid', `The uploaded catalog cannot be used: ${e.message}`, [e.code])
    }
    throw e
  }
  const sha = createHash('sha256').update(input.archive).digest('hex')
  const hit = loaded.catalog.plugins
    .flatMap((p) => p.releases.map((r) => ({ pluginId: p.id, release: r })))
    .find((x) => x.release.sha256 === sha)
  if (!hit) {
    throw new LifecycleError(422, 'sha256_mismatch', `The catalog in use pins no release with this archive's SHA-256 (${sha}).`)
  }
  const d: LifecycleDeps = { ...deps, loadCatalog: async () => loaded, fetchArchive: async () => input.archive }
  const row = await findInstall(hit.pluginId)
  if (row && isInstalled(row.status)) {
    return update(hit.pluginId, { version: hit.release.version, acceptedPermissions: input.acceptedPermissions }, actorId, d)
  }
  return install(
    hit.pluginId,
    { version: hit.release.version, acceptedPermissions: input.acceptedPermissions, restoreOverrides: input.restoreOverrides },
    actorId,
    d,
  )
}
